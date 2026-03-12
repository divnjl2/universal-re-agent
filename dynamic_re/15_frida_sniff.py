"""
Frida-based HTTP sniffer for Nuitka-compiled Python bots.

Attaches to bot processes and hooks:
- Winsock (connect/send/recv/WSASend/WSARecv) — low-level
- SSL (EncryptMessage/DecryptMessage) — pre-encryption plaintext
- OpenSSL (SSL_write/SSL_read) — for libssl-based TLS (httpx uses this)

Logs all HTTP request/response data to JSONL.
PASSIVE: does not modify any data, only observes.
"""
import frida
import json
import os
import sys
import time
import subprocess
from datetime import datetime

OUTPUT_DIR = r"C:\dynamic_re\traffic"
os.makedirs(OUTPUT_DIR, exist_ok=True)

BOT_NAMES = {"KYC bot v1.exe", "Bybit Manager v3.exe"}

# Frida JS instrumentation script
# NOTE: Frida 17.x API — use Process.findModuleByName().findExportByName()
#       instead of Module.findExportByName() which no longer exists
FRIDA_SCRIPT = r"""
'use strict';

var hooks = [];

// Helper: resolve export from DLL (Frida 17.x compatible)
function findExport(dll, fn) {
    try {
        var mod = Process.findModuleByName(dll);
        if (mod) return mod.findExportByName(fn);
    } catch(e) {}
    return null;
}

// ============ Winsock2 hooks ============

// connect() — see where we're connecting
var pConnect = findExport('ws2_32.dll', 'connect');
if (pConnect) {
    Interceptor.attach(pConnect, {
        onEnter: function(args) {
            try {
                var sa = args[1];
                var family = sa.readU16();
                if (family === 2) {
                    var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                    var ip = sa.add(4).readU8() + '.' + sa.add(5).readU8() + '.' +
                             sa.add(6).readU8() + '.' + sa.add(7).readU8();
                    send({type: 'connect', ip: ip, port: port});
                }
            } catch(e) {}
        }
    });
    hooks.push('connect');
}

// send() — outgoing data
var pSend = findExport('ws2_32.dll', 'send');
if (pSend) {
    Interceptor.attach(pSend, {
        onEnter: function(args) {
            try {
                var len = args[2].toInt32();
                if (len > 0 && len < 65536) {
                    var buf = args[1];
                    var preview = '';
                    try { preview = buf.readUtf8String(Math.min(len, 2048)); } catch(e) {
                        preview = '<bin ' + len + 'B>';
                    }
                    if (preview.indexOf('HTTP') !== -1 || preview.indexOf('CONNECT') !== -1 ||
                        preview.indexOf('{') !== -1 || preview.indexOf('GET ') === 0 ||
                        preview.indexOf('POST ') === 0 || preview.indexOf('PUT ') === 0 ||
                        preview.indexOf('DELETE ') === 0 || preview.indexOf('Host:') !== -1) {
                        send({type: 'send', data: preview.substring(0, 4096), len: len});
                    }
                }
            } catch(e) {}
        }
    });
    hooks.push('send');
}

// recv() — incoming data
var pRecv = findExport('ws2_32.dll', 'recv');
if (pRecv) {
    Interceptor.attach(pRecv, {
        onEnter: function(args) {
            this.buf = args[1];
            this.maxLen = args[2].toInt32();
        },
        onLeave: function(retval) {
            try {
                var nRead = retval.toInt32();
                if (nRead > 0 && nRead < 65536) {
                    var preview = '';
                    try { preview = this.buf.readUtf8String(Math.min(nRead, 2048)); } catch(e) {
                        preview = '<bin ' + nRead + 'B>';
                    }
                    if (preview.indexOf('HTTP') !== -1 || preview.indexOf('{') !== -1 ||
                        preview.indexOf('<') !== -1) {
                        send({type: 'recv', data: preview.substring(0, 4096), len: nRead});
                    }
                }
            } catch(e) {}
        }
    });
    hooks.push('recv');
}

// WSASend — async send (common in Python asyncio)
var pWSASend = findExport('ws2_32.dll', 'WSASend');
if (pWSASend) {
    Interceptor.attach(pWSASend, {
        onEnter: function(args) {
            try {
                var lpBuffers = args[1];
                var nBuffers = args[2].toInt32();
                for (var i = 0; i < nBuffers && i < 4; i++) {
                    var len = lpBuffers.add(i * Process.pointerSize * 2).readU32();
                    var buf = lpBuffers.add(i * Process.pointerSize * 2 + Process.pointerSize).readPointer();
                    if (len > 0 && len < 65536 && !buf.isNull()) {
                        var preview = '';
                        try { preview = buf.readUtf8String(Math.min(len, 2048)); } catch(e) {
                            preview = '<bin ' + len + 'B>';
                        }
                        if (preview.indexOf('HTTP') !== -1 || preview.indexOf('CONNECT') !== -1 ||
                            preview.indexOf('{') !== -1 || preview.indexOf('GET ') === 0 ||
                            preview.indexOf('POST ') === 0) {
                            send({type: 'wsasend', data: preview.substring(0, 4096), len: len});
                        }
                    }
                }
            } catch(e) {}
        }
    });
    hooks.push('WSASend');
}

// WSARecv — async recv
var pWSARecv = findExport('ws2_32.dll', 'WSARecv');
if (pWSARecv) {
    Interceptor.attach(pWSARecv, {
        onEnter: function(args) {
            this.lpBuffers = args[1];
            this.nBuffers = args[2].toInt32();
            this.lpBytesRecvd = args[3];
        },
        onLeave: function(retval) {
            try {
                if (retval.toInt32() === 0 && !this.lpBytesRecvd.isNull()) {
                    var totalRead = this.lpBytesRecvd.readU32();
                    if (totalRead > 0 && totalRead < 65536) {
                        var buf = this.lpBuffers.add(Process.pointerSize).readPointer();
                        var preview = '';
                        try { preview = buf.readUtf8String(Math.min(totalRead, 2048)); } catch(e) {
                            preview = '<bin ' + totalRead + 'B>';
                        }
                        if (preview.indexOf('HTTP') !== -1 || preview.indexOf('{') !== -1) {
                            send({type: 'wsarecv', data: preview.substring(0, 4096), len: totalRead});
                        }
                    }
                }
            } catch(e) {}
        }
    });
    hooks.push('WSARecv');
}

// ============ SSL pre-encryption (secur32/schannel) ============

var pEncrypt = findExport('SSPICLI.DLL', 'EncryptMessage');
if (!pEncrypt) pEncrypt = findExport('Secur32.dll', 'EncryptMessage');
if (pEncrypt) {
    Interceptor.attach(pEncrypt, {
        onEnter: function(args) {
            try {
                var pBufDesc = args[1];
                var cBuffers = pBufDesc.add(4).readU32();
                var pBuffers = pBufDesc.add(8).readPointer();
                var stride = 4 + 4 + Process.pointerSize;
                for (var i = 0; i < Math.min(cBuffers, 8); i++) {
                    var cbBuffer = pBuffers.add(i * stride).readU32();
                    var bufType = pBuffers.add(i * stride + 4).readU32();
                    var pvBuffer = pBuffers.add(i * stride + 8).readPointer();
                    if (bufType === 1 && cbBuffer > 0 && cbBuffer < 65536 && !pvBuffer.isNull()) {
                        var data = '';
                        try { data = pvBuffer.readUtf8String(Math.min(cbBuffer, 4096)); } catch(e) {}
                        if (data.length > 5) {
                            send({type: 'ssl_out', data: data.substring(0, 4096), len: cbBuffer});
                        }
                    }
                }
            } catch(e) {}
        }
    });
    hooks.push('EncryptMessage');
}

var pDecrypt = findExport('SSPICLI.DLL', 'DecryptMessage');
if (!pDecrypt) pDecrypt = findExport('Secur32.dll', 'DecryptMessage');
if (pDecrypt) {
    Interceptor.attach(pDecrypt, {
        onEnter: function(args) {
            this.pBufDesc = args[1];
        },
        onLeave: function(retval) {
            try {
                if (retval.toInt32() === 0) {
                    var pBufDesc = this.pBufDesc;
                    var cBuffers = pBufDesc.add(4).readU32();
                    var pBuffers = pBufDesc.add(8).readPointer();
                    var stride = 4 + 4 + Process.pointerSize;
                    for (var i = 0; i < Math.min(cBuffers, 8); i++) {
                        var cbBuffer = pBuffers.add(i * stride).readU32();
                        var bufType = pBuffers.add(i * stride + 4).readU32();
                        var pvBuffer = pBuffers.add(i * stride + 8).readPointer();
                        if (bufType === 1 && cbBuffer > 0 && cbBuffer < 65536 && !pvBuffer.isNull()) {
                            var data = '';
                            try { data = pvBuffer.readUtf8String(Math.min(cbBuffer, 4096)); } catch(e) {}
                            if (data.length > 5) {
                                send({type: 'ssl_in', data: data.substring(0, 4096), len: cbBuffer});
                            }
                        }
                    }
                }
            } catch(e) {}
        }
    });
    hooks.push('DecryptMessage');
}

// ============ OpenSSL hooks (libssl-3-x64.dll) — httpx uses this ============
// The bots use Nuitka-compiled Python with bundled OpenSSL via _ssl.pyd -> libssl-3-x64.dll
// This is the MAIN path for HTTPS traffic (not Schannel)

// Find the right libssl — there may be multiple copies
var sslDlls = ['libssl-3-x64.dll'];
var mods = Process.enumerateModules();
for (var mi = 0; mi < mods.length; mi++) {
    if (mods[mi].name.indexOf('libssl-3-x64') !== -1 && sslDlls.indexOf(mods[mi].name) === -1) {
        sslDlls.push(mods[mi].name);
    }
}

for (var di = 0; di < sslDlls.length; di++) {
    var sslDll = sslDlls[di];

    // SSL_write — outgoing plaintext before encryption
    var pSSLWrite = findExport(sslDll, 'SSL_write');
    if (pSSLWrite) {
        Interceptor.attach(pSSLWrite, {
            onEnter: function(args) {
                try {
                    var len = args[2].toInt32();
                    if (len > 0 && len < 65536) {
                        var preview = '';
                        try { preview = args[1].readUtf8String(Math.min(len, 4096)); } catch(e) {
                            preview = '<bin ' + len + 'B>';
                        }
                        send({type: 'ssl_write', data: preview.substring(0, 4096), len: len});
                    }
                } catch(e) {}
            }
        });
        hooks.push('SSL_write@' + sslDll);
    }

    // SSL_read — incoming plaintext after decryption
    var pSSLRead = findExport(sslDll, 'SSL_read');
    if (pSSLRead) {
        Interceptor.attach(pSSLRead, {
            onEnter: function(args) {
                this.ssl = args[0];
                this.buf = args[1];
                this.maxLen = args[2].toInt32();
            },
            onLeave: function(retval) {
                try {
                    var nRead = retval.toInt32();
                    if (nRead > 0 && nRead < 65536) {
                        var preview = '';
                        try { preview = this.buf.readUtf8String(Math.min(nRead, 4096)); } catch(e) {
                            preview = '<bin ' + nRead + 'B>';
                        }
                        send({type: 'ssl_read', data: preview.substring(0, 4096), len: nRead});
                    }
                } catch(e) {}
            }
        });
        hooks.push('SSL_read@' + sslDll);
    }

    // SSL_write_ex / SSL_read_ex — OpenSSL 3.x extended API (may be used instead of legacy)
    var pSSLWriteEx = findExport(sslDll, 'SSL_write_ex');
    if (pSSLWriteEx) {
        Interceptor.attach(pSSLWriteEx, {
            onEnter: function(args) {
                try {
                    var len = args[2].toUInt32 ? args[2].toUInt32() : args[2].toInt32();
                    if (len > 0 && len < 65536) {
                        var preview = '';
                        try { preview = args[1].readUtf8String(Math.min(len, 4096)); } catch(e) {
                            preview = '<bin ' + len + 'B>';
                        }
                        send({type: 'ssl_write_ex', data: preview.substring(0, 4096), len: len});
                    }
                } catch(e) {}
            }
        });
        hooks.push('SSL_write_ex@' + sslDll);
    }

    var pSSLReadEx = findExport(sslDll, 'SSL_read_ex');
    if (pSSLReadEx) {
        Interceptor.attach(pSSLReadEx, {
            onEnter: function(args) {
                this.buf = args[1];
                this.written = args[3]; // size_t *readbytes
            },
            onLeave: function(retval) {
                try {
                    if (retval.toInt32() === 1 && this.written && !this.written.isNull()) {
                        var nRead = this.written.readUInt ? this.written.readUInt() : this.written.readU32();
                        if (nRead > 0 && nRead < 65536) {
                            var preview = '';
                            try { preview = this.buf.readUtf8String(Math.min(nRead, 4096)); } catch(e) {
                                preview = '<bin ' + nRead + 'B>';
                            }
                            send({type: 'ssl_read_ex', data: preview.substring(0, 4096), len: nRead});
                        }
                    }
                } catch(e) {}
            }
        });
        hooks.push('SSL_read_ex@' + sslDll);
    }
}

send({type: 'ready', hooks: hooks.join(',')});
"""


def get_bot_pids():
    result = subprocess.run(['tasklist', '/FO', 'CSV', '/NH'],
                          capture_output=True, text=True)
    pids = {}
    for line in result.stdout.strip().split('\n'):
        for name in BOT_NAMES:
            if name.lower() in line.lower():
                parts = line.strip('"').split('","')
                if len(parts) >= 2:
                    try:
                        pid = int(parts[1])
                        pids[pid] = name
                    except ValueError:
                        pass
    return pids


def main():
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = os.path.join(OUTPUT_DIR, f"frida_capture_{ts}.jsonl")

    print(f"{'='*60}")
    print(f"  FRIDA HTTP SNIFFER")
    print(f"  {datetime.now().isoformat()}")
    print(f"  Output: {output_file}")
    print(f"{'='*60}\n")

    # Wait for bots to appear (poll every 10s for up to 1h)
    bot_pids = get_bot_pids()
    if not bot_pids:
        print("  No bot processes found. Waiting...")
        for _ in range(360):  # up to 1 hour
            time.sleep(10)
            bot_pids = get_bot_pids()
            if bot_pids:
                break
        if not bot_pids:
            print("  Timed out waiting for bots.")
            return
        print(f"  Bots appeared!")

    print(f"  Target processes:")
    for pid, name in bot_pids.items():
        print(f"    PID {pid}: {name}")

    # Pick ALL PIDs — both launcher and worker need hooks
    targets = {}
    for pid, name in bot_pids.items():
        targets[f"{name}_{pid}"] = pid

    sessions = []
    count = [0]

    def on_message(message, data, proc_name=""):
        if message['type'] == 'send':
            payload = message['payload']
            payload['process'] = proc_name
            payload['ts'] = datetime.now().isoformat()
            count[0] += 1

            # Write to file
            with open(output_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(payload, ensure_ascii=False, default=str) + '\n')

            # Print summary
            t = payload.get('type', '')
            if t == 'ready':
                print(f"  [{proc_name}] Hooks: {payload.get('hooks', '?')}")
            elif t == 'connect':
                print(f"  [{count[0]}] CONNECT {payload['ip']}:{payload['port']} [{proc_name}]")
            elif t in ('send', 'wsasend'):
                d = payload.get('data', '')[:150]
                print(f"  [{count[0]}] {t.upper()} ({payload.get('len',0)}B): {d} [{proc_name}]")
            elif t in ('recv', 'wsarecv'):
                d = payload.get('data', '')[:150]
                print(f"  [{count[0]}] {t.upper()} ({payload.get('len',0)}B): {d} [{proc_name}]")
            elif t == 'ssl_write':
                d = payload.get('data', '')[:200]
                print(f"  [{count[0]}] SSL_WRITE ({payload.get('len',0)}B): {d} [{proc_name}]")
            elif t == 'ssl_read':
                d = payload.get('data', '')[:200]
                print(f"  [{count[0]}] SSL_READ ({payload.get('len',0)}B): {d} [{proc_name}]")
            elif t in ('ssl_out', 'ssl_in'):
                d = payload.get('data', '')[:200]
                print(f"  [{count[0]}] {t.upper()} ({payload.get('len',0)}B): {d} [{proc_name}]")
            elif t in ('ssl_write_ex', 'ssl_read_ex'):
                d = payload.get('data', '')[:200]
                print(f"  [{count[0]}] {t.upper()} ({payload.get('len',0)}B): {d} [{proc_name}]")

        elif message['type'] == 'error':
            print(f"  ERROR [{proc_name}]: {message.get('description', message)}")

    print(f"\n  Attaching Frida...")

    for name, pid in targets.items():
        try:
            session = frida.attach(pid)
            script = session.create_script(FRIDA_SCRIPT)
            script.on('message', lambda msg, data, pn=name: on_message(msg, data, pn))
            script.load()
            sessions.append((session, script, name))
            print(f"  Attached to {name} (PID {pid})")
        except Exception as e:
            print(f"  FAILED to attach to {name} (PID {pid}): {e}")

    if not sessions:
        print("  No processes attached! Exiting.")
        return

    print(f"\n  Listening... Press Ctrl+C to stop.\n")
    print(f"  {'─'*50}")

    attached_pids = {pid for _, _, name in sessions for nm, pid in targets.items() if nm == name}
    duration = int(os.environ.get("CAPTURE_SECONDS", "120"))
    print(f"  Auto-stop after {duration}s\n")
    start = time.time()
    try:
        while time.time() - start < duration:
            time.sleep(5)
            # Check for new bot processes and attach
            try:
                new_pids = get_bot_pids()
                for pid, name in new_pids.items():
                    if pid not in attached_pids:
                        try:
                            label = f"{name}_{pid}"
                            session = frida.attach(pid)
                            script = session.create_script(FRIDA_SCRIPT)
                            script.on('message', lambda msg, data, pn=label: on_message(msg, data, pn))
                            script.load()
                            sessions.append((session, script, label))
                            attached_pids.add(pid)
                            targets[label] = pid
                            print(f"  [+] Attached to NEW {label}")
                        except Exception as e:
                            pass  # might be transient
            except:
                pass
    except KeyboardInterrupt:
        pass
    finally:
        print(f"\n  {'─'*50}")
        print(f"\n  Captured {count[0]} events")
        print(f"  Output: {output_file}")

        for session, script, name in sessions:
            try:
                script.unload()
                session.detach()
            except:
                pass


if __name__ == '__main__':
    main()
