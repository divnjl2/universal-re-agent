"""Minimal Frida test — hooks connect/send/EncryptMessage on a single PID."""
import frida
import json
import sys
import time
import os

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

PID = int(sys.argv[1]) if len(sys.argv) > 1 else 2796

SCRIPT = r"""
'use strict';

var result = {modules: [], hooks: []};

var mods = Process.enumerateModules();
for (var i = 0; i < mods.length; i++) {
    var n = mods[i].name.toLowerCase();
    if (n.indexOf('ws2') !== -1 || n.indexOf('winhttp') !== -1 ||
        n.indexOf('wininet') !== -1 || n.indexOf('secur') !== -1 ||
        n.indexOf('sspicli') !== -1 || n.indexOf('schannel') !== -1 ||
        n.indexOf('crypt') !== -1 || n.indexOf('ssl') !== -1) {
        result.modules.push(mods[i].name + ' @ ' + mods[i].base);
    }
}

// Hook connect
try {
    var pConnect = Module.findExportByName('ws2_32.dll', 'connect');
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
                } catch(e) { send({type: 'hook_err', fn: 'connect', err: e.message}); }
            }
        });
        result.hooks.push('connect');
    }
} catch(e) { result.hooks.push('connect_FAIL:' + e.message); }

// Hook send
try {
    var pSend = Module.findExportByName('ws2_32.dll', 'send');
    if (pSend) {
        Interceptor.attach(pSend, {
            onEnter: function(args) {
                try {
                    var len = args[2].toInt32();
                    if (len > 0 && len < 65536) {
                        var preview = '';
                        try { preview = args[1].readUtf8String(Math.min(len, 512)); } catch(e2) {
                            preview = '<bin ' + len + 'B>';
                        }
                        send({type: 'send', len: len, data: preview.substring(0, 512)});
                    }
                } catch(e) { send({type: 'hook_err', fn: 'send', err: e.message}); }
            }
        });
        result.hooks.push('send');
    }
} catch(e) { result.hooks.push('send_FAIL:' + e.message); }

// Hook recv
try {
    var pRecv = Module.findExportByName('ws2_32.dll', 'recv');
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
                        try { preview = this.buf.readUtf8String(Math.min(nRead, 512)); } catch(e2) {
                            preview = '<bin ' + nRead + 'B>';
                        }
                        send({type: 'recv', len: nRead, data: preview.substring(0, 512)});
                    }
                } catch(e) {}
            }
        });
        result.hooks.push('recv');
    }
} catch(e) { result.hooks.push('recv_FAIL:' + e.message); }

// Hook EncryptMessage (pre-TLS plaintext)
try {
    var pEnc = Module.findExportByName('sspicli.dll', 'EncryptMessage');
    if (!pEnc) pEnc = Module.findExportByName('secur32.dll', 'EncryptMessage');
    if (pEnc) {
        Interceptor.attach(pEnc, {
            onEnter: function(args) {
                try {
                    var pBufDesc = args[1];
                    var cBuffers = pBufDesc.add(4).readU32();
                    var pBuffers = pBufDesc.add(8).readPointer();
                    for (var i = 0; i < Math.min(cBuffers, 8); i++) {
                        var stride = 4 + 4 + Process.pointerSize;
                        var cbBuffer = pBuffers.add(i * stride).readU32();
                        var bufType = pBuffers.add(i * stride + 4).readU32();
                        var pvBuffer = pBuffers.add(i * stride + 8).readPointer();
                        if (bufType === 1 && cbBuffer > 0 && cbBuffer < 65536 && !pvBuffer.isNull()) {
                            var data = '';
                            try { data = pvBuffer.readUtf8String(Math.min(cbBuffer, 512)); } catch(e2) {
                                data = '<bin ' + cbBuffer + 'B>';
                            }
                            if (data.length > 5) {
                                send({type: 'ssl_out', len: cbBuffer, data: data.substring(0, 512)});
                            }
                        }
                    }
                } catch(e) { send({type: 'hook_err', fn: 'EncryptMessage', err: e.message}); }
            }
        });
        result.hooks.push('EncryptMessage');
    } else {
        result.hooks.push('EncryptMessage_NOT_FOUND');
    }
} catch(e) { result.hooks.push('EncryptMessage_FAIL:' + e.message); }

// Hook DecryptMessage (post-TLS plaintext)
try {
    var pDec = Module.findExportByName('sspicli.dll', 'DecryptMessage');
    if (!pDec) pDec = Module.findExportByName('secur32.dll', 'DecryptMessage');
    if (pDec) {
        Interceptor.attach(pDec, {
            onEnter: function(args) {
                this.pBufDesc = args[1];
            },
            onLeave: function(retval) {
                try {
                    if (retval.toInt32() === 0) {
                        var pBufDesc = this.pBufDesc;
                        var cBuffers = pBufDesc.add(4).readU32();
                        var pBuffers = pBufDesc.add(8).readPointer();
                        for (var i = 0; i < Math.min(cBuffers, 8); i++) {
                            var stride = 4 + 4 + Process.pointerSize;
                            var cbBuffer = pBuffers.add(i * stride).readU32();
                            var bufType = pBuffers.add(i * stride + 4).readU32();
                            var pvBuffer = pBuffers.add(i * stride + 8).readPointer();
                            if (bufType === 1 && cbBuffer > 0 && cbBuffer < 65536 && !pvBuffer.isNull()) {
                                var data = '';
                                try { data = pvBuffer.readUtf8String(Math.min(cbBuffer, 512)); } catch(e2) {
                                    data = '<bin ' + cbBuffer + 'B>';
                                }
                                if (data.length > 5) {
                                    send({type: 'ssl_in', len: cbBuffer, data: data.substring(0, 512)});
                                }
                            }
                        }
                    }
                } catch(e) {}
            }
        });
        result.hooks.push('DecryptMessage');
    } else {
        result.hooks.push('DecryptMessage_NOT_FOUND');
    }
} catch(e) { result.hooks.push('DecryptMessage_FAIL:' + e.message); }

send({type: 'ready', info: JSON.stringify(result)});
"""


def on_message(msg, data):
    if msg['type'] == 'send':
        p = msg['payload']
        t = p.get('type', '')
        if t == 'ready':
            info = json.loads(p['info'])
            print(f"READY: hooks={info['hooks']}")
            print(f"  modules={info['modules']}")
        elif t == 'connect':
            print(f"CONNECT {p['ip']}:{p['port']}")
        elif t == 'send':
            print(f"SEND ({p['len']}B): {p['data'][:200]}")
        elif t == 'recv':
            print(f"RECV ({p['len']}B): {p['data'][:200]}")
        elif t == 'ssl_out':
            print(f"SSL_OUT ({p['len']}B): {p['data'][:200]}")
        elif t == 'ssl_in':
            print(f"SSL_IN ({p['len']}B): {p['data'][:200]}")
        elif t == 'hook_err':
            print(f"HOOK_ERR [{p['fn']}]: {p['err']}")
        else:
            print(f"MSG: {json.dumps(p)[:300]}")
    elif msg['type'] == 'error':
        print(f"FRIDA_ERROR: {msg.get('description', msg)}")


try:
    print(f"Attaching to PID {PID}...")
    session = frida.attach(PID)
    script = session.create_script(SCRIPT)
    script.on('message', on_message)
    script.load()
    print(f"Listening for 20s...")
    time.sleep(20)
    script.unload()
    session.detach()
    print("Done.")
except Exception as e:
    print(f"FAIL: {e}")
