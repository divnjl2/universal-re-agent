// DumpAnalysis.java v3 — Enhanced Ghidra headless dump
// Outputs rich JSON: functions (user-first), strings+xrefs, imports+categories,
//   .data byte arrays with XOR brute-force, binary meta,
//   RC4 oracle (crypto key candidates), algorithm constant fingerprinting,
//   raw disassembly for dispatch/handler functions.
//
// Usage:
//   analyzeHeadless.bat <proj_dir> <proj_name> -import <binary>
//     -scriptPath <this_dir> -postScript DumpAnalysis.java <output.json>

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

public class DumpAnalysis extends GhidraScript {

    // ── CRT / library name patterns to deprioritize ───────────────────────────
    private static final String[] CRT_PREFIXES = {
        "__scrt_", "__vcrt_", "__acrt_", "__std_", "__security_",
        "_rtc_", "__chk", "__report", "__cxxframehandler", "__framehandler",
        "buildcatchobject", "__except_", "_purecall", "_invalid_parameter",
        "__tmain", "__wmain", "__current_exception", "__processing_throw",
        "__isa_available", "__setusermatherr", "_set_app_type",
        "__vcrt_initialize", "__vcrt_uninitialize", "vcruntime",
        "__stdtype", "__std_terminate", "msvcrt_", "_ceil", "_floor",
        "__scrt_common_main", "__scrt_initialize", "_alloca_probe",
        "seh_filter", "seh_default", "__crt_", "_crt_"
    };

    // ── Import category keywords ───────────────────────────────────────────────
    private static final String[][] IMPORT_CATS = {
        {"network",   "wsastartup","wsacleanup","connect","send","recv","socket",
                      "internet","http","winhttp","wininet","urldownload","url",
                      "getaddrinfo","bind","listen","accept","select","gethostby"},
        {"crypto",    "crypt","bcrypt","ncrypt","hash","sha","md5","aes","rsa",
                      "certopen","certfind","pfximp"},
        {"antidebug", "isdebuggerpresent","checkremotedebugger","ntqueryinformation",
                      "outputdebugstring","debugbreak","ntsetinformationthread",
                      "blockinput","closehandle"},
        {"injection", "virtualallocex","writeprocessmemory","createremotethread",
                      "ntcreatethreadex","queueuserapc","setwindowshook","hookai",
                      "readprocessmemory","openprocess"},
        {"process",   "createprocess","shellexecute","winexec","createthread",
                      "exitprocess","terminateprocess","openprocess","ntcreateuserprocess"},
        {"filesystem","createfile","readfile","writefile","deletefile","findfile",
                      "movefile","copyfile","gettemp","regopenkey","regsetvalue",
                      "regqueryvalue","regcreatekey"},
        {"evasion",   "sleep","settimer","queryperf","gettick","isprocessorcorepark",
                      "ntdelayexecution","setfiletime","changetimezone"},
    };

    // ── V5: Algorithm constant fingerprint map ────────────────────────────────
    private static Map<Long, String> buildAlgoConstants() {
        Map<Long, String> m = new LinkedHashMap<>();
        // FNV-1a
        m.put(0x01000193L,         "FNV1a_prime_32");
        m.put(0x811C9DC5L,         "FNV1a_basis_32");
        m.put(0x00000100000001B3L, "FNV1a_prime_64");
        // CRC32
        m.put(0xEDB88320L,         "CRC32_poly");
        m.put(0x04C11DB7L,         "CRC32_poly_BE");
        // MD5 init
        m.put(0x67452301L,         "MD5_A_init");
        m.put(0xEFCDAB89L,         "MD5_B_init");
        // SHA1 init (0x67452301 same as MD5_A — use SHA1 label if not already mapped)
        m.put(0xC3D2E1F0L,         "SHA1_E_init");
        // AES S-box
        m.put(0x637C777BL,         "AES_Sbox_start");
        // ROR13 shellcode hashes
        m.put(0xD97E8260L,         "ROR13_MessageBoxA");
        m.put(0x0726774CL,         "ROR13_LoadLibraryA");
        m.put(0x7802F749L,         "ROR13_CreateRemoteThread");
        // RC4 hint
        m.put(256L,                "RC4_sbox_size_hint");
        // MurmurHash3
        m.put(0xCC9E2D51L,         "MurmurHash3_c1");
        m.put(0x1B873593L,         "MurmurHash3_c2");
        return m;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private boolean isCrtFunction(String name) {
        String low = name.toLowerCase();
        for (String p : CRT_PREFIXES) {
            if (low.startsWith(p)) return true;
        }
        if (low.startsWith("_") && (low.contains("printf") || low.contains("scanf") ||
            low.contains("malloc") || low.contains("free") || low.contains("memcpy") ||
            low.contains("memmove") || low.contains("memset") || low.contains("strlen") ||
            low.contains("strcmp") || low.contains("strcpy") || low.contains("strcat"))) {
            return true;
        }
        return false;
    }

    private String categorizeImport(String name) {
        String low = name.toLowerCase();
        for (String[] cat : IMPORT_CATS) {
            for (int i = 1; i < cat.length; i++) {
                if (low.contains(cat[i])) return cat[0];
            }
        }
        return "general";
    }

    /** Try all 256 single-byte XOR keys on data[offset..offset+len].
     *  Returns "0xKK:decoded_string" if any key yields all printable ASCII, else null. */
    private String tryXorDecode(byte[] data, int offset, int len) {
        if (len < 6 || len > 512) return null;
        for (int key = 0x01; key <= 0xFF; key++) {
            boolean ok = true;
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < len; i++) {
                int c = (data[offset + i] & 0xFF) ^ key;
                if (c < 0x20 || c > 0x7E) { ok = false; break; }
                sb.append((char) c);
            }
            if (ok) return String.format("0x%02X:%s", key, sb.toString());
        }
        return null;
    }

    /** JSON-escape a string. */
    private String esc(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t")
                .replace("\u0000", "");
    }

    /** Hex-encode a byte array segment. */
    private String hexBytes(byte[] data, int offset, int len) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {
            if (i > 0) sb.append(' ');
            sb.append(String.format("%02x", data[offset + i] & 0xFF));
        }
        return sb.toString();
    }

    // ── V1: RC4 implementation ────────────────────────────────────────────────

    private byte[] rc4(byte[] key, byte[] data) {
        int[] S = new int[256];
        for (int i = 0; i < 256; i++) S[i] = i;
        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + S[i] + (key[i % key.length] & 0xFF)) & 0xFF;
            int t = S[i]; S[i] = S[j]; S[j] = t;
        }
        byte[] out = new byte[data.length];
        int a = 0; j = 0;
        for (int n = 0; n < data.length; n++) {
            a = (a + 1) & 0xFF; j = (j + S[a]) & 0xFF;
            int t = S[a]; S[a] = S[j]; S[j] = t;
            out[n] = (byte)(data[n] ^ S[(S[a] + S[j]) & 0xFF]);
        }
        return out;
    }

    /** Check if a string looks like a crypto key candidate:
     *  length 8-32, mix of upper/lower/digit, not a path/URL/format string. */
    private boolean isCryptoKeyCandidateStr(String s) {
        int len = s.length();
        if (len < 8 || len > 32) return false;
        // Reject paths and URLs
        if (s.contains("/") || s.contains("\\") || s.contains("://") ||
            s.contains("http") || s.contains("www.")) return false;
        // Reject format strings
        if (s.contains("%") || s.contains("{") || s.contains("}")) return false;
        // Reject strings with spaces (usually human-readable messages)
        if (s.contains(" ")) return false;
        // Must have mix of at least two character classes
        boolean hasUpper = false, hasLower = false, hasDigit = false;
        for (char c : s.toCharArray()) {
            if (Character.isUpperCase(c)) hasUpper = true;
            else if (Character.isLowerCase(c)) hasLower = true;
            else if (Character.isDigit(c)) hasDigit = true;
        }
        int classes = (hasUpper ? 1 : 0) + (hasLower ? 1 : 0) + (hasDigit ? 1 : 0);
        return classes >= 2;
    }

    /** Count printable ASCII bytes in array. */
    private int countPrintable(byte[] data) {
        int cnt = 0;
        for (byte b : data) {
            int c = b & 0xFF;
            if (c >= 0x20 && c <= 0x7E) cnt++;
        }
        return cnt;
    }

    /** Find the longest run of consecutive printable ASCII bytes. */
    private int longestPrintableRun(byte[] data) {
        int maxRun = 0, cur = 0;
        for (byte b : data) {
            int c = b & 0xFF;
            if (c >= 0x20 && c <= 0x7E) {
                cur++;
                if (cur > maxRun) maxRun = cur;
            } else {
                cur = 0;
            }
        }
        return maxRun;
    }

    /** Hex-encode full byte array (no spaces). */
    private String hexFull(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) sb.append(String.format("%02x", b & 0xFF));
        return sb.toString();
    }

    /** Extract printable ASCII sequences of length >= 4 from byte array, joined by '|'. */
    private String printableSequences(byte[] data) {
        StringBuilder out = new StringBuilder();
        StringBuilder cur = new StringBuilder();
        for (byte b : data) {
            int c = b & 0xFF;
            if (c >= 0x20 && c <= 0x7E) {
                cur.append((char) c);
            } else {
                if (cur.length() >= 4) {
                    if (out.length() > 0) out.append("|");
                    out.append(cur);
                }
                cur.setLength(0);
            }
        }
        if (cur.length() >= 4) {
            if (out.length() > 0) out.append("|");
            out.append(cur);
        }
        return out.toString();
    }

    // ── V5: scan pseudocode string for hex literals matching algo constants ───

    private static final Pattern HEX_LITERAL_PATTERN =
        Pattern.compile("0x([0-9a-fA-F]{1,16})\\b");

    /** Scan pseudocode for hex literals that match known algo constants.
     *  Returns list of [constantHex, constantName] pairs. */
    private List<String[]> findAlgoConstantsInPseudo(String pseudo, Map<Long, String> algoMap) {
        List<String[]> found = new ArrayList<>();
        Matcher m = HEX_LITERAL_PATTERN.matcher(pseudo);
        Set<Long> seen = new HashSet<>();
        while (m.find()) {
            try {
                long val = Long.parseUnsignedLong(m.group(1), 16);
                if (!seen.contains(val) && algoMap.containsKey(val)) {
                    seen.add(val);
                    found.add(new String[]{
                        "0x" + m.group(1).toUpperCase(),
                        algoMap.get(val)
                    });
                }
            } catch (NumberFormatException ignore) {}
        }
        return found;
    }

    /** Scan raw .data bytes for 4-byte LE sequences matching algo constants. */
    private List<String[]> findAlgoConstantsInBytes(byte[] bytes, int offset, int len,
                                                      Map<Long, String> algoMap,
                                                      Address baseAddr) {
        List<String[]> found = new ArrayList<>();
        Set<Long> seen = new HashSet<>();
        for (int i = offset; i <= offset + len - 4; i++) {
            long le = ((bytes[i] & 0xFFL))
                    | ((bytes[i+1] & 0xFFL) << 8)
                    | ((bytes[i+2] & 0xFFL) << 16)
                    | ((bytes[i+3] & 0xFFL) << 24);
            if (!seen.contains(le) && algoMap.containsKey(le)) {
                seen.add(le);
                long absAddr = baseAddr.getOffset() + i;
                found.add(new String[]{
                    String.format("0x%X", le),
                    algoMap.get(le),
                    String.format("0x%X", absAddr)
                });
            }
        }
        return found;
    }

    // ── V4: dispatch candidate detection ─────────────────────────────────────

    private static final String[] DISPATCH_NAME_HINTS =
        {"step", "exec", "dispatch", "handler", "vm", "eval", "run", "process"};

    private boolean isDispatchCandidate(Function fn, String pseudo, int incomingRefCount) {
        String nameLow = fn.getName().toLowerCase();
        for (String hint : DISPATCH_NAME_HINTS) {
            if (nameLow.contains(hint)) return true;
        }
        if (pseudo.contains("switch")) return true;
        if (incomingRefCount > 5) return true;
        return false;
    }

    /** Gather raw disassembly for a function, up to maxInsns instructions. */
    private List<Map<String, String>> getDisasm(Function fn, int maxInsns) {
        List<Map<String, String>> result = new ArrayList<>();
        int count = 0;
        for (Instruction insn : currentProgram.getListing()
                .getInstructions(fn.getBody(), true)) {
            if (count >= maxInsns) break;
            Map<String, String> row = new LinkedHashMap<>();
            row.put("addr",     insn.getAddress().toString());
            row.put("mnem",     insn.getMnemonicString());

            // Build bytes hex
            StringBuilder bsb = new StringBuilder();
            try {
                byte[] raw = insn.getBytes();
                for (int i = 0; i < raw.length; i++) {
                    if (i > 0) bsb.append(' ');
                    bsb.append(String.format("%02x", raw[i] & 0xFF));
                }
            } catch (Exception _e) { bsb.append("??"); }
            row.put("bytes",    bsb.toString());

            // Build operands string
            StringBuilder osb = new StringBuilder();
            for (int oi = 0; oi < insn.getNumOperands(); oi++) {
                if (oi > 0) osb.append(", ");
                osb.append(insn.getDefaultOperandRepresentation(oi));
            }
            row.put("operands", osb.toString());
            result.add(row);
            count++;
        }
        return result;
    }

    // ── V1: try 4-byte XOR from integer literals in pseudocode ───────────────

    private static final Pattern INT_LITERAL_PATTERN =
        Pattern.compile("0x([0-9a-fA-F]{6,8})\\b");

    /** Extract candidate 4-byte XOR keys from pseudocode hex literals. */
    private List<byte[]> extract4ByteKeys(String pseudo) {
        List<byte[]> keys = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        Matcher m = INT_LITERAL_PATTERN.matcher(pseudo);
        while (m.find()) {
            String hexStr = m.group(1);
            // Only 4-byte (8 hex chars) literals
            if (hexStr.length() != 8) continue;
            if (!seen.add(hexStr)) continue;
            try {
                long val = Long.parseUnsignedLong(hexStr, 16);
                byte[] key = new byte[4];
                key[0] = (byte)((val >> 24) & 0xFF);
                key[1] = (byte)((val >> 16) & 0xFF);
                key[2] = (byte)((val >>  8) & 0xFF);
                key[3] = (byte)( val        & 0xFF);
                keys.add(key);
            } catch (NumberFormatException ignore) {}
        }
        return keys;
    }

    // ── Main entry ────────────────────────────────────────────────────────────

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outputPath = (args != null && args.length > 0)
            ? args[0] : "C:/tmp/ghidra_dump.json";

        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        decomp.setSimplificationStyle("decompile");

        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager refMgr = currentProgram.getReferenceManager();

        Map<Long, String> ALGO_CONSTANTS = buildAlgoConstants();

        // ── 1. Collect all functions, split user vs crt ───────────────────────
        List<Function> userFuncs = new ArrayList<>();
        List<Function> crtFuncs  = new ArrayList<>();

        for (Function fn : fm.getFunctions(true)) {
            if (fn.isThunk()) continue;
            if (isCrtFunction(fn.getName())) crtFuncs.add(fn);
            else                              userFuncs.add(fn);
        }

        // Sort user functions: unnamed (FUN_) first (interesting unknowns),
        // then named, by address
        userFuncs.sort((a, b) -> {
            boolean aUnnamed = a.getName().startsWith("FUN_");
            boolean bUnnamed = b.getName().startsWith("FUN_");
            if (aUnnamed != bUnnamed) return aUnnamed ? -1 : 1;
            return a.getEntryPoint().compareTo(b.getEntryPoint());
        });

        // Try to find main/WinMain first and move it to front
        String[] ENTRY_NAMES = {"main", "_main", "WinMain", "wWinMain", "DllMain", "wmain"};
        for (String ename : ENTRY_NAMES) {
            SymbolIterator syms = currentProgram.getSymbolTable().getSymbols(ename);
            while (syms.hasNext()) {
                Symbol sym = syms.next();
                Function fn = fm.getFunctionAt(sym.getAddress());
                if (fn != null) {
                    userFuncs.remove(fn);
                    userFuncs.add(0, fn);
                    println("DumpAnalysis: found " + ename + " @ " + fn.getEntryPoint());
                }
            }
        }

        // Pre-compute incoming reference counts for all functions (for V4 dispatch detection)
        Map<Address, Integer> incomingRefCounts = new HashMap<>();
        for (Function fn : userFuncs) {
            int cnt = 0;
            for (Reference ref : refMgr.getReferencesTo(fn.getEntryPoint())) {
                if (ref.getReferenceType().isCall()) cnt++;
            }
            incomingRefCounts.put(fn.getEntryPoint(), cnt);
        }

        // Decompile: up to 150 user functions, then up to 30 crt
        int MAX_USER = 150, MAX_CRT = 30;
        List<Map<String, Object>> funcDump = new ArrayList<>();

        // V5: algo fingerprints accumulator (from pseudocode)
        List<Map<String, String>> algoFingerprints = new ArrayList<>();
        Set<String> algoFingerprintKeys = new HashSet<>(); // deduplicate by constant+location

        // V4: dispatch candidate tracking (up to 5)
        int dispatchCount = 0;
        int MAX_DISPATCH = 5;

        for (int pass = 0; pass < 2; pass++) {
            List<Function> src = (pass == 0) ? userFuncs : crtFuncs;
            int limit = (pass == 0) ? MAX_USER : MAX_CRT;
            int count = 0;
            for (Function fn : src) {
                if (count >= limit) break;
                DecompileResults result = decomp.decompileFunction(fn, 30, monitor);
                String pseudo = "";
                if (result != null && result.decompileCompleted()) {
                    var dc = result.getDecompiledFunction();
                    if (dc != null) pseudo = dc.getC();
                }
                if (pseudo.isEmpty()) continue;

                // Collect string refs for this function
                List<String> strRefs = new ArrayList<>();
                AddressSetView body = fn.getBody();
                AddressIterator addrIt = body.getAddresses(true);
                Set<String> seen = new HashSet<>();
                while (addrIt.hasNext()) {
                    Address a = addrIt.next();
                    for (Reference ref : refMgr.getReferencesFrom(a)) {
                        Address toAddr = ref.getToAddress();
                        Data d = currentProgram.getListing().getDefinedDataAt(toAddr);
                        if (d != null && d.getDataType().getName().toLowerCase().startsWith("string")) {
                            Object val = d.getValue();
                            if (val != null) {
                                String sv = val.toString();
                                if (sv.length() >= 4 && seen.add(sv)) {
                                    strRefs.add(esc(sv));
                                }
                            }
                        }
                    }
                }

                // Collect direct import calls
                List<String> impCalls = new ArrayList<>();
                Set<String> seenImp = new HashSet<>();
                addrIt = body.getAddresses(true);
                while (addrIt.hasNext()) {
                    Address a = addrIt.next();
                    for (Reference ref : refMgr.getReferencesFrom(a)) {
                        if (ref.getReferenceType().isCall()) {
                            Symbol sym = currentProgram.getSymbolTable()
                                .getPrimarySymbol(ref.getToAddress());
                            if (sym != null && sym.isExternal() && seenImp.add(sym.getName())) {
                                impCalls.add(esc(sym.getName()));
                            }
                        }
                    }
                }

                // V5: scan pseudocode for algo constants
                List<String[]> pseudoAlgoHits = findAlgoConstantsInPseudo(pseudo, ALGO_CONSTANTS);
                String fnLabel = fn.getName() + " @ " + fn.getEntryPoint().toString();
                for (String[] hit : pseudoAlgoHits) {
                    String dedupKey = hit[0] + "|" + fnLabel;
                    if (algoFingerprintKeys.add(dedupKey)) {
                        Map<String, String> fp = new LinkedHashMap<>();
                        fp.put("constant",  hit[0]);
                        fp.put("name",      hit[1]);
                        fp.put("found_in",  fnLabel);
                        algoFingerprints.add(fp);
                    }
                }

                Map<String, Object> fnMap = new LinkedHashMap<>();
                fnMap.put("address",    fn.getEntryPoint().toString());
                fnMap.put("name",       esc(fn.getName()));
                fnMap.put("size",       fn.getBody().getNumAddresses());
                fnMap.put("is_user",    (pass == 0));
                fnMap.put("str_refs",   strRefs);
                fnMap.put("imp_calls",  impCalls);
                fnMap.put("pseudocode", esc(pseudo));

                // V4: check dispatch candidate and attach disasm
                if (pass == 0 && dispatchCount < MAX_DISPATCH) {
                    int inCnt = incomingRefCounts.getOrDefault(fn.getEntryPoint(), 0);
                    if (isDispatchCandidate(fn, pseudo, inCnt)) {
                        List<Map<String, String>> disasmList = getDisasm(fn, 200);
                        fnMap.put("disasm", disasmList);
                        dispatchCount++;
                    }
                }

                funcDump.add(fnMap);
                count++;
            }
        }

        // ── 2. Strings + xrefs ───────────────────────────────────────────────
        List<Map<String, Object>> stringDump = new ArrayList<>();
        // V1: collect key candidates from strings
        List<String> keyCandidates = new ArrayList<>();

        for (Data d : currentProgram.getListing().getDefinedData(true)) {
            if (!d.getDataType().getName().toLowerCase().startsWith("string")) continue;
            Object val = d.getValue();
            if (val == null) continue;
            String sv = val.toString();
            if (sv.length() < 4) continue;

            // Collect xrefs
            List<String> xrefs = new ArrayList<>();
            for (Reference ref : refMgr.getReferencesTo(d.getAddress())) {
                Function fn = fm.getFunctionContaining(ref.getFromAddress());
                if (fn != null) {
                    String fname = fn.getName();
                    String entry = fn.getEntryPoint().toString();
                    xrefs.add(entry + ":" + esc(fname));
                }
            }

            Map<String, Object> sm = new LinkedHashMap<>();
            sm.put("address", d.getAddress().toString());
            sm.put("value",   esc(sv));
            sm.put("xrefs",   xrefs);
            stringDump.add(sm);

            // V1: check if this string is a key candidate
            if (isCryptoKeyCandidateStr(sv)) {
                keyCandidates.add(sv);
            }
        }

        // ── 3. Imports + categories ──────────────────────────────────────────
        List<Map<String, String>> importDump = new ArrayList<>();
        Map<String, List<String>> importByCat = new LinkedHashMap<>();
        for (String[] cat : IMPORT_CATS) importByCat.put(cat[0], new ArrayList<>());
        importByCat.put("general", new ArrayList<>());

        for (Symbol sym : currentProgram.getSymbolTable().getExternalSymbols()) {
            String sname = sym.getName();
            String sns   = sym.getParentNamespace().toString();
            String cat   = categorizeImport(sname);

            Map<String, String> im = new LinkedHashMap<>();
            im.put("name",      esc(sname));
            im.put("namespace", esc(sns));
            im.put("category",  cat);
            importDump.add(im);

            importByCat.computeIfAbsent(cat, k -> new ArrayList<>()).add(sname);
        }

        // ── 4. .data / .rdata byte arrays + XOR brute-force ─────────────────
        // V1: RC4 oracle + 4-byte XOR from pseudocode
        // V5: algo constant scan in raw bytes
        List<Map<String, Object>> dataDump = new ArrayList<>();
        Memory mem = currentProgram.getMemory();
        String[] SCAN_BLOCKS = {".data", ".rdata", "DATA", "RDATA", ".rodata"};

        // Collect all pseudocode for nearby-function 4-byte key extraction
        // Build a flat combined pseudocode string for 4-byte key extraction
        StringBuilder allPseudoSb = new StringBuilder();
        for (Map<String, Object> fnMap : funcDump) {
            Object pc = fnMap.get("pseudocode");
            if (pc != null) allPseudoSb.append(pc.toString()).append("\n");
        }
        String allPseudo = allPseudoSb.toString();
        List<byte[]> fourByteKeys = extract4ByteKeys(allPseudo);

        int rc4DecryptionCount = 0;

        for (MemoryBlock block : mem.getBlocks()) {
            boolean shouldScan = false;
            for (String bn : SCAN_BLOCKS) {
                if (block.getName().equalsIgnoreCase(bn)) { shouldScan = true; break; }
            }
            // Also scan any r/w initialized block
            if (!shouldScan && block.isInitialized() && block.isLoaded()
                    && block.isWrite() && !block.isExecute()) shouldScan = true;
            if (!shouldScan) continue;

            long blkSize = block.getSize();
            if (blkSize > 2 * 1024 * 1024) continue; // skip huge blocks

            byte[] bytes = new byte[(int) blkSize];
            try {
                block.getBytes(block.getStart(), bytes);
            } catch (Exception e) {
                continue;
            }

            // V5: scan entire block for algo constants in raw bytes
            List<String[]> blockAlgoHits = findAlgoConstantsInBytes(
                bytes, 0, bytes.length, ALGO_CONSTANTS, block.getStart());
            for (String[] hit : blockAlgoHits) {
                // hit: [hexVal, name, addrHex]
                String location = ".data @ " + hit[2];
                String dedupKey = hit[0] + "|" + location;
                if (algoFingerprintKeys.add(dedupKey)) {
                    Map<String, String> fp = new LinkedHashMap<>();
                    fp.put("constant",  hit[0]);
                    fp.put("name",      hit[1]);
                    fp.put("found_in",  location);
                    algoFingerprints.add(fp);
                }
            }

            // Scan for non-trivial byte sequences (not all-same, not all-zero)
            int i = 0;
            while (i < bytes.length) {
                // Skip zeros
                if (bytes[i] == 0) { i++; continue; }

                // Find run of non-zero bytes
                int start = i;
                while (i < bytes.length && bytes[i] != 0) i++;
                int len = i - start;

                if (len < 8 || len > 512) continue;

                // Check: are any bytes already printable ASCII?
                int printable = 0;
                for (int j2 = start; j2 < start + len; j2++) {
                    int b = bytes[j2] & 0xFF;
                    if (b >= 0x20 && b <= 0x7E) printable++;
                }
                // If >70% printable already, it's just a string — skip (already in strings)
                if ((double) printable / len > 0.70) continue;

                // Try XOR brute-force (single-byte)
                String xorResult = tryXorDecode(bytes, start, len);

                // Only include if XOR decodes OR if it's short enough to be interesting
                if (xorResult != null || len <= 64) {
                    Address blockBase = block.getStart();
                    Address seqAddr   = blockBase.add(start);

                    Map<String, Object> dm = new LinkedHashMap<>();
                    dm.put("address", seqAddr.toString());
                    dm.put("block",   block.getName());
                    dm.put("length",  len);
                    dm.put("hex",     hexBytes(bytes, start, Math.min(len, 64)));
                    if (xorResult != null) {
                        String[] parts = xorResult.split(":", 2);
                        dm.put("xor_key",     parts[0]);
                        dm.put("xor_decoded", parts.length > 1 ? parts[1] : "");
                    }

                    // V1: RC4 oracle — try each key candidate string
                    if (len >= 16 && len <= 512 && !keyCandidates.isEmpty()) {
                        byte[] blobData = Arrays.copyOfRange(bytes, start, start + len);
                        for (String keyStr : keyCandidates) {
                            try {
                                byte[] keyBytes = keyStr.getBytes("UTF-8");
                                byte[] decoded = rc4(keyBytes, blobData);
                                int decodedPrintable = countPrintable(decoded);
                                double ratio = (double) decodedPrintable / decoded.length;
                                int longestRun = longestPrintableRun(decoded);
                                if (ratio > 0.70 && longestRun >= 4) {
                                    dm.put("rc4_key",            esc(keyStr));
                                    dm.put("rc4_decoded_hex",    hexFull(decoded));
                                    String printableSeqs = printableSequences(decoded);
                                    dm.put("rc4_decoded_printable", esc(printableSeqs));
                                    rc4DecryptionCount++;
                                    break; // use first successful key
                                }
                            } catch (Exception ignore) {}
                        }
                    }

                    // V1: try 4-byte XOR keys from pseudocode integer literals
                    if (!fourByteKeys.isEmpty() && !dm.containsKey("xor_key")) {
                        byte[] blobData = Arrays.copyOfRange(bytes, start, start + len);
                        for (byte[] key4 : fourByteKeys) {
                            try {
                                byte[] decoded = new byte[blobData.length];
                                for (int ki = 0; ki < blobData.length; ki++) {
                                    decoded[ki] = (byte)(blobData[ki] ^ key4[ki % 4]);
                                }
                                int decodedPrintable = countPrintable(decoded);
                                double ratio = (double) decodedPrintable / decoded.length;
                                int longestRun = longestPrintableRun(decoded);
                                if (ratio > 0.70 && longestRun >= 4) {
                                    String keyHex = String.format("0x%02X%02X%02X%02X",
                                        key4[0] & 0xFF, key4[1] & 0xFF,
                                        key4[2] & 0xFF, key4[3] & 0xFF);
                                    dm.put("xor4_key",     keyHex);
                                    dm.put("xor4_decoded", esc(printableSequences(decoded)));
                                    break;
                                }
                            } catch (Exception ignore) {}
                        }
                    }

                    dataDump.add(dm);
                }
            }
        }

        // ── 5. Meta ───────────────────────────────────────────────────────────
        Address ep = currentProgram.getImageBase();
        String arch = currentProgram.getLanguage().getLanguageID().toString();
        int totalFuncs = fm.getFunctionCount();

        // ── 6. Serialize to JSON ──────────────────────────────────────────────
        StringBuilder json = new StringBuilder();
        json.append("{\n");

        // meta
        json.append("\"meta\": {\n");
        json.append("  \"version\": \"3\",\n");
        json.append("  \"binary_name\": \"").append(esc(currentProgram.getName())).append("\",\n");
        json.append("  \"image_base\": \"").append(ep).append("\",\n");
        json.append("  \"arch\": \"").append(arch).append("\",\n");
        json.append("  \"total_functions\": ").append(totalFuncs).append(",\n");
        json.append("  \"user_functions\": ").append(userFuncs.size()).append(",\n");
        json.append("  \"dumped_functions\": ").append(funcDump.size()).append(",\n");
        json.append("  \"strings_count\": ").append(stringDump.size()).append(",\n");
        json.append("  \"imports_count\": ").append(importDump.size()).append(",\n");
        json.append("  \"data_blobs\": ").append(dataDump.size()).append(",\n");
        json.append("  \"key_candidates\": ").append(keyCandidates.size()).append(",\n");
        json.append("  \"algo_fingerprints_count\": ").append(algoFingerprints.size()).append(",\n");
        json.append("  \"rc4_decryptions\": ").append(rc4DecryptionCount).append("\n");
        json.append("},\n");

        // import_categories (summary)
        json.append("\"import_categories\": {\n");
        boolean firstCat = true;
        for (Map.Entry<String, List<String>> e : importByCat.entrySet()) {
            if (e.getValue().isEmpty()) continue;
            if (!firstCat) json.append(",\n");
            json.append("  \"").append(e.getKey()).append("\": [");
            boolean fi = true;
            for (String n : e.getValue()) {
                if (!fi) json.append(", ");
                json.append("\"").append(esc(n)).append("\"");
                fi = false;
            }
            json.append("]");
            firstCat = false;
        }
        json.append("\n},\n");

        // imports
        json.append("\"imports\": [\n");
        for (int idx = 0; idx < importDump.size(); idx++) {
            Map<String, String> im = importDump.get(idx);
            json.append("  {\"name\": \"").append(im.get("name"))
                .append("\", \"namespace\": \"").append(im.get("namespace"))
                .append("\", \"category\": \"").append(im.get("category")).append("\"}");
            if (idx < importDump.size() - 1) json.append(",");
            json.append("\n");
        }
        json.append("],\n");

        // strings
        json.append("\"strings\": [\n");
        for (int idx = 0; idx < stringDump.size(); idx++) {
            Map<String, Object> sm = stringDump.get(idx);
            @SuppressWarnings("unchecked")
            List<String> xr = (List<String>) sm.get("xrefs");
            json.append("  {\"address\": \"").append(sm.get("address"))
                .append("\", \"value\": \"").append(sm.get("value"))
                .append("\", \"xrefs\": [");
            boolean fx = true;
            for (String x : xr) { if (!fx) json.append(", "); json.append("\"").append(x).append("\""); fx = false; }
            json.append("]}");
            if (idx < stringDump.size() - 1) json.append(",");
            json.append("\n");
        }
        json.append("],\n");

        // key_candidates (V1)
        json.append("\"key_candidates\": [\n");
        for (int idx = 0; idx < keyCandidates.size(); idx++) {
            json.append("  \"").append(esc(keyCandidates.get(idx))).append("\"");
            if (idx < keyCandidates.size() - 1) json.append(",");
            json.append("\n");
        }
        json.append("],\n");

        // algo_fingerprints (V5)
        json.append("\"algo_fingerprints\": [\n");
        for (int idx = 0; idx < algoFingerprints.size(); idx++) {
            Map<String, String> fp = algoFingerprints.get(idx);
            json.append("  {\"constant\": \"").append(fp.get("constant"))
                .append("\", \"name\": \"").append(fp.get("name"))
                .append("\", \"found_in\": \"").append(esc(fp.get("found_in"))).append("\"}");
            if (idx < algoFingerprints.size() - 1) json.append(",");
            json.append("\n");
        }
        json.append("],\n");

        // data_bytes (XOR candidates + RC4 oracle + 4-byte XOR)
        json.append("\"data_bytes\": [\n");
        for (int idx = 0; idx < dataDump.size(); idx++) {
            Map<String, Object> dm = dataDump.get(idx);
            json.append("  {");
            json.append("\"address\": \"").append(dm.get("address")).append("\"");
            json.append(", \"block\": \"").append(dm.get("block")).append("\"");
            json.append(", \"length\": ").append(dm.get("length"));
            json.append(", \"hex\": \"").append(dm.get("hex")).append("\"");
            if (dm.containsKey("xor_key")) {
                json.append(", \"xor_key\": \"").append(dm.get("xor_key")).append("\"");
                json.append(", \"xor_decoded\": \"").append(esc(dm.get("xor_decoded").toString())).append("\"");
            }
            if (dm.containsKey("xor4_key")) {
                json.append(", \"xor4_key\": \"").append(dm.get("xor4_key")).append("\"");
                json.append(", \"xor4_decoded\": \"").append(dm.get("xor4_decoded")).append("\"");
            }
            if (dm.containsKey("rc4_key")) {
                json.append(", \"rc4_key\": \"").append(dm.get("rc4_key")).append("\"");
                json.append(", \"rc4_decoded_hex\": \"").append(dm.get("rc4_decoded_hex")).append("\"");
                json.append(", \"rc4_decoded_printable\": \"").append(dm.get("rc4_decoded_printable")).append("\"");
            }
            json.append("}");
            if (idx < dataDump.size() - 1) json.append(",");
            json.append("\n");
        }
        json.append("],\n");

        // functions (with optional disasm for dispatch candidates)
        json.append("\"functions\": [\n");
        for (int idx = 0; idx < funcDump.size(); idx++) {
            Map<String, Object> fn = funcDump.get(idx);
            @SuppressWarnings("unchecked")
            List<String> strR = (List<String>) fn.get("str_refs");
            @SuppressWarnings("unchecked")
            List<String> impC = (List<String>) fn.get("imp_calls");

            json.append("  {");
            json.append("\"address\": \"").append(fn.get("address")).append("\"");
            json.append(", \"name\": \"").append(fn.get("name")).append("\"");
            json.append(", \"size\": ").append(fn.get("size"));
            json.append(", \"is_user\": ").append(fn.get("is_user"));
            json.append(", \"str_refs\": [");
            boolean fsr = true;
            for (String s : strR) { if (!fsr) json.append(", "); json.append("\"").append(s).append("\""); fsr = false; }
            json.append("]");
            json.append(", \"imp_calls\": [");
            boolean fic = true;
            for (String s : impC) { if (!fic) json.append(", "); json.append("\"").append(esc(s)).append("\""); fic = false; }
            json.append("]");
            json.append(", \"pseudocode\": \"").append(fn.get("pseudocode")).append("\"");

            // V4: emit disasm if present
            if (fn.containsKey("disasm")) {
                @SuppressWarnings("unchecked")
                List<Map<String, String>> disasmList = (List<Map<String, String>>) fn.get("disasm");
                json.append(", \"disasm\": [");
                for (int di = 0; di < disasmList.size(); di++) {
                    Map<String, String> row = disasmList.get(di);
                    json.append("{");
                    json.append("\"addr\": \"").append(row.get("addr")).append("\"");
                    json.append(", \"mnem\": \"").append(esc(row.get("mnem"))).append("\"");
                    json.append(", \"bytes\": \"").append(row.get("bytes")).append("\"");
                    json.append(", \"operands\": \"").append(esc(row.get("operands"))).append("\"");
                    json.append("}");
                    if (di < disasmList.size() - 1) json.append(", ");
                }
                json.append("]");
            }

            json.append("}");
            if (idx < funcDump.size() - 1) json.append(",");
            json.append("\n");
        }
        json.append("]\n}");

        Files.writeString(Paths.get(outputPath), json.toString(), java.nio.charset.StandardCharsets.UTF_8);
        println("DumpAnalysis v3: " + funcDump.size() + " functions, "
            + algoFingerprints.size() + " algo_fingerprints, "
            + rc4DecryptionCount + " rc4_decryptions, "
            + stringDump.size() + " strings, "
            + importDump.size() + " imports, "
            + dataDump.size() + " data blobs → " + outputPath);

        decomp.closeProgram();
    }
}
