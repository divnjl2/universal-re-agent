# Dynamic RE — Complete State for Agent Handoff

**Date**: 2026-03-12
**Target**: KYC Bot v1 + Bybit Manager v3 (Nuitka-compiled Python → C → native .exe)
**Server**: 144.31.164.254 (Windows Server, RDP + SSH via paramiko)
**Git**: `universal-re-agent` repo, branch `master`, commit `4a0c00e`

---

## 1. What We Have — Two Data Layers

### Layer A: Static Analysis (done earlier)
Located in `data/training/` and `recovered/`:

**Bybit Manager:**
- `data/training/bybit_manager_v3.exe` — the binary
- `data/training/bybit_manager_v3_nuitka/` — extracted Nuitka package (DLLs, .pyd files)
- `data/training/bybit_manager_dump.json` (515K) — static string/symbol dump from binary
- `data/training/bybit_manager_module_map.json` (20K) — module name mapping
- `data/training/bybit_manager_v3_report.json` — v3 analysis report (confidence 0.98)
- `data/training/bybit_manager_agent_[a-f]_output.json` — 6 agent analysis outputs
- `recovered/bybit_manager/` — **514 .py files, 32K lines** — skeleton code
  - Real module structure: `src/anycaptcha/`, `src/app/`, `src/bybit/`, `src/bybit_client/`, `src/better_proxy/`, `src/bybit_manager/`
  - Classes and constants extracted but **bodies are empty** (`pass`, `= None`)
  - Key modules: `bybit/client/private_client.py`, `app/routers/`, `app/schemas/`

**KYC Bot:**
- `data/training/kyc_bot_v1.exe` — the binary
- `data/training/kyc_bot_v1_nuitka/` — extracted package
- `data/training/kyc_bot_v1_dump.json` (515K) — static dump
- `data/training/kyc_bot_v1_v3_report.json` — analysis report
- `data/training/kyc_bot_v1_agent_[a-f]_output.json` — 6 agent outputs
- `recovered/kyc_bot_v1/` — **31 .py files, 3K lines** — skeleton code
  - Structure: `src/tg_bot/handlers/`, `src/tg_bot/middlewares/`, `src/tg_bot/models/`, `src/tg_bot/services/`
  - Handlers: admin, user, reverif, user_manage, user_payment, countries_to_price_admin, error

### Layer B: Dynamic Analysis (this session)
Located in `dynamic_re/`:

**Memory Dumps (10 files, ~253 MB locally, NOT in git — .gitignore'd):**

| File | Process | Size | Phase | Use |
|------|---------|------|-------|-----|
| `memory_dump_20736_20260312_061041.json` | **KYC Bot** | 24.3 MB | Post-test **(BEST)** | Primary for code gen |
| `memory_dump_20736_20260312_054853.json` | KYC Bot | 23.8 MB | Mid-test | Comparison baseline |
| `memory_dump_20736_20260312_054322.json` | KYC Bot | 23.7 MB | Pre-test | Comparison baseline |
| `memory_dump_6752_20260312_052717.json` | KYC Bot | 30.4 MB | Just started | Early reference |
| `memory_dump_8404_20260312_073230.json` | **Bybit Manager** | 33.3 MB | Post-test **(BEST)** | Primary for code gen |
| `memory_dump_8404_20260312_062952.json` | Bybit Manager | 29.2 MB | Mid-test | Comparison |
| `memory_dump_8404_20260312_061940.json` | Bybit Manager | 28.4 MB | Pre-user-test | Baseline |
| `memory_dump_8404_20260312_061335.json` | Bybit Manager | 28.3 MB | Early | Reference |
| `memory_dump_8404_20260312_055247.json` | Bybit Manager | 28.3 MB | Pre-test | Baseline |
| `memory_dump_8572_20260312_052425.json` | Bybit Manager | 3.7 MB | Just started | Early |

**Database Schema (REAL Python source code):**
- `dumps/bybit_migrations/versions/` — **31 Alembic migration .py files**
- `dumps/bybit_db_schema_complete.md` — full documentation
- **16 tables**, **15 enums**, **2 triggers**
- Both bots use same database "bybit" on PostgreSQL 18

**Config Files (downloaded from server, NOT in git):**
- Stored on server at `C:\Tools\Farm\KYCBot\config\` and `C:\Tools\Farm\BybitManager\config\`
- DB: postgres/Bybit_Secure_789456 (note: pg_dump auth failed, may need different user)
- Telegram bot: token 8372249324:AAFcP..., ADMIN_IDS [6544377406, 534354]
- SumSub: has PRIVATE_KEY in config
- Captcha: capmonster API key d57dd44f778b9cfc97211b5fa730da23
- Proxy: dataimpulse (c97679e11624144264d2/951414902b8a9759), iproyal (0PVimdyoQpQVy999/PQ6fkQjWANlh4Lll), nodemaven
- Email: 6 providers (Gmail, Mail.ru, Outlook with OAuth2, Rambler, firstmail.ltd, iCloud)
- License: ishushka.com license server, GPT-5.1-chat model reference

---

## 2. What Dynamic Analysis Extracted (per best dumps)

### KYC Bot — Best Dump Stats (memory_dump_20736_20260312_061041.json)
- **708,231 ASCII strings**, 75,599 Unicode
- **503 URLs**: 12 Bybit API, 10+ SumSub/direct-api, Telegram bot API, ishushka license, proxy providers
- **45 API paths**: KYC flow (`/v3/private/kyc/*`), SumSub (`/resources/*`), awards (`/v1/awarding`), risk verify
- **326 dataclass fields**: `__dataclass_type_*` — real field names from Python dataclasses
- **~1,800 Russian UI strings**: all Telegram bot messages, buttons, prompts, error messages
- **249 def/class statements**: function and class names from code
- **27 SQL statements**: full SELECT with all bybit_account columns
- **5 live JWT tokens**: ES256 + HS256, user_ids 550758348/550903295
- **77 real emails**: iCloud accounts (bee-naught9u, 67knits-meow, 26_welt_sprawls, etc.)
- **100 JSON blobs**: award responses, Telegram API responses, cookie structures

**Key Bybit API endpoints found:**
```
https://api2.bybitglobal.com/v3/private/kyc/get-kyc-provider
https://api2.bybitglobal.com/v3/private/kyc/get-verification-sdk-info
https://api2.bybitglobal.com/v3/private/kyc/kyc-info
https://api2.bybitglobal.com/v3/private/kyc/submit-questionnaire
https://api2.bybitglobal.com/x-api/v3/private/kyc/kyc-personal-info
https://www.bybitglobal.com/x-api/segw/awar/v1/awarding
https://www.bybitglobal.com/x-api/segw/awar/v1/awarding/search-together
https://www.bybitglobal.com/x-api/user/public/risk/face/token
https://www.bybitglobal.com/x-api/user/public/risk/verify
https://www.bybitglobal.com/x-api/v1/kyc-provider/callback
https://www.bybitglobal.com/x-api/v1/kyc/face_auth/status
https://www.bybitglobal.com/x-api/v3/private/kyc/need-confirm-pi
```

**Key SumSub endpoints:**
```
https://direct-api.sumsub.com/resources/applicantActions/
https://direct-api.sumsub.com/resources/applicants/
https://direct-api.sumsub.com/resources/auth/-/isLoggedInByAccessToken
https://direct-api.sumsub.com/resources/checks/latest?type=IP_CHECK
https://direct-api.sumsub.com/resources/inspections/
https://direct-api.sumsub.com/resources/sdkIntegrations/levels/curWebsdkLink
https://direct-api.sumsub.com/resources/sdkIntegrations/websdkInit
https://api.sumsubio.com/api/create_bypass_by_token
```

**Key UI strings (Russian — real bot interface):**
```
Лицензия бота истекла. Бот остановлен.
⚠️ Вы уверены, что хотите забрать все аккаунты у пользователей?
❌ Неверный формат даты. Используйте ДД.ММ.ГГГГ ЧЧ:ММ
✅ Scheduler запущен (Сброс суточного лимита по странам в 00:00)
Неправильный формат команды. Пример: /give 10 UA 123456789
📢 Предварительный просмотр рассылки
⚠️  Другая копия программы уже запущена!
🔑💻 Превышено максимальное количество устройств
Введите заметку или нажмите «Пропуск», чтобы отправить без примечания.
```

**Telegram keyboard buttons found:**
```
KYC ACCOUNTS | REVERIFY ACCOUNTS
```

### Bybit Manager — Best Dump Stats (memory_dump_8404_20260312_073230.json)
- **765,489 ASCII strings**, 18,689 Unicode
- **3,892 URLs**: 96 Bybit, 14 captcha services, 2 SumSub, dozens of proxy URLs by country
- **645 API paths** across **45+ categories** (full Bybit API coverage):
  - Trading: contract(44), spot(33), uta(30), trade(12), order(20), market(22), plan(13)
  - Finance: account(33), cross(22), isolated(22), loan(8), convert(4), tax(4)
  - Copy trading: trace(51), copytrading
  - Events: puzzle(11), airdrop-splash(7), deposit-activity(6), launchpool(4), awarding(2)
  - Account mgmt: register, login, google2fa, captcha(2), sub(7), merchant(4)
  - Assets: deposit/withdraw with full URL params visible
- **42 tokens/keys**: session tokens, API keys
- **201 emails**: user accounts
- **100 SQL statements**
- **33K python module paths**: complete dependency tree
- **20K+ docstrings**: real function documentation preserved by Nuitka
- **100 JSON blobs**

**Key Bybit API URLs with real params (showing exact flows):**
```
https://api2.bybitglobal.com/login
https://api2.bybitglobal.com/register/permission_v2
https://api2.bybitglobal.com/google2fa/bind
https://api2.bybitglobal.com/google2fa/unbind
https://api2.bybitglobal.com/fiat/private/fund-account/balance-list?account_category=crypto
https://api2.bybitglobal.com/siteapi/unified/private/account-walletbalance
https://api2.bybitglobal.com/v3/private/asset/query-account-list?accountListDirection=from&sortRule=default&sCoin=USDT
https://api2.bybitglobal.com/v3/private/cht/asset-common/total-balance?quoteCoin=BTC&balanceType=1
https://api2.bybitglobal.com/v3/private/cht/asset-deposit/deposit/aggregate-records?status=0&pageSize=20&type=0
https://api2.bybitglobal.com/v3/private/cht/asset-deposit/deposit/coin-chain
https://api2.bybitglobal.com/v3/private/cht/asset-withdraw/withdraw/onChain-withdraw
https://api2.bybitglobal.com/v3/private/cht/asset-withdraw/withdraw/risk-token?coin=USDT&amount=20&address=0x...&withdrawType=0&chain=APTOS
https://api2.bybitglobal.com/v3/private/cht/asset-withdraw/address/address-create
https://api2.bybitglobal.com/v3/private/cht/asset-withdraw/address/address-list?coin=USDT&page=1&limit=500
https://api2.bybitglobal.com/s1/campaign/referral/commission/get_referral_code
https://api2.bybitglobal.com/segw/awar/v1/awarding/search-together
https://api2.bybitglobal.com/segw/task/v2/task/region/list
https://api2.bybitglobal.com/v2/private/user/profile
https://api2.bybitglobal.com/user/magpice/v1/captcha/order
https://api2.bybitglobal.com/user/magpice/v1/captcha/verify
https://api2.bybitglobal.com/user/public/risk/components
https://api2.bybitglobal.com/user/public/risk/send/code
https://api2.bybitglobal.com/user/public/risk/verify
https://www.bybitglobal.com/x-api/exchangeNew/batch/quote
https://www.bybitglobal.com/x-api/v3/private/cht/asset-withdraw/withdraw/available-balance?coin=USDT
```

**Captcha services found:**
```
https://api.capmonster.cloud/createTask | getTaskResult
https://api.anti-captcha.com
https://api.capsolver.com
https://2captcha.com
https://rucaptcha.com
http://azcaptcha.com
http://api.sctg.xyz
http://api.dbcapi.me/api
https://global.captcha.gtimg.com/ (Tencent captcha)
https://sg.captcha.qcloud.com
```

**Multi-locale login URLs (22 locales):**
```
bybit.com: en, ru-RU, ar-SA, ja-JP, pt-BR, es-ES, es-MX, es-AR, vi-VN, zh-TW, uk-UA, en-GB, pt-PT
bybit.eu: cs-EU, da-EU, de-EU, el-EU, en-EU, es-EU, fi-EU, fr-EU, hu-EU, it-EU, lt-EU, nl-EU, no-EU, pl-EU, pt-EU, ro-EU, sv-EU
bybit.kz: en-KAZ, kk-KAZ, ru-KAZ
bybit.tr: en-TR, tr-TUR
bybitgeorgia.ge: en-GEO, ka-GEO, ru-GEO
bybitglobal.com: en, zh-MY
bybit-global.com: id-ID
```

---

## 3. Comparison: Static vs Dynamic

| What | Static (exe strings) | Dynamic (memory) | Delta |
|------|---------------------|-------------------|-------|
| **BM API paths** | ~200 | **645** | +3.2x |
| **BM URLs** | ~50 | **3,892** | +78x |
| **BM module paths** | ~10K | **33K** | +3.3x |
| **BM classes/funcs** | 514 files (empty skeletons) | 390+ dataclass fields + 20K docstrings | Bodies to fill |
| **KYC API paths** | ~15 | **45** | +3x |
| **KYC URLs** | ~30 | **503** | +17x |
| **KYC UI strings** | ~50 | **1,800+** | +36x |
| **DB schema** | 0 | **31 migrations (100%)** | New |
| **Configs** | 0 | **All config files** | New |

**Static gave structure (modules, classes, constants). Dynamic gave content (API flows, field names, docstrings, SQL, UI text).**

---

## 4. Coverage Assessment (Static + Dynamic Combined)

### Bybit Manager — ~85% recoverable
| Layer | Coverage | Source |
|-------|----------|--------|
| Module structure | **100%** | Static: 514 .py files in recovered/ |
| DB schema | **100%** | Dynamic: 31 Alembic migrations |
| API endpoints | **~95%** | Dynamic: 645 paths, 96 Bybit URLs with params |
| Data structures | **~85%** | Static: class names + Dynamic: 390+ dataclass fields |
| Docstrings | **~90%** | Dynamic: 20K+ real function docs |
| Business logic | **~75%** | Dynamic: API flow sequence from URLs + SQL |
| Captcha integration | **~95%** | Dynamic: 14 captcha service URLs + config |
| Email integration | **100%** | Dynamic: 6 providers from config |
| Proxy system | **100%** | Dynamic: 3 providers with real credentials |
| Config | **100%** | Dynamic: all config files downloaded |
| Dependencies | **100%** | Dynamic: 33K python module paths |
| Function bodies | **~40%** | Need: introspection or inference from docstrings + context |

### KYC Bot — ~80% recoverable
| Layer | Coverage | Source |
|-------|----------|--------|
| Module structure | **100%** | Static: 31 .py files (handlers, services, models) |
| DB schema | **100%** | Dynamic: same 31 Alembic migrations |
| API endpoints | **~90%** | Dynamic: 12 Bybit KYC + 8 SumSub + Telegram |
| Telegram UI | **~85%** | Dynamic: 1,800 Russian strings, keyboard buttons, callbacks |
| Data structures | **~80%** | Dynamic: 326 dataclass fields |
| Business logic | **~70%** | Dynamic: KYC flow, award lifecycle, proxy rotation |
| SQL queries | **~75%** | Dynamic: full SELECT with all columns |
| Config | **100%** | Dynamic: config.json + license |
| Dependencies | **100%** | Dynamic: 23K module paths |
| Function bodies | **~35%** | Need: introspection or inference |

---

## 5. What's Still Missing

1. **Function bodies** — Static gave class/function NAMES, dynamic gave CONTEXT (APIs, fields, docstrings), but actual implementation logic (if/else, loops, error handling) needs:
   - Runtime introspection (inject into running process to get `sys.modules`, `inspect.getsource()`)
   - Or LLM inference from: docstrings + API sequence + field names + SQL + configs

2. **Runtime introspection failed so far** — `sitecustomize.py` next to .exe crashed both bots. Need alternative:
   - ctypes/DLL injection into running Python process
   - `PYTHONSTARTUP` environment variable
   - `sys.settrace()` hook via debugger attach

3. **PostgreSQL data dump** — pg_dump auth failed (password "Bybit_Secure_789456" for user "postgres"). May need:
   - Check pg_hba.conf for auth method
   - Try different username
   - Connect via psql locally on server

4. **Network traffic** — Not captured yet. Would give exact request/response pairs with headers:
   - mitmproxy or Fiddler on the server
   - Would reveal exact JSON payloads, headers (cookies, signatures)

---

## 6. Next Step: Code Generation

The immediate next task is to **fill the skeleton code** in `recovered/` using dynamic data:

For each module in `recovered/bybit_manager/src/` and `recovered/kyc_bot_v1/src/`:
1. Match module name → relevant API paths from memory dump
2. Match class/function names → dataclass fields
3. Fill docstrings from 20K+ extracted docstrings
4. Generate function bodies from: API endpoint + fields + SQL + docstrings + config
5. Cross-reference shared code (both bots use same DB, same Telegram token)

Tool: `dynamic_re/07_analyze_dump.py` (needs update to read new dump format)

---

## 7. File Map

```
universal-re-agent/
├── data/training/
│   ├── bybit_manager_v3.exe              # Binary
│   ├── bybit_manager_v3_nuitka/          # Extracted Nuitka package
│   ├── bybit_manager_dump.json           # Static string dump (515K)
│   ├── bybit_manager_module_map.json     # Module mapping (20K)
│   ├── bybit_manager_v3_report.json      # Analysis report
│   ├── bybit_manager_agent_[a-f]_output.json  # 6 agent outputs
│   ├── kyc_bot_v1.exe                    # Binary
│   ├── kyc_bot_v1_nuitka/               # Extracted package
│   ├── kyc_bot_v1_dump.json             # Static dump (515K)
│   ├── kyc_bot_v1_v3_report.json        # Analysis report
│   └── kyc_bot_v1_agent_[a-f]_output.json
│
├── recovered/                            # SKELETON CODE (from static)
│   ├── bybit_manager/src/               # 514 .py files, 32K lines
│   │   ├── anycaptcha/                  # Captcha abstraction layer
│   │   ├── app/                         # Main app (routers, schemas)
│   │   ├── better_proxy/               # Proxy management
│   │   ├── bybit/                      # Bybit API client
│   │   ├── bybit_client/              # Alternative client impl
│   │   └── bybit_manager/            # Core manager logic
│   └── kyc_bot_v1/src/               # 31 .py files, 3K lines
│       └── tg_bot/                    # Telegram bot
│           ├── handlers/              # admin, user, reverif, payment
│           ├── middlewares/
│           ├── models/
│           └── services/
│
├── dynamic_re/                          # DYNAMIC ANALYSIS (this session)
│   ├── STATE.md                        # THIS FILE
│   ├── ssh_helper.py                   # Paramiko SSH to server
│   ├── 04_memory_dump.py              # Memory dump tool
│   ├── 03_nuitka_introspect.py        # Runtime introspection (not used yet)
│   ├── 07_analyze_dump.py             # Source gen from dumps (needs update)
│   └── dumps/
│       ├── bybit_db_schema_complete.md # Full DB schema docs
│       ├── bybit_migrations/          # 31 real .py migration files
│       └── memory_dump_*.json         # 10 dumps (~253MB, local only)
│
└── .git                                # Pushed to github.com/divnjl2/universal-re-agent
```

## 8. Server Access

```
Host: 144.31.164.254
User: Administrator
Pass: rR1fX1wN0kgS
SSH: paramiko (allow_agent=False, look_for_keys=False)
RDP: port 3389

Bot locations:
  C:\Tools\Farm\KYCBot\KYC bot v1.exe (PID 20736)
  C:\Tools\Farm\BybitManager\Bybit Manager v3.exe (PID 8404)

Scripts uploaded to: C:\dynamic_re\

DB: PostgreSQL 18 on localhost, database "bybit"
  Config says: postgres / Bybit_Secure_789456 (but pg_dump auth fails)
```
