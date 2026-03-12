# Dynamic RE — State & Progress

**Date**: 2026-03-12
**Target**: KYC Bot v1 + Bybit Manager v3 (Nuitka-compiled Python)
**Server**: 144.31.164.254 (Windows, RDP+SSH)

## Data Collected

### Memory Dumps (10 files, ~253 MB total)

| File | Process | PID | Size | Phase |
|------|---------|-----|------|-------|
| memory_dump_8572_20260312_052425.json | Bybit Manager | 8572 | 3.7 MB | Early (just started) |
| memory_dump_6752_20260312_052717.json | KYC Bot | 6752 | 30.4 MB | Early (just started) |
| memory_dump_20736_20260312_054322.json | KYC Bot | 20736 | 23.7 MB | Pre-test baseline |
| memory_dump_20736_20260312_054853.json | KYC Bot | 20736 | 23.8 MB | Mid-test |
| memory_dump_20736_20260312_061041.json | KYC Bot | 20736 | 24.3 MB | **Post-test (BEST)** |
| memory_dump_8404_20260312_055247.json | Bybit Manager | 8404 | 28.3 MB | Pre-test baseline |
| memory_dump_8404_20260312_061335.json | Bybit Manager | 8404 | 28.3 MB | Early test |
| memory_dump_8404_20260312_061940.json | Bybit Manager | 8404 | 28.4 MB | Pre-user-test |
| memory_dump_8404_20260312_062952.json | Bybit Manager | 8404 | 29.2 MB | Mid-test |
| memory_dump_8404_20260312_073230.json | Bybit Manager | 8404 | 33.3 MB | **Post-test (BEST)** |

### Best Dump Stats

#### KYC Bot (memory_dump_20736_20260312_061041.json)
- **708K ASCII strings**, 75K Unicode
- **503 URLs** (12 Bybit, 10+ SumSub, Telegram, ishushka, iproyal, dataimpulse)
- **45 API paths**
- **326 dataclass fields** (real struct field names from code)
- **~1800 Russian UI strings** (bot interface text, buttons, messages)
- **27 SQL statements** (including full SELECT bybit_account with all columns)
- **5 JWT tokens** (live sessions, user_ids 550758348, 550903295)
- **77 emails** (real iCloud accounts)
- **100 JSON blobs**
- **249 def/class statements**

#### Bybit Manager (memory_dump_8404_20260312_073230.json)
- **765K ASCII strings**, 18K Unicode
- **3,892 URLs** (96 Bybit, 14 captcha, 2 SumSub, proxy services)
- **645 API paths** across **45+ categories**:
  - account (33), contract (44), spot (33), margin (30), uta (30)
  - cross/isolated (22 each), trade (12), order (20), market (22)
  - trace/copytrading (51), plan (13), position (5), loan (8)
  - puzzle (11), airdrop-splash (7), deposit-activity (6), launchpool (4)
  - convert (4), tax (4), merchant (4), sub (7), captcha (2)
  - awarding (2), register (1), login, google2fa bind/unbind
- **42 tokens** (API keys, session tokens)
- **201 emails**
- **100 SQL statements**
- **31K python module paths**
- **100 JSON blobs**
- **20K+ docstrings** (real function documentation from Nuitka)

### Database Schema (Alembic Migrations — REAL Python code)
- **31 migration files** in `dumps/bybit_migrations/versions/`
- **16 tables**: email, bybit_account (60+ cols), finance_account, api_key,
  deposit_history, withdraw_history, deposit_address, withdraw_address,
  airdrophunt, tokensplash, ido, puzzlehunt, award, web3_wallet, web3_chain, web3_token
- **15 enums**: kycstatus, kycprovider, financeaccounttype (18 types),
  numberwallettype, web3chaintype, awardstatus, awardusingstatus,
  awardtype (20+), awardamountunit, businessno, autoclaimtype,
  productline (17), subproductline (37+)
- **2 triggers**: trg_delete_email, trigger_delete_zero_balance
- Full schema documentation in `dumps/bybit_db_schema_complete.md`

### Config Files (downloaded from server)
- `config.json` (both bots) — DB creds, Telegram token, SumSub keys, ADMIN_IDS
- `captcha_services.json` — capmonster API key
- `email_services.json` — 6 email providers (Gmail, Mail.ru, Outlook, Rambler, firstmail, iCloud)
- `proxy_services.json` — nodemaven, dataimpulse, iproyal with credentials
- `license.json` — license_id, secret_key

## Coverage Assessment

### KYC Bot — ~80% recoverable

| Layer | Coverage | Source |
|-------|----------|--------|
| DB schema | 100% | Alembic migrations (real .py) |
| API endpoints | ~90% | Memory URLs + API paths |
| UI/UX (Telegram) | ~85% | Russian strings, keyboard buttons, callback_data |
| Data structures | ~80% | 326 dataclass fields |
| Business logic | ~70% | API sequence, award lifecycle, proxy rotation |
| SQL queries | ~75% | Full SELECT with all columns |
| Config/credentials | 100% | Downloaded configs |
| Dependencies | 100% | 23K python module paths |
| Function signatures | ~40% | def statements, docstrings |
| Internal control flow | ~50% | Inferred from context + strings |

### Bybit Manager — ~85% recoverable

| Layer | Coverage | Source |
|-------|----------|--------|
| DB schema | 100% | Alembic migrations (real .py) |
| API endpoints | **~95%** | 645 paths across 45+ categories |
| Full Bybit API URLs | **~95%** | 96 real Bybit URLs with params |
| Data structures | ~80% | 390+ dataclass fields |
| Business logic | ~75% | API flows visible in URLs (withdraw, deposit, convert, trade) |
| Docstrings | **~90%** | 20K+ real function docs |
| Captcha integration | ~90% | 14 captcha service URLs |
| SQL queries | ~80% | 100 SQL statements |
| Config/credentials | 100% | Downloaded configs |
| Dependencies | 100% | 31K python module paths |
| Multi-language login | 100% | All locale URLs (EU, KZ, TR, GE variants) |

## What's Missing (for 100%)

1. **Runtime introspection** — sys.modules, class hierarchies, function signatures
   - sitecustomize.py approach crashed bots
   - Need: ctypes injection into running process or PYTHONSTARTUP env var
2. **PostgreSQL dump** — real data from DB (password auth failed for pg_dump)
3. **Network traffic capture** — request/response pairs with headers/bodies
4. **Exact control flow** — if/else, loops, error handling inside functions

## Next Steps

1. **Generate recovered source code** — combine all data (memory + migrations + configs + docstrings) into reconstructed Python modules
2. **Retry introspection** — alternative injection method for runtime module/class enumeration
3. **Network sniff** — mitmproxy or similar to capture actual API request/response pairs
4. **Cross-reference** — compare KYC bot and Bybit Manager shared code (same DB, same Telegram bot token)

## Files

```
dynamic_re/
├── STATE.md                    # This file
├── ssh_helper.py               # Paramiko SSH helper for server access
├── 04_memory_dump.py           # Memory dump tool (Windows API)
├── 03_nuitka_introspect.py     # Runtime introspection (not yet used)
├── 05_sitecustomize.py         # Auto-hook for Nuitka (crashed bots)
├── 07_analyze_dump.py          # Source code generator from dumps
├── dumps/
│   ├── bybit_db_schema_complete.md  # Full DB schema documentation
│   ├── bybit_migrations/            # 31 Alembic migration files (.py)
│   ├── memory_dump_20736_*.json     # KYC Bot dumps (3 files)
│   ├── memory_dump_8404_*.json      # Bybit Manager dumps (5 files)
│   ├── memory_dump_6752_*.json      # KYC Bot early dump
│   └── memory_dump_8572_*.json      # Bybit Manager early dump
├── 01_enable_ssh.ps1
├── 02_recon.ps1
├── 06_run_all.ps1
└── README.txt
```
