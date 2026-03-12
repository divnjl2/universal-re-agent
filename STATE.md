# Reverse Engineering Findings - Nuitka-Compiled Python Bots

**Date:** 2026-03-12
**Targets:** Bybit Manager v3.exe, KYC bot v1.exe
**Methods:** Static analysis (Nuitka binary introspection, memory dumps), Dynamic analysis (Frida hooking, traffic capture)

---

## 1. Architecture Overview

### Bybit Manager v3

An automated Bybit exchange account management tool. It handles mass login, balance checking, captcha solving, 2FA verification, orderbook reading, and likely registration and trading across 100+ accounts simultaneously.

**Build:**
- Compiled with Nuitka (Python -> native .exe)
- Process structure: launcher (PID 7500) + worker (PID 2796). The launcher spawns a worker that does all the real work (27,011 of 27,067 captured events came from the worker)
- Uses FastAPI (`app.routers`) for a local management API
- Uses `httpx` for HTTP via AdsPower browser profiles (not direct requests)
- Uses `pydantic` models throughout for data validation
- Database: PostgreSQL via SQLAlchemy 2.0 async + Alembic migrations (31 migration files recovered, spanning 2024-12-27 to 2026-02-27)

**Key packages recovered from binary:**
- `bybit/` - core Bybit API client (client, account, password, device, constants, enums, models, web3)
- `bybit_client/` - second-layer client abstraction (public_client, private_client, base_private_client)
- `anycaptcha/` - captcha solving integration (transport layer, captcha types)
- `better_proxy/` - proxy management
- `app/` - FastAPI application (routers, schemas, dependencies, enums, exceptions)
- `bybit/web3/` - Web3/DeFi integration (eth swap, transfer, utils)
- `bybit/models/web3/` - Web3 data models (wallet, token, staking, ido, activity, chain, gas, transaction)
- `bybit/models/x_api/` - Cross-exchange API models (cross, withdraw)

### KYC bot v1

A Telegram bot that manages Bybit KYC (Know Your Customer) verification for accounts. It reads from the same PostgreSQL database that Bybit Manager writes to, distributes accounts to human KYC operators via Telegram, and tracks verification status.

**Build:**
- Compiled with Nuitka (Python -> native .exe)
- Process structure: launcher (PID 6752) + worker (PID 3880). Minimal traffic captured (54 events) -- was not actively running during capture
- Uses aiogram 3.x for Telegram bot functionality
- Uses SQLAlchemy 2.0 async for PostgreSQL
- Uses APScheduler for scheduled tasks
- Licensed via ishushka.com (HWID-bound licensing)

**Bot username from memory:** `kyc_bot_shop_bot`

---

## 2. Bybit Manager - Complete API Map

### Traffic Capture Metadata
- **Capture duration:** 5 minutes (12:27:21 to 12:32:21 UTC, 2026-03-12)
- **Total events:** 27,067
- **Total HTTP requests:** 1,723
- **Total HTTP responses:** 1,645
- **Unique endpoints:** 23
- **Unique session GUIDs:** 265 (each represents an AdsPower browser profile session)
- **Unique email accounts seen:** 113

### AUTHENTICATION (2 endpoints)

| # | Method | Endpoint | Count | Request Body | Response Body | Auth |
|---|--------|----------|-------|-------------|---------------|------|
| 1 | GET | `www.bybitglobal.com/en/login` | 117 | (none) | 302 redirect OR JSON `{ret_code:0, result:{result:true, token:"..."}}` | Cookies: `_by_l_g_d`, `deviceId`, `sensorsdata2015jssdkcross`, `BYBIT_REG_REF_prod` |
| 2 | POST | `api2.bybitglobal.com/login` | 137 | `{username, proto_ver:"2.1", encrypt_password, encrypt_timestamp, magpie_verify_info:{token, scene:"31000"}}` | `{ret_code:0, result:{result:true, token:"...", state:"", challenge_type:"", serial_no:""}}` | Same cookies + `guid` header |

### CAPTCHA - Bybit Side (2 endpoints)

| # | Method | Endpoint | Count | Request Body | Response Body |
|---|--------|----------|-------|-------------|---------------|
| 3 | POST | `api2.bybitglobal.com/user/magpice/v1/captcha/order` | 75 | `{login_name:"<md5_hash>", scene:"31000", country_code:"", txid:""}` | `{ret_code:0, result:{result:true, token:"...", challenge_type:"", challenge:"", serial_no:""}}` |
| 4 | POST | `api2.bybitglobal.com/user/magpice/v1/captcha/verify` | 81 | `{captcha_type:"recaptcha", scene:"31000", serial_no:"...", g_recaptcha_response:"<token>"}` | `{ret_code:0, result:{result:true, token:"..."}}` |

### CAPTCHA - CapMonster Service (2 endpoints)

| # | Method | Endpoint | Count | Request Body | Response Body |
|---|--------|----------|-------|-------------|---------------|
| 5 | POST | `api.capmonster.cloud/createTask` | 75 | `{clientKey:"<key>", task:{type:"RecaptchaV2Task", websiteURL:"https://bybitglobal.com", websiteKey:"<siteKey>", isInvisible:0, proxy:"<proxy_string>", userAgent:"<ua>"}}` | `{taskId:<int>, errorId:0}` |
| 6 | POST | `api.capmonster.cloud/getTaskResult` | 78 | `{clientKey:"<key>", taskId:"<id>"}` | `{errorId:0, status:"ready", solution:{gRecaptchaResponse:"<token>"}}` or polling response |

### RISK MANAGEMENT / 2FA (2 endpoints)

| # | Method | Endpoint | Count | Request Body | Response Body |
|---|--------|----------|-------|-------------|---------------|
| 7 | POST | `api2.bybitglobal.com/user/public/risk/components` | 59 | `{risk_token:"<token>#<hash>"}` | Lists required security components. Can return 302 redirect to /en/login if session expired. When successful: `{component_type:2, component_list:[{component_id:"google2fa"}]}` |
| 8 | POST | `api2.bybitglobal.com/user/public/risk/verify` | 54 | `{risk_token:"<token>#<hash>", component_list:{google2fa:"<6-digit-code>"}}` | `{ret_code:0, result:{risk_token:"...", ret_code:0, component_list:[{component_id:"google2fa", component_code:0, ext_info:{}}]}}` |

### BALANCE / PRIVATE API (4 endpoints)

| # | Method | Endpoint | Count | Request Body | Response Body | Auth Required |
|---|--------|----------|-------|-------------|---------------|---------------|
| 9 | GET | `api2.bybitglobal.com/v3/private/cht/asset-common/total-balance?quoteCoin=BTC&balanceType=1` | 299 | (none) | `{ret_code:0, result:<timestamp>}` (when auth fails: `{ret_code:10007, ret_msg:"User authentication failed."}`) | `secure-token` cookie (ES256 JWT) |
| 10 | GET | `api2.bybitglobal.com/fiat/private/fund-account/balance-list?account_category=crypto` | 237 | (none) | Binary/gzip (JSON with balance data) | `secure-token` + `self-unbind-token` cookies |
| 11 | POST | `api2.bybitglobal.com/siteapi/unified/private/account-walletbalance` | 236 | (empty body, Content-Length: 0) | Binary/gzip (JSON with wallet balance) | `secure-token` cookie. Response header may include refreshed `Token` |
| 12 | GET | `api2.bybitglobal.com/v2/private/user/profile` | 90 | (none) | Binary/gzip (JSON with user profile) | `secure-token` + `self-unbind-token` cookies |

### REGISTRATION (1 endpoint)

| # | Method | Endpoint | Count | Request Body | Response Body |
|---|--------|----------|-------|-------------|---------------|
| 13 | GET | `api2.bybitglobal.com/register/permission_v2` | 84 | (none) | `{ret_code:0, result:{code:"DZ", name_en:"Algeria", is_visible:1, is_login:1, is_trade:1, ip:"<proxy_ip>", ban_time:"...", is_sanction_ip_disallow:0, refer_site_id:"BYBIT"}}` |

### SPOT TRADING / ACTIVITY (1 endpoint)

| # | Method | Endpoint | Count | Request Body | Response Body |
|---|--------|----------|-------|-------------|---------------|
| 14 | GET | `api2.bybitglobal.com/spot/api/activity/v1/project/system/date` | 54 | (none) | Binary/gzip (system date/activity data) |

### MARKET DATA / ORDERBOOK (9 endpoints, public API)

| # | Method | Endpoint | Count |
|---|--------|----------|-------|
| 15 | GET | `api.bybitglobal.com/v5/market/orderbook?symbol=MNTUSDT&limit=15&category=spot` | 33 |
| 16 | GET | `api.bybitglobal.com/v5/market/orderbook?symbol=TRIAUSDT&limit=15&category=spot` | 4 |
| 17 | GET | `api.bybitglobal.com/v5/market/orderbook?symbol=ZAMAUSDT&limit=15&category=spot` | 3 |
| 18 | GET | `api.bybitglobal.com/v5/market/orderbook?symbol=NIGHTUSDT&limit=15&category=spot` | 2 |
| 19 | GET | `api.bybitglobal.com/v5/market/orderbook?symbol=PENGUINUSDT&limit=15&category=spot` | 1 |
| 20 | GET | `api.bybitglobal.com/v5/market/orderbook?symbol=ELONUSDT&limit=15&category=spot` | 1 |
| 21 | GET | `api.bybitglobal.com/v5/market/orderbook?symbol=ADAUSDT&limit=15&category=spot` | 1 |
| 22 | GET | `api.bybitglobal.com/v5/market/orderbook?symbol=DOGEUSDT&limit=15&category=spot` | 1 |
| 23 | GET | `api.bybitglobal.com/v5/market/orderbook?symbol=LTCUSDT&limit=15&category=spot` | 1 |

All orderbook requests use `api.bybitglobal.com` (not `api2`), with `limit=15` and `category=spot`. Response bodies are binary/gzip (12KB+ for MNTUSDT).

### Host Distribution

| Host | Request Count |
|------|-------------|
| api2.bybitglobal.com | 1,406 |
| api.capmonster.cloud | 153 |
| www.bybitglobal.com | 117 |
| api.bybitglobal.com | 47 |

---

## 3. Bybit Manager - Login Flow (Step by Step)

The complete login sequence for one account, confirmed by traffic capture:

### Step 1: Initialize Browser Session
- Open AdsPower profile (each account has its own profile with persistent cookies/fingerprint)
- Navigate to `GET www.bybitglobal.com/en/login`
- Receive EdgeOne CDN cookies: `EO-Bot-Session`, `EO-Bot-SessionId`, `EO-Bot-Token`
- Receive `X-Country-Code` header confirming proxy geo-location

### Step 2: Request Captcha Challenge
- `POST api2.bybitglobal.com/user/magpice/v1/captcha/order`
- Body: `{login_name: "<md5_of_email>", scene: "31000", country_code: "", txid: ""}`
- `login_name` is an MD5 hash of the email address (e.g., `80cdfd2e081755b2911b9a101a60addd`)
- `scene: "31000"` = login captcha scene
- Response: `{result:{token:"...", serial_no:"..."}}`

### Step 3: Solve Captcha via CapMonster
- `POST api.capmonster.cloud/createTask`
- Body:
  ```json
  {
    "clientKey": "d57dd44f778b9cfc97211b5fa730da23",
    "task": {
      "type": "RecaptchaV2Task",
      "websiteURL": "https://bybitglobal.com",
      "websiteKey": "6LcJqb0pAAAAAEJCmRWqNFtGGMG7Gr20S-F1TTq6",
      "isInvisible": 0,
      "proxy": "<iProyal_proxy_string>",
      "userAgent": "<matching_user_agent>"
    }
  }
  ```
- Poll `POST api.capmonster.cloud/getTaskResult` with `{clientKey, taskId}` until solved
- User-Agent in CapMonster request: `python-anycaptcha` (reveals the library used)

### Step 4: Submit Captcha Verification to Bybit
- `POST api2.bybitglobal.com/user/magpice/v1/captcha/verify`
- Body:
  ```json
  {
    "captcha_type": "recaptcha",
    "scene": "31000",
    "serial_no": "<from_step_2>",
    "g_recaptcha_response": "<from_capmonster>"
  }
  ```
- Response: `{result:{result:true, token:"<magpie_token>"}}`

### Step 5: Login with Credentials
- `POST api2.bybitglobal.com/login`
- Body:
  ```json
  {
    "username": "mergers-footy.3y@icloud.com",
    "proto_ver": "2.1",
    "encrypt_password": "<RSA_encrypted_password_base64>",
    "encrypt_timestamp": "1773343638611",
    "magpie_verify_info": {
      "token": "<from_step_4>",
      "scene": "31000"
    }
  }
  ```
- Password is RSA-encrypted with a timestamp (RSA-OAEP, 2048-bit key, base64-encoded)
- Response on success: `{ret_code:0, result:{result:true, token:"...", state:""}}`
- Response sets cookies: `self-unbind-token` (HS256 JWT), `secure-token` (ES256 JWT), `isLogin=1`

### Step 6: Risk/2FA Check
- `POST api2.bybitglobal.com/user/public/risk/components`
- Body: `{risk_token: "<from_login_response>"}`
- Response may require Google 2FA: `{component_list:[{component_id:"google2fa"}]}`

### Step 7: Submit 2FA Code
- `POST api2.bybitglobal.com/user/public/risk/verify`
- Body: `{risk_token:"...", component_list:{google2fa:"896049"}}`
- The 6-digit TOTP code is generated from `totp_secret` stored in the database
- Response on success: `{ret_code:0, result:{component_list:[{component_id:"google2fa", component_code:0}]}}`

### Step 8: Post-Login Data Collection
Parallel requests after successful login:
- `GET api2.bybitglobal.com/v2/private/user/profile` (user profile data)
- `GET api2.bybitglobal.com/v3/private/cht/asset-common/total-balance?quoteCoin=BTC&balanceType=1` (total balance in BTC)
- `GET api2.bybitglobal.com/fiat/private/fund-account/balance-list?account_category=crypto` (fiat fund account)
- `POST api2.bybitglobal.com/siteapi/unified/private/account-walletbalance` (unified wallet)
- `GET api2.bybitglobal.com/register/permission_v2` (geo/permission check)
- `GET api2.bybitglobal.com/spot/api/activity/v1/project/system/date` (activity/promo data)

### Step 9: Market Data (if trading)
- `GET api.bybitglobal.com/v5/market/orderbook?symbol=MNTUSDT&limit=15&category=spot`
- Primary focus on MNTUSDT (33 requests), with occasional checks of TRIA, ZAMA, NIGHT, PENGUIN, ELON, ADA, DOGE, LTC

---

## 4. Bybit Manager - Captcha Flow

### CapMonster Integration

The bot uses the `anycaptcha` Python library (User-Agent: `python-anycaptcha`) to communicate with CapMonster Cloud.

**Service:** api.capmonster.cloud
**Task Type:** `RecaptchaV2Task` (NOT invisible)

**createTask request format:**
```json
{
  "clientKey": "d57dd44f778b9cfc97211b5fa730da23",
  "task": {
    "type": "RecaptchaV2Task",
    "websiteURL": "https://bybitglobal.com",
    "websiteKey": "6LcJqb0pAAAAAEJCmRWqNFtGGMG7Gr20S-F1TTq6",
    "isInvisible": 0,
    "proxy": "<user:pass@host:port format>",
    "userAgent": "<matching Chrome UA>"
  }
}
```

**Key observations:**
- The proxy is passed TO CapMonster so it solves using the same IP as the bot's session (proxy-bound solving)
- `isInvisible: 0` means it's a visible reCAPTCHA v2
- The siteKey `6LcJqb0pAAAAAEJCmRWqNFtGGMG7Gr20S-F1TTq6` belongs to Bybit's login page

**getTaskResult polling:**
- Polls every ~5-20 seconds until solution is ready
- Solution contains `gRecaptchaResponse` token (~2KB base64 string)

**Bybit Captcha Flow (Magpie system):**
1. `captcha/order` - request a captcha challenge (login_name is MD5 of email, scene 31000)
2. CapMonster solves the reCAPTCHA
3. `captcha/verify` - submit the reCAPTCHA solution to Bybit
4. Verified token is passed to `/login` in `magpie_verify_info`

**Additional captcha types found in binary (not seen in traffic):**
- From recovered `bybit_client.bybit.models.captcha`: `BadTencentCaptchaCookies`, `BadTencentCaptchaSolution` -- indicates Tencent captcha support exists
- From captcha order response: `challenge: "geecaptcha,qqcaptcha,gee4captcha"` -- Bybit sometimes returns GeeTest/QQ captcha types
- The recovered `anycaptcha` module also has: `RecaptchaV3`, `HCaptcha`, `FunCaptcha`, `KeyCaptcha`, `Capy`, `ImageCaptcha`, `TextCaptcha`

---

## 5. Bybit Manager - Infrastructure

### Proxy Providers (3 providers, 112 unique credentials observed)

**1. iProyal (geo.iproyal.com:11250)**
- Format: `user:password_country-XX_session-XXXXXXXX_lifetime-168h@geo.iproyal.com:11250`
- Credentials: `0PVimdyoQpQVy999:PQ6fkQjWANlh4Lll`
- Session-based sticky IPs with 168h (7 day) lifetime
- Most heavily used provider (majority of connections via 91.239.130.17:11250)

**2. DataImpulse (gw.dataimpulse.com)**
- Format: `c97679e11624144264d2__cr.XX:951414902b8a9759@gw.dataimpulse.com`
- Country code embedded in username with `__cr.` prefix
- Seen for 31+ countries

**3. NodeMaven (gate.nodemaven.com)**
- Format: `lazunegor_gmail_com-country-XX-sid-XXXXXXXX-filter-medium:jpcr50xmhd@gate.nodemaven.com`
- Username contains the operator's email: `lazunegor@gmail.com` (underscores replace special chars)
- Session IDs are unique per connection
- `filter-medium` quality tier

**4. Two additional simple auth proxies seen:**
- `QwYi7vnV:n3ZfF7LW` (connecting to various IPs on non-standard ports)
- `xqQXz9GA:3nrCPNkN` (same pattern)

### Direct Connection IPs (top proxy endpoints)
| IP | Port | Count | Likely Provider |
|----|------|-------|----------------|
| 91.239.130.17 | 11250 | 103 | iProyal |
| 135.148.136.22 | 8080 | 32 | Unknown |
| 135.181.20.38 | 443 | 28 | Unknown (direct?) |
| 167.235.26.46 | 11250 | 27 | iProyal |
| 91.239.130.34 | 11250 | 15 | iProyal |
| 67.213.121.105 | various | ~50 | NodeMaven/other |

### AdsPower Antidetect Browser
- Local API: `localhost:50325` (standard AdsPower port)
- 265 unique GUIDs in 5 minutes = 265 distinct browser profiles used
- Each profile has its own: cookies, fingerprint, proxy, user-agent

### Chrome Version Rotation
User-Agents seen across profiles (all Chrome-based):
- Chrome 133, 134, 135, 136 (Windows NT 10.0)
- Chrome 133, 134, 135, 136, 142, 143, 144 (macOS 10_15_7)
- Range: **133 to 144** (12 distinct Chrome versions)
- Both Windows and macOS platform spoofing

### Account Email Patterns
- **Primary:** `@icloud.com` - auto-generated patterns like `word-word.Xchar@icloud.com` (e.g., `mergers-footy.3y@icloud.com`, `cavalry-challis-6e@icloud.com`)
- **Secondary:** `@rambler.ru` - Russian emails (e.g., `genakiselevfb3018@rambler.ru`, `lazunegor@gmail.com`)
- **Total unique accounts:** 113 in 5 minutes of capture

### Country Targeting
31 countries observed in proxy geo-targeting:

AE (UAE), AO (Angola), BG (Bulgaria), BO (Bolivia), BW (Botswana), BY (Belarus), CI (Ivory Coast), CL (Chile), CR (Costa Rica), DE (Germany), DZ (Algeria), EC (Ecuador), EG (Egypt), ET (Ethiopia), GE (Georgia), GT (Guatemala), HN (Honduras), IQ (Iraq), JO (Jordan), KE (Kenya), KW (Kuwait), LK (Sri Lanka), MA (Morocco), MG (Madagascar), MW (Malawi), MZ (Mozambique), NG (Nigeria), NI (Nicaragua), NP (Nepal), PA (Panama), PY (Paraguay), RU (Russia), RW (Rwanda), SA (Saudi Arabia), TG (Togo), TR (Turkey), TZ (Tanzania), UG (Uganda), UY (Uruguay), ZA (South Africa), ZM (Zambia), ZW (Zimbabwe)

Pattern: Primarily developing countries and countries where Bybit allows registration without heavy restrictions.

---

## 6. KYC Bot - Architecture

### Telegram Bot Structure

**Framework:** aiogram 3.x (async Telegram Bot API)
**Entry point:** `start_bot.py` -> `asyncio.run(main())`
**Bot username:** `kyc_bot_shop_bot`

**Handlers (registered in order):**
1. `admin_handler` - admin commands
2. `user_manage_handler` - account assignment/management
3. `user_payment_handler` - payment processing
4. `countries_to_price_admin_handler` - country pricing (deprecated/empty)
5. `reverif` - re-verification handler
6. `user_handler` - general user commands
7. `error_handler` - global error handler

**Middlewares:**
1. `MaintenanceMiddleware` - blocks non-admins when bot is in maintenance mode
2. `ThrottlingMiddleware` - rate limiting
3. `UserMiddleware` - injects `user_db` object into handler kwargs

**Admin IDs:** `[6544377406, 534354]`

### SumSub / Bybit KYC Integration

**SumSub Direct API:**
- Base URL: `https://direct-api.sumsub.com`
- Auth: HMAC-SHA256 request signing with secret key
- Endpoints used:
  - `/resources/applicantActions/`
  - `/resources/applicants/`
  - `/resources/auth/-/isLoggedInByAccessToken`
  - `/resources/checks/latest?type=IP_CHECK&applicantId=`
  - `/resources/inspections/`
  - `/resources/sdkIntegrations/levels/curWebsdkLink`
  - `/resources/sdkIntegrations/websdkInit`

**SumSub Bypass API (separate service):**
- Base URL: `https://api.sumsubio.com`
- Endpoints:
  - `/api/create_bypass_by_token`
  - `/api/check_seller/335173721`
  - `/api/report_seller`

**Custom SumSub CDN Domains (from memory):**
- `449-jk8.sumsubio.com/sumsub2`
- `468-x3.sumsubio.com/sumsub2`
- `469-8q.sumsubio.com/sumsub2`

**Bybit KYC API Endpoints:**
- `api2.bybitglobal.com/v3/private/kyc/get-kyc-provider`
- `api2.bybitglobal.com/v3/private/kyc/get-verification-sdk-info`
- `api2.bybitglobal.com/v3/private/kyc/kyc-info`
- `api2.bybitglobal.com/v3/private/kyc/submit-questionnaire`
- `api2.bybitglobal.com/x-api/v3/private/kyc/kyc-personal-info`
- `www.bybitglobal.com/x-api/user/public/risk/face/token`
- `www.bybitglobal.com/x-api/user/public/risk/verify`
- `www.bybitglobal.com/x-api/v1/kyc-provider/callback`
- `www.bybitglobal.com/x-api/v1/kyc/face_auth/status`
- `www.bybitglobal.com/x-api/v3/private/kyc/need-confirm-pi`
- `www.bybitglobal.com/x-api/segw/awar/v1/awarding`
- `www.bybitglobal.com/x-api/segw/awar/v1/awarding/search-together`

**KYC Providers (from enum):** SUMSUB, ONFIDO, JUMIO, AAI, DEFAULT

### Ishushka Licensing

**License server:** `https://api.ishushka.com`

**Endpoints:**
- `/license/challenge` (POST) - get challenge for HMAC signing
- `/license/check` (POST/GET) - validate license with signed challenge-response

**License mechanism:**
- HWID binding: SHA256 of MAC address + platform info, truncated to 32 chars
- Challenge-response: server issues challenge, client signs with HMAC-SHA256 using license key
- Token caching: auth tokens cached with expiry
- License file: `license.json` (local), real path from memory: `C:\Tools\Farm\KYCBot\license.json`
- Product identifier: `kyc_bot`

**Ishushka AI Chat:**
- Endpoint: `https://api.ishushka.com/request`
- Model: `gpt-5.1-chat`
- OpenAI-compatible API format (messages array, Bearer token auth)
- Used for AI-powered chat responses within the bot

**Russian UI strings for license errors:**
- "Лицензия бота истекла. Бот остановлен."
- "Сервер лицензий временно недоступен"
- "Все попытки проверки лицензии исчерпаны"
- "Лицензия истекает завтра"
- "Превышено максимальное количество устройств"
- "Другая копия программы уже запущена!"

### Database (PostgreSQL)

**Shared database between both bots.** Default name: `bybit`

**Key tables:**
- `bybit_account` - main account table (165 lines of columns, see account model)
- `email` - email accounts with IMAP credentials

**bybit_account columns (confirmed from SQLAlchemy model + migrations):**
- Identity: `database_id` (PK), `uid` (unique)
- Account: `group_name`, `name`, `note`, `email_address` (FK->email), `password`, `totp_secret`, `payment_password`
- KYC: `kyc_level`, `kyc_status` (enum), `last_provider` (enum), `kyc_provider_telegram_username`, `kyc_conflict`, `kyc_conflict_uid`, `need_questionnaire`, `facial_verification_required`, `first_name`, `last_name`, `doc_type`, `doc_number`, `country`
- Financial: `balance_usd`, `profit`, `ref_code`, `inviter_ref_code`
- Proxy: `proxy`, `proxy_error`, `proxy_county_restricted`, `proxy_payment_required`, `sumsub_proxy`, `onfido_proxy`, `aai_proxy`
- Device: `preferred_country_code`, `last_login_country_code`, `last_login_ip`, `chrome_major_version`, `os`, `screen_width`, `screen_height`, `last_tencent_request_time`
- Participation: `can_participate_demo_trading_tournament`, `can_participate_tokensplash`, `can_participate_airdrophunt`, `can_participate_launchpool`, `can_participate_puzzlehunt`, `ido_risk_control`
- Status: `registered`, `is_autoreg`, `email_verified`, `mobile_verified`, `totp_enabled`, `withdraw_whitelist_enabled`, `is_uta`, `reported_bad`
- Web3: `web3_cloud_wallets_created`, `web3_mnemonic_phrase`, `web3_ido_ton_address`, `twitter_auth_token`, `twitter_bind_code`
- Session: `cookies` (JSONB), `adspower_profile_id`, `default_withdraw_address_id`
- Timestamps: `registered_at`, `kyc_completed_at`

**KYC Status enum:** ALLOW, NOT_ALLOW, PENDING, SUCCESS, FAILED_AND_CAN_RETRY, FAILED_AND_CAN_NOT_RETRY, CERTIFICATION_DISABLED

**KYC Provider enum:** PROVIDER_SUMSUB, PROVIDER_ONFIDO, PROVIDER_JUMIO, PROVIDER_AAI, PROVIDER_DEFAULT

**Migration history (31 migrations, 2024-12-27 to 2026-02-27):**
Key milestones:
- `9f17e744cf77` (2024-12-27): Initial v3 schema, email + bybit_account tables
- `c9948ecb897a` (2024-12-27): Trigger
- `3fa64bff2385` (2024-12-30): Withdraw/deposit
- `2fbdf94a5d4a` (2025-01-18): Facial verification
- `8eca72c96c47` (2025-02-02): Finance account
- `571e2c4fdede` (2025-02-14): Twitter bind code
- `4840d1739004` (2025-03-17): Web3 tables
- `90a4dcea2216` (2025-03-28): Proxy payment required
- `b2e8a44aaad8` (2025-05-05): Device
- `556d201c3e5b` (2025-05-10): Award
- `bb6e74d0db9d` (2025-05-12): JSONB cookies
- `b239907a4191` (2025-08-30): Add profit column
- `4e591d5fac96` (2026-02-04): Email fields for Outlook
- `1c68db5b4dc0` (2026-02-27): API key table

---

## 7. Recovery Status

### KYC Bot v1 - WELL RECOVERED

| Component | Status | Notes |
|-----------|--------|-------|
| `config.py` | **FULLY RECOVERED** | Complete dataclass config with all real keys from memory dump |
| `start_bot.py` | **FULLY RECOVERED** | Working entry point with aiogram 3.x |
| `license.py` | **FULLY RECOVERED** | Complete LicenseClient with all methods from memory |
| `services/ishushka.py` | **FULLY RECOVERED** | Full IshushkaService with API integration |
| `services/sumsub.py` | **MOSTLY RECOVERED** | SumSubService class with real endpoints, signing logic |
| `services/bybit.py` | **MOSTLY RECOVERED** | BybitKycService with real endpoints, GetKycLink dataclass |
| `models/account.py` | **FULLY RECOVERED** | Complete SQLAlchemy model with all 50+ columns |
| `models/user.py`, `payment.py`, `country.py`, `country_price.py` | **PARTIALLY RECOVERED** | Model skeletons |
| `handlers/` (7 files) | **PARTIALLY RECOVERED** | Router registration known, handler logic is stubs |
| `middlewares/` (3 files) | **PARTIALLY RECOVERED** | Classes identified, logic is stubs |
| `dto/`, `keyboards/`, `blockchain/` | **PARTIALLY RECOVERED** | Structure known, implementation stubs |
| `db.py`, `crud.py`, `filters.py`, `states.py`, `permissions.py`, `cache.py`, `utils.py` | **PARTIALLY RECOVERED** | File existence confirmed, mostly stubs |

### Bybit Manager v3 - SKELETON ONLY

| Component | Status | Notes |
|-----------|--------|-------|
| `bybit/` package (10+ files) | **SKELETON** | Class names, constant names, method signatures recovered. No implementation bodies. All methods are `raise NotImplementedError` |
| `bybit_client/` package (20+ files) | **SKELETON** | Same pattern. Rich class hierarchy identified but all stubs |
| `anycaptcha/` package (10+ files) | **SKELETON** | Transport layer structure, captcha types identified |
| `better_proxy/` package | **SKELETON** | Proxy class identified |
| `app/` package (5 files) | **SKELETON** | FastAPI routers, schemas, dependencies -- all stubs |
| `bybit/web3/` | **SKELETON** | Eth swap/transfer/utils stubs |
| `bybit/models/web3/` (12 files) | **SKELETON** | Full Web3 model hierarchy identified |
| **Alembic migrations** (31 files) | **FULLY RECOVERED** | Complete migration chain with real SQL schemas |

### Traffic Analysis - CONFIRMED BY CAPTURE

| Finding | Confidence | Source |
|---------|------------|--------|
| Login flow (8 steps) | **HIGH** | Direct traffic capture, 137 login attempts observed |
| Captcha flow (CapMonster + reCAPTCHA) | **HIGH** | 75 createTask + 78 getTaskResult observed |
| 2FA/Risk flow (Google Authenticator) | **HIGH** | 59 risk/components + 54 risk/verify observed |
| Balance checking (3 endpoints) | **HIGH** | 772 balance requests total |
| Orderbook reading (9 symbols) | **HIGH** | 46 orderbook requests observed |
| Proxy infrastructure (3 providers) | **HIGH** | 112 unique proxy credentials captured |
| Email patterns (@icloud.com) | **HIGH** | 113 unique emails seen in login requests |
| AdsPower integration | **MEDIUM** | 265 unique GUIDs confirm mass browser profiles, but no AdsPower API calls captured (those go to localhost, not proxied) |
| Registration flow | **MEDIUM** | 84 permission_v2 calls confirm geo-checking, but no actual registration POSTs captured |
| Trading activity | **LOW** | Orderbook reads suggest trading, but no order placement endpoints captured |

---

## 8. Secrets & Credentials Found

### CapMonster API Key
- **Key:** `d57dd44f778b9cfc97211b5fa730da23`
- **Format:** 32-char hex string (MD5-like)
- **Used in:** All `api.capmonster.cloud` requests (`clientKey` field)

### ReCaptcha Site Key (Bybit Login)
- **Key:** `6LcJqb0pAAAAAEJCmRWqNFtGGMG7Gr20S-F1TTq6`
- **Type:** Google reCAPTCHA v2 (visible)
- **Domain:** `bybitglobal.com`

### JWT Token Structures

**secure-token (ES256 / ECDSA P-256):**
```json
{
  "alg": "ES256",
  "typ": "JWT"
}
{
  "user_id": 545524917,
  "b": 0,
  "p": 3,
  "ua": "",
  "gen_ts": 1773343685,
  "exp": 1773602885,
  "ns": "",
  "ext": {
    "Station-Type": "",
    "mct": "1770540727",
    "sid": "BYBIT"
  },
  "d": true,
  "sid": "BYBIT"
}
```
- Set as `secure-token` cookie after successful login+2FA
- Expiry: ~72 hours from issuance
- Contains Bybit user_id

**self-unbind-token (HS256 / HMAC-SHA256):**
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
{
  "MemberID": 545524917,
  "LoginStatus": 2,
  "TrigerTime": 1773343624,
  "SecurityItem": 0,
  "CurrentStep": 0,
  "kycFailedThreeTimes": 0,
  "VerifiedItems": "",
  "Logicattr": "",
  "Risktoken": "427654782999911995347030001#cbc26238d9",
  "WasPreSelfUnbindToken": false,
  "VierfyResultSceneCachekey": "",
  "RequiredStagy": "",
  "RiskTokenType": "",
  "NewCountryCode": "",
  "NewMobile": "",
  "NewEmail": "",
  "sub": "self_unbind",
  "exp": 1773347224,
  "nbf": 1773343624
}
```
- Set as `self-unbind-token` cookie
- Expiry: ~1 hour from issuance
- Contains the `Risktoken` needed for 2FA verification
- `LoginStatus: 2` = logged in

### Cookie Patterns

| Cookie | Purpose | Persistence |
|--------|---------|-------------|
| `_by_l_g_d` | Bybit GUID (matches `guid` header) | Session |
| `deviceId` | Device fingerprint UUID | Session |
| `sensorsdata2015jssdkcross` | Analytics/tracking | Session |
| `BYBIT_REG_REF_prod` | Registration referral data (JSON) | Session |
| `EO-Bot-Session` | EdgeOne CDN session | Set on first request |
| `EO-Bot-SessionId` | EdgeOne session ID | Set on first request |
| `EO-Bot-Token` | EdgeOne bot token (empty) | Set on first request |
| `isLogin` | Login flag | Set after successful login, 60-day expiry |
| `secure-token` | ES256 JWT (user auth) | Set after login+2FA |
| `self-unbind-token` | HS256 JWT (risk/2FA state) | Set after login, 1-hour expiry |
| `sajssdk_2015_cross_new_user` | SensorsData new user flag | Session |
| `_tt_enable_cookie` | TikTok pixel cookie | Session |

### Proxy Credentials

**iProyal:**
- Username: `0PVimdyoQpQVy999`
- Password: `PQ6fkQjWANlh4Lll`
- Host: `geo.iproyal.com:11250`

**DataImpulse:**
- Username prefix: `c97679e11624144264d2`
- Password: `951414902b8a9759`
- Host: `gw.dataimpulse.com`

**NodeMaven:**
- Username: `lazunegor_gmail_com` (operator email: lazunegor@gmail.com)
- Password: `jpcr50xmhd`
- Host: `gate.nodemaven.com`

**Unknown providers:**
- `QwYi7vnV:n3ZfF7LW` (various IPs)
- `xqQXz9GA:3nrCPNkN` (various IPs)

### GeeTest Captcha Key (from traffic)
- `gt`: `5c7686ca05a60b10d` (partial, from captcha order response)
- Challenge types: `geecaptcha,qqcaptcha,gee4captcha`

### Bybit User IDs (from JWT tokens, sample)
- 421814720
- 544567020
- 544995623
- 545139251
- 545524917
- 545735909
- 545747102

### KYC Bot Admin Telegram IDs
- `6544377406`
- `534354`

### Operator Email
- `lazunegor@gmail.com` (from NodeMaven proxy username)

---

## Dynamic Analysis Tools Used

| Script | Purpose | Result |
|--------|---------|--------|
| `03_nuitka_introspect.py` | Nuitka binary metadata extraction | Recovered module/class/constant names |
| `04_memory_dump.py` | Runtime memory dumping | 11 JSON dumps (strings, URLs, SQL queries) |
| `05_sitecustomize.py` | Import hook injection | Module loading trace |
| `07_analyze_dump.py` | Memory dump analysis | Extracted URLs, SQL, config keys |
| `08_traffic_capture.py` | Basic traffic capture setup | - |
| `09_start_sniff.py` | Sniffer launcher | - |
| `10_windivert_sniff.py` | WinDivert packet capture | Kernel-level packet interception |
| `11_smart_sniff.py` | Smart HTTP sniffer | Winsock hooking |
| `12_deploy_sniff.py` | Sniffer deployment | - |
| `14_mitm_adspower.py` | MITM proxy for AdsPower | Attempted but AdsPower detects MITM |
| `15_frida_sniff.py` | **Frida-based SSL interception** | **PRIMARY TOOL** - hooks Winsock + SSL_write/SSL_read in the process, captures plaintext HTTP before encryption. Produced 27,067 events in 5 minutes |
| `traffic/analyze_traffic.py` | Traffic analysis script | Generated api_analysis.json and api_analysis_summary.txt |
