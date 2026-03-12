# Bybit Manager v3 — Complete Database Schema

**Source**: 32 Alembic migration files (REAL Python source code)
**Database**: PostgreSQL 18, database "bybit"

## Tables (16 total)

### 1. email (PK: address)
| Column | Type | Nullable | Default |
|--------|------|----------|---------|
| address | String(254) | NO | PK |
| imap_address | String(254) | YES | |
| imap_password | String(128) | YES | |
| proxy_error | Boolean | NO | FALSE |
| last_login_failed | Boolean | NO | FALSE |
| proxy | String | YES | |
| client_id | String(100) | YES | OAuth2 (Outlook) |
| refresh_token | String(500) | YES | OAuth2 |

### 2. bybit_account (PK: database_id)
**Identity & Auth:**
- database_id (INT, PK), uid (INT, unique), email_address (FK→email.address)
- password (String(128)), totp_secret (String(16), unique), payment_password (String(30))

**Profile:** group_name (default "no_group"), name, note

**KYC:** kyc_level, kyc_status (ENUM), last_provider (ENUM), kyc_conflict, kyc_conflict_uid, facial_verification_required, need_questionnaire, first_name, last_name, doc_type, doc_number, country

**Financial:** balance_usd (Float), profit (Float)

**Web3:** web3_cloud_wallets_created, web3_mnemonic_phrase (unique), web3_ido_ton_address, twitter_auth_token, twitter_bind_code

**Proxy:** proxy, proxy_error, proxy_county_restricted, proxy_payment_required, sumsub_proxy, onfido_proxy, aai_proxy

**Device:** preferred_country_code, last_login_country_code, last_login_ip, chrome_major_version, os, screen_width, screen_height, last_tencent_request_time

**Status:** registered, is_autoreg, email_verified, mobile_verified, totp_enabled, withdraw_whitelist_enabled, is_uta, reported_bad

**Participation:** can_participate_demo_trading_tournament, can_participate_tokensplash, can_participate_airdrophunt, can_participate_launchpool, can_participate_puzzlehunt, ido_risk_control

**Other:** adspower_profile_id, default_withdraw_address_id, cookies (JSONB), ref_code, inviter_ref_code, registered_at, kyc_completed_at, kyc_provider_telegram_username

### 3. finance_account (PK: uid + type)
| Column | Type |
|--------|------|
| uid | INT (FK→bybit_account.uid) |
| type | ENUM financeaccounttype |
| balance | Float |

### 4. api_key (PK: bybit_id)
| Column | Type |
|--------|------|
| uid | INT (FK→bybit_account.uid) |
| bybit_id | String (PK) |
| note, key, secret | String |
| ipv4_addresses | JSONB |
| read_only | Boolean |
| permissions | JSONB |
| created_at | DateTime |

### 5-6. deposit_history / withdraw_history (PK: id + uid)
Full transaction tracking with tx_id, coin_symbol, chain, address, amount, fee, status, confirmations, timestamps

### 7-8. deposit_address / withdraw_address
Crypto addresses per account per chain

### 9-12. Event tables: airdrophunt, tokensplash, ido, puzzlehunt
Campaign participation tracking with registration, spending, volume, rewards

### 13. award (PK: id + uid + spec_code)
Complex reward system: 7+ enums, lifecycle tracking, partial redemptions

### 14-16. Web3 tables: web3_wallet → web3_chain → web3_token
Multi-wallet, multi-chain portfolio tracking with USD valuation

## Enums (15)
- **kycstatus**: ALLOW, NOT_ALLOW, PENDING, SUCCESS, FAILED_AND_CAN_RETRY, FAILED_AND_CAN_NOT_RETRY, CERTIFICATION_DISABLED
- **kycprovider**: PROVIDER_SUMSUB, PROVIDER_ONFIDO, PROVIDER_JUMIO, PROVIDER_AAI, PROVIDER_DEFAULT
- **financeaccounttype**: 18 types (FUND, UNIFIED, CONTRACT, SPOT, MARGIN_STAKE, etc.)
- **numberwallettype**: CLOUD, PRIVATE_KEY, MNEMONIC_PHRASE
- **web3chaintype**: ALL, EVM, SUI, SOLANA, BTC, STX, APT, TON, TRON
- **awardstatus**: 5 values
- **awardusingstatus**: 7 values
- **awardtype**: 20+ values
- **awardamountunit**: USD, COIN
- **businessno**: 8 values
- **autoclaimtype**: UNKNOWN, YES, NO
- **productline**: 17 values
- **subproductline**: 37+ values

## Triggers
1. `trg_delete_email` — AFTER DELETE on bybit_account → deletes email
2. `trigger_delete_zero_balance` — BEFORE INSERT/UPDATE on web3_token → removes zero-balance tokens

## Entity Relationships
```
bybit_account (root, uid = core FK)
├── email (1:1, cascade delete)
├── finance_account (1:N, by account type)
├── api_key (1:N, multiple API keys)
├── deposit_history (1:N)
├── withdraw_history (1:N)
├── deposit_address (1:N)
├── withdraw_address (1:N)
├── airdrophunt (1:N)
├── tokensplash (1:N)
├── ido (1:N)
├── puzzlehunt (1:N)
├── award (1:N)
└── web3_wallet (1:N)
    ├── web3_chain (1:N)
    └── web3_token (N:M)
```
