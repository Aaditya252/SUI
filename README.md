# FluidBLCX — Sovereign Web3 Execution Architecture

<div align="center">

[![Sui Devnet](https://img.shields.io/badge/Sui-Devnet-38bdf8?style=flat-square)](https://suiscan.xyz/devnet/object/0xe4d805346677389d3d36930b77117a0e620cb9d5580fbfd85cd25430aff6d72a)
[![Node](https://img.shields.io/badge/Node.js-18%2B-339933?style=flat-square&logo=nodedotjs)](https://nodejs.org)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-64748b?style=flat-square)](LICENSE)

**Zero-trust cryptography · AI-swarm defense · PTB compilation · DeepBook v3 HFT · Walrus decentralized storage**

</div>

---

## Overview

FluidBLCX is a full-stack Web3 execution platform built on the **Sui blockchain**. It combines a real-time AI security engine, on-chain Move smart contracts, an interactive PTB compiler with 3D block visualization, DeepBook v3 high-frequency trading interfaces, and a client-side encrypted Walrus vault — all served through a dark cyber-industrial web dashboard.

**On-chain (Sui Devnet):** [`0xe4d805346677389d3d36930b77117a0e620cb9d5580fbfd85cd25430aff6d72a`](https://suiscan.xyz/devnet/object/0xe4d805346677389d3d36930b77117a0e620cb9d5580fbfd85cd25430aff6d72a)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Web Browser (port 5501 / 3000)               │
│  ┌──────────┐  ┌──────────┐  ┌───────┐  ┌────────┐  ┌──────────┐  │
│  │ Terminal  │  │ Compiler  │  │Wallet │  │Security│  │ Walrus   │  │
│  │startingpar│  │compiler.h│  │w1.html│  │dashbrd │  │vault.html│  │
│  │t.html     │  │tml       │  │       │  │.html   │  │          │  │
│  └─────┬─────┘  └─────┬────┘  └───┬───┘  └───┬────┘  └────┬─────┘  │
│        │              │          │          │           │         │
│        └──────────────┴──────────┴──────────┴───────────┘         │
│                              │ REST / SSE                          │
└──────────────────────────────┼──────────────────────────────────────┘
                               │
┌──────────────────────────────┼──────────────────────────────────────┐
│            Node.js Express Server (port 3000) — server.js          │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Zero-Trust Middleware (Ed25519 signing · HMAC · Token Auth) │  │
│  └──────────────────────────────────────────────────────────────┘  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────────┐ │
│  │ /api/zt/*│ │ /api/sui*│ │/api/prices│ │ /api/compile* / SSE  │ │
│  │Crypto    │ │Testnet   │ │Binance→  │ │ Move Compiler +      │ │
│  │Endpoints │ │RPC Proxy │ │CG→Static │ │ 3D Block Visualizer  │ │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────────────┘ │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────────┐ │
│  │ /api/swap│ │ /api/ass │ │ /walrus- │ │ /security-dashboard  │ │
│  │ ▾Quote   │ │ istant   │ │ vault    │ │   (proxied to AI     │ │
│  │ ▾Execute │ │ Gemini AI│ │ (static)  │ │    Engine port 5001) │ │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────────────┘ │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ HMAC-secured proxy
┌──────────────────────────┴──────────────────────────────────────────┐
│            Python AI Security Engine (port 5001) — app.py          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐ │
│  │Pattern       │  │ ML Anomaly   │  │ Rate Limiter             │ │
│  │ Matcher      │  │Detector      │  │ (100 req/min/IP,         │ │
│  │(SQLi/XSS/    │  │(Isolation    │  │  auto-block 5 min)       │ │
│  │ CMD/Path)    │  │ Forest)      │  │                          │ │
│  └──────────────┘  └──────────────┘  └──────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────────┐
│                  Sui Blockchain (Devnet)                            │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ fluidblcx_core @ 0xe4d805346677...aff6d72a                   │  │
│  │ EncryptedVault · Position · SealAccess                        │  │
│  │ create_vault · verify_proof · grant_seal_access ·             │  │
│  │ assert_margin_risk · verify_zklogin_spending_policy           │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Features

### 🛡 Zero-Trust Cryptography
- **Ed25519 Response Signing** — Every JSON response carries `X-ZT-Signature` and `X-ZT-PublicKey` headers; clients can mathematically verify server identity
- **HMAC Inter-Service Trust** — Server→AI Engine requests authenticated with HMAC-SHA256 shared secret
- **Time-Bound Token Auth** — Short-lived (5 min) zero-trust tokens with Ed25519 client signature verification
- **Endpoints:** `GET /api/zt/status`, `GET /api/zt/public-key`, `POST /api/zt/request-token`, `POST /api/zt/verify`

### 🤖 AI Security Shield
- **Pattern-based detection** — 42 regex rules covering SQL injection, XSS, command injection, path traversal
- **ML Anomaly Detection** — scikit-learn Isolation Forest (100 estimators, 5% contamination) trained on 7 request features
- **Rate Limiting** — 100 req/min per IP, auto-block for 5 min on threshold breach
- **Adaptive Learning** — Model retrains with noise-augmented malicious samples; persists to `model_data.json`
- **Python Flask service** on port 5001, proxied through Node.js with HMAC authentication

### ☠ Poison AI Matrix
- Autonomous adversarial noise injection to neutralize hostile ML scanners
- Fake execution endpoints (honeypot traps) for attacker fingerprinting
- Real-time poison stream with noise density, entropy level, honeypot node monitoring
- **Page:** `ui/poison_ai.html`

### 🤖 Trojan AI Defense Bots
- 7 autonomous AI defense bot agents (Archangel, Spectre, Cerberus, Pulse, Mirage, Vigil, Xenith)
- Swarm consensus (≥3 bots confirm → auto-containment)
- Real-time activity log, threat targeting, and countermeasure deployment
- **Page:** `ui/trojan_bots.html`

### ⚙ Sui Move PTB Compiler + 3D Block Visualizer
- Real Sui Move CLI compilation (`sui move build`) with local diagnostic fallback
- SSE streaming compile output via `/api/compile-stream`
- 3D Three.js blockchain block graph with orbit controls and hover inspection
- Template selector: Atomic Asset Router, DeepBook Liquidity Node, Walrus Encrypted Vault Guard
- **Page:** `ui/compiler.html`

### 📊 DeepBook v3 HFT Suite
- Order book UI with institutional liquidity and matching engine interface
- CSV wallet upload login with sub-wallet allocation matrix
- Portfolio risk terminal with batch PTB mode
- **Pages:** `Deepbookv3ui/Deepbookv3.html`, `deepbookv3login.html`, `deepbookv3portfolio.html`

### 🗄 Walrus Vault (E2E Encrypted)
- **Client-side encryption** via Web Crypto API — PBKDF2 (600k iterations) → AES-256-GCM
- Wrong passphrase yields garbage — zero-knowledge design
- Upload pipeline: Register → Encode → Certify → Active
- Blob explorer with status badges, expiry management, Seal Access Control
- Storage pricing calculator ($0.023/GB/mo)
- **Page:** `ui/walrus_vault.html`

### 🔄 Live Price Feeds
- Fetches from **Binance API** (primary), falls back to **CoinGecko**, then static fallback ($0.72 SUI)
- 15-second cache for `/api/prices`
- 1-hour candlestick chart rendered on canvas in the right sidebar
- Price tickers for: SUI, BTC, ETH, SOL, BNB, USDT, USDC

### 🔗 Sui Testnet RPC Proxy
- `GET /api/sui/balances` — Fetch all token balances for an address
- `POST /api/sui/faucet` — Request test SUI from faucet
- `POST /api/sui/rpc` — Whitelisted RPC methods (getBalance, getOwnedObjects, getTransactionBlock, etc.)
- `GET /api/sui/network` — Network info (RPC, faucet, explorer URLs)

### 🔄 Swap Engine
- `POST /api/swap/quote` — Price quotes with slippage, price impact, fee estimation
- `POST /api/swap/execute` — Simulated execution with mock tx hashes
- `POST /api/swap/build-tx` — Real Sui PTB transaction building via `@mysten/sui`
- `POST /api/swap/cancel-all` — Cancel all open orders for an address

### 🤖 AI Assistant (Chatbot)
- Natural language interface for blockchain operations (route, compile, wallet, liquidity, vault, visualizer)
- **Gemini AI** (`gemini-1.5-flash`) when `GEMINI_API_KEY` is configured; local intent-based fallback
- Draggable chat widget on the starting page

---

## Pages Reference

| Route | Page | Description |
|---|---|---|
| `/` | `index.html` | Landing hub with particle network and app grid |
| `/startingpart.html` | `startingpart.html` | Main shell — wallet connect, AI agent, typewriter hero |
| `/compiler.html` | `compiler.html` | Sui Move PTB compiler + 3D block visualizer |
| `/security_dashboard.html` | `security_dashboard.html` | AI Security Shield with ZT crypto status |
| `/walrus_vault.html` | `walrus_vault.html` | E2E-encrypted Walrus blob vault |
| `/poison_ai.html` | `poison_ai.html` | Poison AI Obfuscation Matrix |
| `/trojan_bots.html` | `trojan_bots.html` | Trojan AI Defense Bot Swarm |
| `/wallet1.html` | `wallet1.html` | Full wallet dashboard (portfolio, swap, bridge, vaults, history) |
| `/loginpage.html` | `loginpage.html` | Verification gateway with 3D crystal viz |
| `/tradewindow.html` | `tradewindow.html` | Quantum trading terminal |
| `/Deepbookv3ui/Deepbookv3.html` | `Deepbookv3.html` | DeepBook v3 order book |
| `/Deepbookv3ui/deepbookv3login.html` | `deepbookv3login.html` | DeepBook v3 login |
| `/Deepbookv3ui/deepbookv3portfolio.html` | `deepbookv3portfolio.html` | DeepBook v3 portfolio risk terminal |

---

## Installation

### Prerequisites

- **Node.js** 18+ and **npm**
- **Python** 3.10+ and **pip**
- **Git**

### 1. Clone & Install

```bash
git clone https://github.com/Aaditya252/SUI.git
cd SUI

# Node.js dependencies
npm install

# Python dependencies (AI Engine)
pip install -r AIEngine/requirements.txt
```

### 2. Configure (Optional)

Create a `.env` file in the project root:

```env
GEMINI_API_KEY=your_gemini_key_here
GEMINI_MODEL=gemini-1.5-flash
ZT_HMAC_SECRET=your_64_byte_hmac_secret_hex_encoded_here
AI_ENGINE_PORT=5001
```

### 3. Start Services

**Option A: Run both services separately**

```bash
# Terminal 1: AI Security Engine
python AIEngine/app.py

# Terminal 2: Web Server (wait for AI Engine to start)
npm start
```

**Option B: Run with Live Server (frontend only, no API access)**

```bash
# VS Code: right-click ui/index.html → Open with Live Server
# Port defaults to 5501; frontend pages work but API calls fail without Node.js
```

### 4. Open

- **Web interface:** [http://localhost:3000](http://localhost:3000)
- **AI Engine health:** [http://localhost:5001/api/health](http://localhost:5001/api/health)
- **Zero-Trust crypto status:** [http://localhost:3000/api/zt/status](http://localhost:3000/api/zt/status)

---

## Deploy Move Contracts

```bash
# Switch to devnet (already deployed at 0xe4d8...6d72a)
sui client switch --env devnet

# Build
sui move build --path move

# Deploy
sui client publish move --gas-budget 50000000

# To deploy on testnet (if not rate-limited):
sui client switch --env testnet
sui client publish move --gas-budget 50000000
```

---

## Smart Contract: `fluidblcx_core`

| Function | Description |
|---|---|
| `create_vault` | Create a new `EncryptedVault` with Merkle root |
| `register_blob_proof` | Register a blob's Merkle proof |
| `verify_blob_integrity` | Verify blob integrity via challenge |
| `grant_seal_access` | Grant Seal decryption access (grantee, blob_id, expiry) |
| `check_seal_access` | Check if access policy is valid |
| `revoke_seal_access` | Revoke a Seal access policy |
| `verify_proof` | Zero-trust cryptographic proof verification |
| `verify_session` | Zero-trust session proof verification |
| `assert_margin_risk` | Assert position margin ratio ≥ minimum |
| `verify_zklogin_spending_policy` | Verify zkLogin proof + daily cap |

**Package:** `0xe4d805346677389d3d36930b77117a0e620cb9d5580fbfd85cd25430aff6d72a`

---

## Project Structure

```
D:\SUI\
├── server.js                    Express server (port 3000)
├── package.json                 Node.js dependencies & scripts
├── .env                         Environment variables (gitignored)
├── .gitignore
│
├── AIEngine/                    Python AI Security Shield
│   ├── app.py                   Flask server (port 5001)
│   ├── pattern_matcher.py       Regex threat detection
│   ├── rate_limiter.py          IP rate limiter
│   ├── threat_detector.py       Isolation Forest ML anomaly detection
│   ├── requirements.txt         Python dependencies
│   ├── model_data.json          Persisted ML training data
│   └── threats.jsonl            Threat event log
│
├── move/                        Sui Move smart contract
│   ├── Move.toml                Package manifest
│   ├── Move.lock                Dependency lock
│   └── sources/
│       └── fluidblcx_core.move  Core module (vault, seal, margin, zkLogin)
│
├── corecontracts/               PTB compiler engine (JavaScript)
│   ├── ptbBuilder.js            Graph builder + Move code generator
│   ├── core/
│   │   ├── ptbBuilder.js        Duplicate PTB builder
│   │   ├── intentParser.js      Natural language parser (stub)
│   │   └── test_parser.js       Test suite (6 scenarios)
│   └── contracts/
│       └── guardrails.move      Price/spread/margin guardrails
│
├── ui/                          Frontend web pages
│   ├── index.html               Landing hub
│   ├── startingpart.html        Main terminal shell
│   ├── startingpage.html        Redirect alias
│   ├── compiler.html            PTB compiler + 3D block visualizer
│   ├── security_dashboard.html  AI Security Shield
│   ├── walrus_vault.html        E2E-encrypted Walrus vault
│   ├── poison_ai.html           Poison AI Matrix
│   ├── trojan_bots.html         Trojan AI Defense Bots
│   ├── wallet1.html             Full wallet dashboard
│   ├── loginpage.html           Verification gateway
│   ├── tradewindow.html         Trading terminal
│   ├── style.css                Global design system (992 lines)
│   ├── app.js                   PTB app controller
│   ├── requiredimage/           Wallet provider logos
│   └── Deepbookv3ui/            DeepBook v3 trading suite
│       ├── Deepbookv3.html      Order book UI
│       ├── deepbookv3login.html Login portal
│       ├── deepbookv3portfolio.html Portfolio risk terminal
│       └── portfolio.csv        Sample portfolio data
│
├── tools/sui/                   Sui CLI binaries (Windows)
│   ├── sui.exe, sui-node.exe, sui-faucet.exe, ...
│   └── move-analyzer.exe
│
├── Frontend_raw/                Raw HTML prototypes
├── bridge/                      Cross-chain bridge (placeholder)
├── Wallets/                     Wallet integration (placeholder)
└── Pub.devnet.toml              Move publication metadata
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Blockchain** | Sui (Devnet) |
| **Smart Contracts** | Sui Move (Edition 2024) |
| **Backend** | Node.js / Express 5 |
| **AI Engine** | Python / Flask / scikit-learn |
| **Frontend** | Vanilla HTML+CSS+JS, Three.js (3D viz) |
| **Crypto** | Web Crypto API (Ed25519, PBKDF2, AES-256-GCM), Node crypto |
| **Wallet** | `@mysten/sui` SDK, Sui Wallet / MetaMask / Coinbase / Trust / Binance |
| **Prices** | Binance API → CoinGecko → static fallback |
| **Server-sent Events** | `/api/compile-stream` SSE endpoint |
| **Package Manager** | npm / pip |

---

## API Endpoints Summary

### Zero-Trust Cryptography
| Method | Path | Description |
|---|---|---|
| GET | `/api/zt/status` | All ZT layer health |
| GET | `/api/zt/public-key` | Ed25519 public key (PEM + fingerprint) |
| POST | `/api/zt/request-token` | Issue time-bound token |
| POST | `/api/zt/verify` | Verify client Ed25519 signature |

### Move Compiler
| Method | Path | Description |
|---|---|---|
| POST | `/api/compile` | Compile Sui Move code |
| POST | `/api/compile-stream` | SSE streaming compile |
| GET | `/api/compiler-status` | Sui CLI availability check |

### Prices & Swap
| Method | Path | Description |
|---|---|---|
| GET | `/api/prices` | Live prices (Binance→CoinGecko→static) |
| POST | `/api/swap/quote` | Swap price quote |
| POST | `/api/swap/execute` | Simulated swap execution |
| POST | `/api/swap/build-tx` | Sui PTB transaction building |
| POST | `/api/swap/cancel-all` | Cancel all open orders |

### AI Security (proxied to AI Engine)
| Method | Path | Description |
|---|---|---|
| POST | `/api/security/analyze` | Threat analysis |
| GET | `/api/security/status` | Security layer health |
| GET | `/api/security/threats/recent` | Last 50 threats |
| GET | `/api/security/blocked-ips` | Blocked IPs list |
| GET | `/api/security/zt-status` | HMAC inter-service status |

### AI Assistant
| Method | Path | Description |
|---|---|---|
| POST | `/api/assistant` | Chat with AI (Gemini or local) |
| GET | `/api/assistant-status` | Assistant backend status |

### Sui Testnet
| Method | Path | Description |
|---|---|---|
| GET | `/api/sui/balances` | Token balances for address |
| POST | `/api/sui/faucet` | Request test SUI |
| POST | `/api/sui/rpc` | Generic RPC proxy |
| GET | `/api/sui/network` | Network info |
| GET | `/api/chain-status` | Sui testnet reachability |

---

## License

MIT
