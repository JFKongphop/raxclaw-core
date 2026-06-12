# RAXC — Autonomous Exploit Intelligence Core

> **AI-powered DeFi smart contract vulnerability scanner using RAG (Retrieval-Augmented Generation) with on-chain audit proof on Arbitrum Sepolia.**

[![Rust](https://img.shields.io/badge/backend-Rust-orange)](./backend)
[![Stylus](https://img.shields.io/badge/contracts-Rust%20Stylus-orange)](./stylus)

---

## Architecture

```mermaid
graph TD
    subgraph Client
        CLI["ws-client.rs"] --> WS["ws-server.rs"]
        Frontend["Any WebSocket client"] --> WS
    end

    subgraph "Backend (Rust)"
        WS --> AgentCore{AgentCore}
        AgentCore --> Tools["7 Analysis Tools"]
        AgentCore --> OpenAI["OpenAI GPT-4o-mini"]
        AgentCore --> Qdrant["Qdrant Vector DB"]
        AgentCore --> Stylus["Stylus Contracts"]
    end

    subgraph "On-Chain (Arbitrum Sepolia)"
        Stylus --> AgentMemory["AgentMemory"]
        Stylus --> AuditReport["AuditReport"]
    end
```

---

## How It Works — 13-Phase Pipeline

```
Phase 0  → Load on-chain memory (past audits from Arbitrum Sepolia)
Phase 1  → Dispatch 7 analysis tools in parallel
Phase 2  → Normalize tool signals (filter noise, enforce precision)
Phase 3  → Multi-agent reasoning (convert signals to agent votes)
Phase 4  → Consensus engine (weighted voting aggregation)
Phase 5  → Risk intelligence scoring (severity × confidence × agreement)
Phase 6  → Attack simulation (VM-like execution path generation)
Phase 7  → Graph construction (deterministic attack DAG)
Phase 8  → Consistency verification (4-way gatekeeper)
Phase 9  → Final decision (SINGLE AUTHORITY — no override)
Phase 10 → Attestation proof (cryptographic replay ID + trace hash)
Phase 11 → LLM explanation (GPT-4o-mini, constrained to 2-3 sentences)
Phase 12 → Markdown report + on-chain storage (Stylus)
```

### 7 Analysis Tools

| Tool | Detects | Trust Weight |
|---|---|---|
| `RaxcAnalyzer` | RAG-based exploit matching (Qdrant + OpenAI) | 1.0x |
| `PatternDetectorTool` | Reentrancy, delegatecall, tx.origin, overflow | 0.8x |
| `FlashLoanTool` | Flash loan callbacks, spot price oracles | 0.7x |
| `AccessControlTool` | Missing `onlyOwner`, unprotected initializers | 0.7x |
| `ReflectionTool` | LLM self-critique (CONFIRMED/REDUCED/REJECTED) | 0.7x |
| `MemoryTool` | Past audit recall from on-chain storage | 0.7x |
| `GasAnalyzerTool` | Gas optimizations (non-security) | 0.2x |

---

## On-Chain Contracts (Stylus / Rust)

### `AgentMemory` — Long-Context Memory

Stores JSON audit summaries on Arbitrum Sepolia for persistent agent memory.

```solidity
function pushMemory(uint256 tokenId, bytes summaryJson, string description)
function getMemoryData(uint256 tokenId, uint256 index) → bytes
function memoryCount(uint256 tokenId) → uint256
```

### `AuditReport` — Immutable Audit Trail

Stores full markdown security reports on-chain with cryptographic hashing.

```solidity
function createAudit(string contractName) → uint256 taskId
function finalizeAudit(uint256 taskId, uint8 riskLevel, uint64 confidence,
                        string vulnType, bytes reportMarkdown)
function getReport(uint256 taskId) → bytes
function recordCount() → uint256
```

Risk levels: `0=None | 1=Low | 2=Medium | 3=High | 4=Critical`

---

## Project Structure

```
raxclaw-arbitrum/
├── stylus/                    # Stylus contracts (Rust → WASM → Arbitrum)
│   ├── src/
│   │   ├── agent_memory.rs   # AgentMemory contract
│   │   └── audit_report.rs   # AuditReport contract
│   └── Cargo.toml
│
├── backend/                   # Rust backend (original)
│   ├── src/
│   │   ├── lib.rs             # Embedding + RAG pipeline
│   │   ├── agent.rs           # AgentCore, 13 engines, ReportEngine
│   │   ├── tools.rs           # 7 analysis tools
│   │   ├── openai_client.rs   # GPT-4o-mini interface
│   │   ├── qdrant_storage.rs  # Qdrant HNSW vector search
│   │   ├── stylus_client.rs   # Alloy-based Stylus contract client
│   │   └── bin/
│   │       ├── ws_server.rs   # WebSocket server (Axum)
│   │       └── ws_client.rs   # WebSocket client (tokio-tungstenite)
│   ├── examples/
│   │   └── agent_example.rs   # Standalone CLI analysis
│   └── Cargo.toml
│ 
└── reports/                   # Generated audit reports (.md)
```

---

## Quick Start

```bash
cd backend
# Fill in .env with your keys
cargo run --release --example agent_example
```

### WebSocket API

```bash
# Rust server
cargo run --release --bin ws_server
cargo run --release --bin ws_client  # Separate terminal

# Connect with any WebSocket client
wscat -c ws://localhost:3001/ws
> {"contract": "pragma solidity ^0.8.0; contract Foo { ... }"}
```

### Response Format (Server → Client)

| Message Type | Description |
|---|---|
| `banner` | Welcome/header box |
| `info` | Phase progress (connection, tools, decisions) |
| `progress` | Real-time detail lines (tree format) |
| `explanation` | LLM-generated vulnerability explanation |
| `complete` | Final summary with on-chain tx hashes |
| `error` | Error message |

---

## Technology Stack

| Layer | Rust |
|---|---|
| **Runtime** | [Tokio](https://tokio.rs) |
| **WebSocket** | [Axum](https://docs.rs/axum) |
| **LLM** | OpenAI GPT-4o-mini |
| **Embeddings** | text-embedding-3-small (1536d) |
| **Vector DB** | Qdrant Cloud (HNSW) |
| **Blockchain** | Arbitrum Sepolia |
| **On-chain client** | [Alloy](https://alloy.rs) |
| **Container** | Single binary (~15MB) |

---

## Secrets Management

`.env` is git-ignored. `.env.example` is safe to commit.

```
OPENAI_API_KEY        # https://platform.openai.com/api-keys
QDRANT_ENDPOINT       # https://cloud.qdrant.io
QDRANT_API_KEY        # Qdrant Cloud API key
ARBITRUM_SEPOLIA      # RPC endpoint
PRIVATE_KEY           # Wallet with Sepolia ETH
AGENT_MEMORY          # Deployed contract address
AUDIT_REPORT          # Deployed contract address
```

---

## License

MIT © RAXC Team
