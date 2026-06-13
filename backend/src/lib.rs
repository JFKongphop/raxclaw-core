/*!
RAXC — RAG-based smart contract vulnerability analysis with 0G Storage + 0G Compute.

Simplified architecture matching full_rag_demo.rs:
1. Pre-load exploits at startup (OgStorageClient does this)
2. Embed contract code (OpenAI or hash-based demo)
3. Query in-memory exploits (fast cosine similarity)
4. Build RAG context and prompt
5. Send to 0G Compute for LLM analysis
*/

use anyhow::{Context, Result};
use reqwest::Client;
use std::path::Path;

mod agent;
mod openai_client;
pub mod qdrant_storage;
pub mod stylus_client;
pub mod tools;
pub use agent::{
  AgentCore,
  AgentVote,
  AnalysisResult,
  // Attack Simulation + Deterministic Exploit Execution Engine
  AttackSimulation,
  AttackSimulationEngine,
  AttackSuccessProbability,
  AttackerCapabilities,
  AttackerModel,
  AttackerPersona,
  ConfidenceEngine,
  ConsensusEngine,
  DecisionResult,
  DeterministicReplay,
  ExecutionStep,
  ExploitGraph,
  ExploitVerdict,
  ExploitabilityEstimator,
  // Intelligence + Scoring Layer
  IntelligenceReport,
  MemoryLayer,
  RaxcAnalyzer,
  RaxcAnalyzerRemote,
  ReportEngine,
  RiskScoringEngine,
  SeverityLock,
  SeverityProof,
  // Production Hardening
  SignalNormalizer,
  StateProof,
  StateTransition,
  Tool,
  // Multi-Agent Framework
  ToolRegistry,
  ToolSignal,
  ToolSignalReference,
  ToolTrustWeighting,
};
pub use openai_client::OpenAiClient;
pub use qdrant_storage::{QdrantExploitResult, QdrantStorageClient};
pub use stylus_client::StylusClient;
pub use tools::{
  AccessControlTool, FlashLoanTool, GasAnalyzerTool, MemoryTool, PatternDetectorTool,
  ReflectionTool,
};

// ─── Constants ────────────────────────────────────────────────────────────────

pub const TOP_K: usize = 5;
pub const SIM_THRESHOLD: f64 = 0.01; // Lowered to always trigger analysis even with poor similarity

// ─── Environment setup ────────────────────────────────────────────────────────

/// Load `.env` from the project root
pub fn load_env() {
  dotenv::dotenv().ok();
  let root = Path::new(env!("CARGO_MANIFEST_DIR"));
  dotenv::from_path(root.join(".env")).ok();
}

/// Build OpenAI client (LLM reasoning + embeddings — active/default path).
pub fn build_openai_client() -> Result<OpenAiClient> {
  OpenAiClient::from_env()
}

// ─── Embedding (OpenAI text-embedding-3-small) ─────────────────────────────────

#[derive(serde::Serialize)]
struct EmbedRequest {
  input: String,
  model: String,
}

#[derive(serde::Deserialize)]
struct EmbedResponse {
  data: Vec<EmbedData>,
}

#[derive(serde::Deserialize)]
struct EmbedData {
  embedding: Vec<f64>,
}

/// Embed text — always uses OpenAI text-embedding-3-small (1536 dims).
pub async fn embed(client: &Client, text: &str) -> Result<Vec<f64>> {
  embed_openai(client, text).await
}

/// OpenAI API embedding (fallback when 0G Compute is unavailable)
async fn embed_openai(client: &Client, text: &str) -> Result<Vec<f64>> {
  let api_key = std::env::var("OPENAI_API_KEY")
    .context("OPENAI_API_KEY not set — required for USE_OPENAI_EMBEDDING=true")?;

  let req = EmbedRequest {
    input: text.chars().take(8000).collect(),
    model: "text-embedding-3-small".to_string(),
  };

  let resp = client
    .post("https://api.openai.com/v1/embeddings")
    .bearer_auth(api_key)
    .json(&req)
    .send()
    .await
    .context("OpenAI API request failed")?;

  if !resp.status().is_success() {
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    anyhow::bail!("OpenAI API error {}: {}", status, body);
  }

  let embed_resp: EmbedResponse = resp.json().await?;
  Ok(
    embed_resp
      .data
      .into_iter()
      .next()
      .map(|d| d.embedding)
      .unwrap_or_default(),
  )
}

// ─── Analysis workflow ────────────────────────────────────────────────────────

/// Analyze contract using Qdrant vector database (no 0G Storage dependency).
/// Identical to analyze_remote() but queries Qdrant instead of api_0g_storage.
pub async fn analyze_qdrant(
  http: &Client,
  storage: &qdrant_storage::QdrantStorageClient,
  compute: &OpenAiClient,
  contract: &str,
) -> Result<String> {
  println!("[RaxcAnalyzer]   Embedding contract code...");
  let query_vec = embed(http, contract).await?;

  println!("[RaxcAnalyzer]   Querying Qdrant (defi_cases + defi_protocols)...");
  let top_matches = storage.query(&query_vec, TOP_K).await?;

  let top_score = top_matches.first().map(|e| e.score).unwrap_or(0.0);
  println!("[RaxcAnalyzer]   Top similarity: {:.3}", top_score);

  if top_score < SIM_THRESHOLD {
    println!(
      "[!] Similarity {:.3} below threshold {} — skipping analysis, contract appears safe.",
      top_score, SIM_THRESHOLD
    );
    return Ok(format!(
      "✅ NO EXPLOITABLE VULNERABILITY FOUND\nTop similarity score ({:.3}) is below minimum threshold ({}).",
      top_score, SIM_THRESHOLD
    ));
  }

  println!("[RaxcAnalyzer]   Building RAG context...");
  let context = build_rag_context_qdrant(&top_matches);

  println!("[LLM]            Sending for analysis...");
  let prompt = format!(
    r#"You are a smart contract security expert specializing in DeFi vulnerabilities.

Analyze the following Solidity contract for potential vulnerabilities.
Use the reference cases below as context — retrieved from DeFiHackLabs (real protocol attacks) and DeFiVulnLabs (educational vulnerability patterns).

## Similar Reference Cases (DeFiHackLabs real exploits + DeFiVulnLabs educational patterns):
{context}

## Contract to Analyze:
{contract}

## Critical instructions before answering:
1. The exploit cases show HOW past vulnerabilities worked. Your job is to determine if THIS contract has the same UNMITIGATED flaw — not just a similar structure.
2. Actively check for these mitigations. If any are correctly implemented, they PREVENT exploitation:
   - ReentrancyGuard modifier or Checks-Effects-Interactions (state update before external call)
   - TWAP / time-weighted average price oracle (resistant to single-block manipulation)
   - onlyOwner / role-based access control on sensitive functions
   - Solidity 0.8+ built-in overflow protection or SafeMath
3. Structural similarity to an exploit is NOT sufficient. The contract must have the same exploitable flaw WITH NO mitigation present.
4. Include a CONFIDENCE score (0-100) reflecting how certain you are a real exploitable vulnerability exists with no mitigation.
5. For EXPLOIT_TX in your report: only cite the exact Attack Tx URLs present in the reference cases above. If a reference shows "N/A" or no real tx, write N/A. Do NOT fabricate or invent transaction hashes.

## Provide a structured security report with the following sections:

**Vulnerability Found:** Yes / No
**Risk Level:** Critical / High / Medium / Low / None
**Vulnerability Type:** (e.g. Reentrancy, Flash Loan, Price Manipulation, Access Control, etc.)
**Confidence:** (0-100 — certainty that a real exploitable vulnerability exists with no mitigation present)
**Similar Exploit Reference:** (which exploit case above is most relevant and why)
**Explanation:** (describe the exact vulnerability and how an attacker could exploit it step-by-step)
**Recommendation:**
IMPORTANT: Provide AT LEAST 3-4 detailed cases (A, B, C, D, ...). Each case must be a complete, standalone solution.
Separate each distinct issue or improvement into its own labeled case (A, B, C, D, ...). For each case:
- State the problem in one sentence.
- Show ONLY the one affected function rewritten in full — do NOT include contract declaration, constructor, imports, structs, or any other functions.
- Every line of the function must be written out completely — the words "existing code", "existing logic", "..." and any placeholder comments are FORBIDDEN.
- Add an inline comment on every line you changed explaining what was fixed and why.
- If a vulnerability was found: each case must directly correspond to one finding named in the Explanation section (Case A: fix reentrancy, Case B: fix oracle manipulation, Case C: add access control, Case D: add input validation).
- If no vulnerability was found: each case must apply a concrete proactive improvement (e.g. Case A: add ReentrancyGuard, Case B: implement TWAP oracle, Case C: add onlyOwner modifier, Case D: add SafeMath).
- You MUST write ALL cases completely. Do NOT summarize, skip, or abbreviate any case. Do NOT end with a generic note like "apply similar changes elsewhere" — write each case in full.
EXAMPLE: If you find a reentrancy bug, provide: Case A (Checks-Effects-Interactions), Case B (ReentrancyGuard modifier), Case C (Oracle TWAP improvement), Case D (Access control for sensitive functions).
"#,
    context = context,
    contract = contract,
  );

  compute.infer(&prompt).await
}

/// Build RAG context string from Qdrant search results
pub fn build_rag_context_qdrant(top: &[qdrant_storage::QdrantExploitResult]) -> String {
  let mut ctx = String::new();
  for (i, e) in top.iter().enumerate() {
    let score_rounded = (e.score * 1000.0).round() / 1000.0;
    let is_real = e.source != "DeFiVulnLabs";

    let header = format!(
      "--- Reference {}: {} ({}) [similarity: {}] [source: {}] [collection: {}] ---",
      i + 1,
      e.exploit_name,
      e.date,
      score_rounded,
      e.source,
      e.collection,
    );

    let (tx_line, lost_line, type_line) = if is_real {
      (
        format!(
          "Attack Tx: {}",
          if e.attack_tx.is_empty() {
            "unknown"
          } else {
            &e.attack_tx
          }
        ),
        format!("Total Lost: {}", e.total_lost),
        String::new(),
      )
    } else {
      (
        "Attack Tx: N/A (educational pattern)".to_string(),
        "Total Lost: N/A".to_string(),
        format!("Vulnerability Type: {}\n", e.vuln_type),
      )
    };

    let code = e.code_snippet.chars().take(1500).collect::<String>();

    ctx.push_str(&format!(
      "\n{}\nChain: {}\n{}\n{}\n{}Code Snippet:\n{}\n",
      header, e.chain, lost_line, tx_line, type_line, code,
    ));
  }
  ctx
}
