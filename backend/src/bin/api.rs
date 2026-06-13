/*!
RAXC API Server — full agent_clean pipeline over HTTP.

Usage:
  cargo run --bin api_step9_9

Endpoints:
  POST /analyze    { "contract": "...", "name": "ContractName" }
  GET  /reports/{file}  Download markdown report
  GET  /health      Health check
*/

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
  body::Body,
  extract::{Path, State},
  http::{header, StatusCode},
  response::{IntoResponse, Response},
  routing::{get, post},
  Json, Router,
};
use raxc::{
  build_openai_client, load_env, AccessControlTool, AgentCore, FlashLoanTool, GasAnalyzerTool,
  MemoryTool, PatternDetectorTool, QdrantStorageClient, RaxcAnalyzerRemote, ReflectionTool,
  StylusClient,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Mutex;
use tower_http::cors::{Any, CorsLayer};

// ─── Shared State ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
  agent_core: Arc<Mutex<AgentCore>>,
  reports: Arc<Mutex<HashMap<String, String>>>,
}

// ─── Request / Response ───────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AnalyzeRequest {
  contract: String,
  #[serde(default = "default_name")]
  name: String,
}

fn default_name() -> String { "contract".to_string() }

#[derive(Serialize)]
struct AnalyzeResponse {
  download_url: String,
  vulnerability_found: bool,
  risk_level: String,
  vulnerability_type: String,
  confidence: f64,
  risk_score: f64,
  exploitability: f64,
  attack_probability: f64,
  consistency_score: f64,
  graph_nodes: usize,
  graph_edges: usize,
  replay_id: String,
  trace_hash: String,
  /// On-chain tx hashes
  storage_tx: String,
  report_tx: String,
  report_task_id: String,
}

// ─── Error ────────────────────────────────────────────────────────────────────

struct AppError(anyhow::Error);

impl IntoResponse for AppError {
  fn into_response(self) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": format!("{:#}", self.0) }))).into_response()
  }
}

impl<E: Into<anyhow::Error>> From<E> for AppError {
  fn from(e: E) -> Self { AppError(e.into()) }
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

#[axum::debug_handler]
async fn handle_analyze(
  State(state): State<AppState>,
  Json(req): Json<AnalyzeRequest>,
) -> Result<Json<AnalyzeResponse>, AppError> {
  println!("\n[*] Analyze request: {} ({} bytes)", req.name, req.contract.len());

  let result = {
    let core = state.agent_core.lock().await;
    core.analyze(&req.contract, &req.name).await?
  };

  println!("[✓] Done: {}", result.filename);

  // Store report
  state.reports.lock().await.insert(result.filename.clone(), result.markdown.clone());

  let vuln_type = result.decision.primary_vulnerability.clone().unwrap_or_else(|| "None".to_string());

  Ok(Json(AnalyzeResponse {
    download_url: format!("/reports/{}", result.filename),
    vulnerability_found: result.decision.vulnerability_found,
    risk_level: result.decision.risk_level.clone(),
    vulnerability_type: vuln_type,
    confidence: (result.final_decision.final_confidence * 100.0).round(),
    risk_score: (result.final_decision.final_risk_score * 100.0).round(),
    exploitability: (result.intelligence_report.exploitability_score * 100.0).round(),
    attack_probability: (result.final_decision.final_attack_probability * 100.0).round(),
    consistency_score: (result.consistency_check.consistency_score * 100.0).round(),
    graph_nodes: result.attack_graph.nodes.len(),
    graph_edges: result.attack_graph.edges.len(),
    replay_id: result.attestation.replay_id.clone(),
    trace_hash: result.attestation.execution_trace_hash.clone(),
    storage_tx: result.storage_root_hash.clone(),
    report_tx: result.report_tx.clone(),
    report_task_id: result.report_root_hash.clone(),
  }))
}

async fn download_report(
  State(state): State<AppState>,
  Path(filename): Path<String>,
) -> Result<Response, AppError> {
  let safe = std::path::Path::new(&filename)
    .file_name().and_then(|n| n.to_str())
    .ok_or_else(|| anyhow::anyhow!("Invalid filename"))?.to_owned();

  let content = state.reports.lock().await.get(&safe).cloned()
    .ok_or_else(|| anyhow::anyhow!("Report not found: {}", safe))?;

  Ok(Response::builder()
    .header(header::CONTENT_TYPE, "text/markdown; charset=utf-8")
    .header(header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", safe))
    .body(Body::from(content))
    .unwrap())
}

async fn health() -> impl IntoResponse {
  Json(json!({ "status": "ok", "pipeline": "agent_clean 13-phase", "chain": "Arbitrum Sepolia" }))
}

// ─── Entry Point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  load_env();

  println!("╔══════════════════════════════════════════════════════════════════╗");
  println!("║   RAXC API — agent_clean 13-phase pipeline                       ║");
  println!("╚══════════════════════════════════════════════════════════════════╝\n");

  // Init clients
  println!("[*] Qdrant…");
  let qdrant = QdrantStorageClient::from_env()?;
  qdrant.health().await?;

  println!("[*] Stylus…");
  let stylus = Arc::new(StylusClient::from_env().await?);

  println!("[*] OpenAI…");
  let compute = Arc::new(build_openai_client()?);

  println!("[*] Building AgentCore…");
  let mut core = AgentCore::new(qdrant.clone(), stylus, (*compute).clone());

  // Register all 7 tools (matching ws_server pipeline)
  core.tools.register(Box::new(RaxcAnalyzerRemote::new(qdrant, (*compute).clone())));
  println!("[✓] RaxcAnalyzerRemote");
  core.tools.register(Box::new(GasAnalyzerTool::new()));
  core.tools.register(Box::new(PatternDetectorTool::new()));
  core.tools.register(Box::new(FlashLoanTool::new()));
  core.tools.register(Box::new(AccessControlTool::new()));
  core.tools.register(Box::new(ReflectionTool::new(compute.clone())));
  core.tools.register(Box::new(MemoryTool::new(Arc::new(core.memory.clone()))));
  println!("[✓] {} tools registered", core.tools.tool_count());

  let state = AppState {
    agent_core: Arc::new(Mutex::new(core)),
    reports: Arc::new(Mutex::new(HashMap::new())),
  };

  let app = Router::new()
    .route("/analyze", post(handle_analyze))
    .route("/reports/*filename", get(download_report))
    .route("/health", get(health))
    .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any))
    .with_state(state);

  let addr = "0.0.0.0:3000";
  println!("\n[✓] Listening on http://{}\n", addr);

  let listener = tokio::net::TcpListener::bind(addr).await?;
  axum::serve(listener, app).await?;
  Ok(())
}
