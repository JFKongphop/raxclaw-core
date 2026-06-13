/*!
RAXC WebSocket Server — real-time exploit intelligence over WebSocket.

Connect: ws://localhost:3001/ws
Send a JSON message to trigger analysis:
  { "contract": "pragma solidity ^0.8.0; contract Foo { ... }" }

The server streams phase-by-phase progress then sends the final result,
mirroring the terminal output of `agent_example_remote`.

Run:
    cargo run --bin ws_server
*/

use anyhow::Result;
use axum::{
  extract::{ws::{Message, WebSocket, WebSocketUpgrade}, Path, State},
  response::IntoResponse,
  routing::get,
  Router,
};
use std::collections::HashMap;
use futures::{SinkExt, StreamExt};
use raxc::{
  build_openai_client, load_env, AccessControlTool, AgentCore, FlashLoanTool, GasAnalyzerTool,
  MemoryTool, PatternDetectorTool, QdrantStorageClient, RaxcAnalyzerRemote, ReflectionTool,
  StylusClient,
};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Mutex;

// ─── WebSocket message types (server → client) ────────────────────────────────

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
enum WsMessage {
  #[serde(rename = "banner")]
  Banner { text: String },
  #[serde(rename = "info")]
  Info { text: String },
  #[serde(rename = "phase")]
  #[allow(dead_code)]
  Phase {
    name: String,
    details: serde_json::Value,
  },
  #[serde(rename = "explanation")]
  Explanation { text: String },
  #[serde(rename = "complete")]
  Complete {
    report_path: String,
    summary: serde_json::Value,
    markdown: String,
  },
  #[serde(rename = "error")]
  Error { message: String },
}

impl WsMessage {
  fn to_json(&self) -> String {
    serde_json::to_string(self).unwrap_or_default()
  }
}

// ─── Shared state ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
  reports: Arc<Mutex<HashMap<String, String>>>,
}

// ─── Analysis runner (identical pipeline to agent_example_remote) ─────────────

async fn run_analysis(
  contract_code: &str,
  tx: Arc<Mutex<futures::stream::SplitSink<WebSocket, Message>>>,
  state: Arc<AppState>,
) -> Result<serde_json::Value> {
  let send = |msg: WsMessage| {
    let tx = Arc::clone(&tx);
    async move {
      let mut sender = tx.lock().await;
      let _ = sender.send(Message::Text(msg.to_json().into())).await;
    }
  };

  send(WsMessage::Info {
    text: "[*] Connecting to Qdrant...".into(),
  })
  .await;
  let qdrant = QdrantStorageClient::from_env()?;
  let loaded = qdrant.health().await?;
  send(WsMessage::Info {
    text: format!(
      "[✓] Qdrant online — {} total exploit vectors loaded",
      loaded
    ),
  })
  .await;

  let stylus = Arc::new(StylusClient::from_env().await?);
  let compute = Arc::new(build_openai_client()?);

  let mut core = AgentCore::new(qdrant.clone(), stylus, (*compute).clone());

  // Register tools
  core.tools.register(Box::new(RaxcAnalyzerRemote::new(
    qdrant,
    (*compute).clone(),
  )));
  send(WsMessage::Info {
    text: "[✓] Registered tool: RaxcAnalyzerRemote".into(),
  })
  .await;
  core.tools.register(Box::new(GasAnalyzerTool::new()));
  send(WsMessage::Info {
    text: "[✓] Registered tool: GasAnalyzerTool".into(),
  })
  .await;
  core.tools.register(Box::new(PatternDetectorTool::new()));
  send(WsMessage::Info {
    text: "[✓] Registered tool: PatternDetectorTool".into(),
  })
  .await;
  core.tools.register(Box::new(FlashLoanTool::new()));
  send(WsMessage::Info {
    text: "[✓] Registered tool: FlashLoanTool".into(),
  })
  .await;
  core.tools.register(Box::new(AccessControlTool::new()));
  send(WsMessage::Info {
    text: "[✓] Registered tool: AccessControlTool".into(),
  })
  .await;
  core
    .tools
    .register(Box::new(ReflectionTool::new(compute.clone())));
  send(WsMessage::Info {
    text: "[✓] Registered tool: ReflectionTool".into(),
  })
  .await;
  core
    .tools
    .register(Box::new(MemoryTool::new(Arc::new(core.memory.clone()))));
  send(WsMessage::Info {
    text: "[✓] Registered tool: MemoryTool".into(),
  })
  .await;

  // Extract contract name
  let contract_name = contract_code
    .split_whitespace()
    .skip_while(|w| *w != "contract")
    .nth(1)
    .map(|s| {
      s.trim_matches(|c: char| !c.is_alphanumeric() && c != '_')
        .to_string()
    })
    .filter(|s| !s.is_empty())
    .unwrap_or_else(|| "Contract".to_string());

  send(WsMessage::Info {
    text: format!("[*] Analyzing contract: {}", contract_name),
  })
  .await;
  send(WsMessage::Info {
    text: "[*] Initiating autonomous exploit analysis — 13-phase verification pipeline...".into(),
  })
  .await;

  // Set up real-time progress streaming from AgentCore
  let (progress_tx, mut progress_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
  let progress_tx_clone = progress_tx.clone();
  core.set_progress_sender(progress_tx_clone);

  // Spawn progress forwarder: reads from AgentCore, sends to WebSocket
  let tx_progress = Arc::clone(&tx);
  tokio::spawn(async move {
    while let Some(msg) = progress_rx.recv().await {
      let mut sender = tx_progress.lock().await;
      let _ = sender
        .send(Message::Text(
          serde_json::json!({ "type": "progress", "text": msg }).to_string(),
        ))
        .await;
    }
  });

  // Run the full pipeline
  let result = core
    .analyze(contract_code, &contract_name)
    .await
    .map_err(|e| {
      // Try to send error over ws before returning
      anyhow::anyhow!("{}", e)
    })?;

  // Drop progress sender to close channel, wait for forwarder to flush
  drop(progress_tx);
  tokio::time::sleep(std::time::Duration::from_millis(500)).await;

  // ─── Stream results in EXACT terminal format ─────────────────────────

  // Header box
  send(WsMessage::Banner {
    text: "\n╔══════════════════════════════════════════════════════════════════════════╗\n║                  AUTONOMOUS EXPLOIT INTELLIGENCE RESULT                  ║\n╚══════════════════════════════════════════════════════════════════════════╝".into(),
  })
  .await;

  // Phase: Basic Decision
  let mut basic = format!(
    "  Vulnerability Found:  {}\n  Risk Level:          {}\n  Confidence:          {:.1}%\n  Tool Signals:        {}",
    result.decision.vulnerability_found,
    result.decision.risk_level,
    result.decision.confidence * 100.0,
    result.signals.len(),
  );
  if let Some(vuln) = &result.decision.primary_vulnerability {
    basic = format!("  Vulnerability Type:  {}\n{}", vuln, basic);
  }
  send(WsMessage::Info { text: format!("📊 BASIC DECISION:\n{}", basic) }).await;
  tokio::time::sleep(std::time::Duration::from_millis(800)).await;

  // Phase: Intelligence Report
  send(WsMessage::Info {
    text: format!(
      "📈 INTELLIGENCE REPORT:\n  Risk Score:          {:.2}%\n  Exploitability:      {:.2}%\n  Attack Likelihood:   {:.2}%\n  Classification:      {}",
      result.intelligence_report.risk_score * 100.0,
      result.intelligence_report.exploitability_score * 100.0,
      result.intelligence_report.attack_likelihood * 100.0,
      result.intelligence_report.final_classification,
    ),
  }).await;
  tokio::time::sleep(std::time::Duration::from_millis(800)).await;

  // Phase: Attack Simulation
  send(WsMessage::Info {
    text: format!(
      "🧪 ATTACK SIMULATION:\n  Execution Path:      {} steps\n  State Transitions:   {} tracked\n  Attacker Type:       {}\n  Exploit Status:      {}\n  Success Probability: {:.1}%\n  Replay ID:           {}",
      result.attack_simulation.execution_path.len(),
      result.attack_simulation.state_transitions.len(),
      result.attack_simulation.attacker_model.attacker_type,
      result.attack_simulation.exploit_verdict.status,
      result.attack_simulation.exploit_verdict.success_probability * 100.0,
      result.attack_simulation.replay_info.replay_id,
    ),
  }).await;
  tokio::time::sleep(std::time::Duration::from_millis(800)).await;

  // Phase: Graph Construction
  send(WsMessage::Info {
    text: format!(
      "📊 ATTACK MAP ENGINE:\n  Graph Nodes:         {}\n  Graph Edges:         {}\n  Root Node:           {}",
      result.attack_graph.nodes.len(),
      result.attack_graph.edges.len(),
      result.attack_graph.root_node,
    ),
  }).await;
  tokio::time::sleep(std::time::Duration::from_millis(800)).await;

  // Phase: Consistency Verification
  send(WsMessage::Info {
    text: format!(
      "✅ CONSISTENCY VERIFICATION:\n  Simulation Valid:    {}\n  Graph Consistent:    {}\n  State Correct:       {}\n  Tool Conflict:       {}\n  Consistency Score:   {:.2}%",
      if result.consistency_check.simulation_valid { "✅ PASS" } else { "❌ FAIL" },
      if result.consistency_check.graph_consistent { "✅ PASS" } else { "❌ FAIL" },
      if result.consistency_check.state_correct { "✅ PASS" } else { "❌ FAIL" },
      if result.consistency_check.tool_conflict { "⚠️  YES" } else { "✅ NO" },
      result.consistency_check.consistency_score * 100.0,
    ),
  }).await;
  tokio::time::sleep(std::time::Duration::from_millis(800)).await;

  // Phase: Final Decision
  send(WsMessage::Info {
    text: format!(
      "🎯 FINAL DECISION:\n  Final Verdict:       {}\n  Final Confidence:    {:.2}%\n  Final Attack Prob:   {:.2}%\n  Final Risk Score:    {:.2}%",
      result.final_decision.final_verdict,
      result.final_decision.final_confidence * 100.0,
      result.final_decision.final_attack_probability * 100.0,
      result.final_decision.final_risk_score * 100.0,
    ),
  }).await;
  tokio::time::sleep(std::time::Duration::from_millis(800)).await;

  // Phase: Attestation
  send(WsMessage::Info {
    text: format!(
      "🔐 ATTESTATION:\n  Replay ID:           {}\n  Seed:                {}\n  Trace Hash:          {}\n  Timestamp:           {}\n  Verdict:             {}",
      result.attestation.replay_id,
      result.attestation.seed,
      result.attestation.execution_trace_hash,
      result.attestation.timestamp,
      result.attestation.final_verdict,
    ),
  }).await;
  tokio::time::sleep(std::time::Duration::from_millis(800)).await;

  // Phase: LLM Explanation
  send(WsMessage::Explanation {
    text: result.explanation.clone(),
  })
  .await;

  // Save report to in-memory store (like api.rs — no disk writes)
  state.reports.lock().await.insert(result.filename.clone(), result.markdown.clone());
  println!("[Server]       Report stored in memory: {}", result.filename);

  // ─── On-Chain Proof (mirrors terminal output) ─────────────────────────

  send(WsMessage::Info {
    text: format!(
      "[Memory]         Pushed             | TX: {}",
      result.storage_root_hash
    ),
  })
  .await;

  send(WsMessage::Info {
    text: format!(
      "[AuditReport]    Task #{} created   | TX: {}",
      result.report_root_hash, result.report_tx
    ),
  })
  .await;

  send(WsMessage::Info {
    text: format!(
      "[AuditReport]    Task #{} finalized | TX: {}",
      result.report_root_hash, result.report_tx
    ),
  })
  .await;

  // ON-CHAIN PROOF box
  send(WsMessage::Banner {
    text: "\n╔════════════════════════════════════════════════════════════════════════╗\n║                      ON-CHAIN PROOF — Arbitrum Sepolia                 ║\n╚════════════════════════════════════════════════════════════════════════╝".into(),
  })
  .await;

  let agent_tx = &result.storage_root_hash;
  let report_tx_clean = &result.report_tx;

  send(WsMessage::Info {
    text: format!("  AgentMemory (JSON): {}", result.storage_root_hash),
  })
  .await;
  send(WsMessage::Info {
    text: format!("  AuditReport Task #: {}", result.report_root_hash),
  })
  .await;
  send(WsMessage::Info {
    text: format!(
      "  AgentMemory TX:     https://sepolia.arbiscan.io/tx/{}",
      agent_tx
    ),
  })
  .await;
  send(WsMessage::Info {
    text: format!(
      "  AuditReport TX:     https://sepolia.arbiscan.io/tx/{}",
      report_tx_clean
    ),
  })
  .await;

  // Build summary
  let summary = serde_json::json!({
      "contract": contract_name,
      "vulnerability_found": result.decision.vulnerability_found,
      "risk_level": result.decision.risk_level,
      "confidence": result.decision.confidence,
      "final_verdict": result.final_decision.final_verdict,
      "report_path": result.filename,
      "storage_tx": result.storage_root_hash,
      "report_tx": result.report_tx,
      "attestation_replay_id": result.attestation.replay_id,
      "execution_trace_hash": result.attestation.execution_trace_hash,
      "agent_explorer_url": format!("https://sepolia.arbiscan.io/tx/{}", agent_tx),
      "report_explorer_url": format!("https://sepolia.arbiscan.io/tx/{}", report_tx_clean),
  });

  send(WsMessage::Complete {
    report_path: result.filename.clone(),
    summary,
    markdown: result.markdown.clone(),
  })
  .await;

  Ok(serde_json::json!({ "status": "ok" }))
}

// ─── WebSocket handler ────────────────────────────────────────────────────────

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<Arc<AppState>>) -> impl IntoResponse {
  ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>) {
  let (sender, mut receiver) = socket.split();
  let sender = Arc::new(Mutex::new(sender));

  // Send welcome banner
  let banner = WsMessage::Banner {
    text: "\
╔══════════════════════════════════════════════════════════════════════════╗
║         RAXC Autonomous Exploit Intelligence Core — WebSocket API        ║
║         Deterministic Exploit Execution + Verification Framework         ║
╚══════════════════════════════════════════════════════════════════════════╝"
      .into(),
  };
  {
    let mut s = sender.lock().await;
    let _ = s.send(Message::Text(banner.to_json().into())).await;
  }
  // Send usage hint
  let usage = WsMessage::Info {
    text: "Send a JSON message: {\"contract\": \"pragma solidity ^0.8.0; ...\"}".into(),
  };
  {
    let mut s = sender.lock().await;
    let _ = s.send(Message::Text(usage.to_json().into())).await;
  }

  while let Some(Ok(msg)) = receiver.next().await {
    match msg {
      Message::Text(text) => {
        // Parse incoming message
        let contract_code = if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
          json
            .get("contract")
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_else(|| text.to_string())
        } else {
          // Plain text = contract code
          text.to_string()
        };

        let sender_clone = sender.clone();
        let state_clone = state.clone();
        tokio::spawn(async move {
          match run_analysis(&contract_code, sender_clone.clone(), state_clone).await {
            Ok(_) => {}
            Err(e) => {
              let err_msg = WsMessage::Error {
                message: format!("{:#}", e),
              };
              let mut s = sender_clone.lock().await;
              let _ = s.send(Message::Text(err_msg.to_json().into())).await;
            }
          }
        });
      }
      Message::Close(_) => break,
      _ => {}
    }
  }
}

// ─── Server entrypoint ────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
  load_env();

  let port = std::env::var("WS_PORT").unwrap_or_else(|_| "3001".to_string());
  let addr = format!("0.0.0.0:{}", port);

  println!("\n╔══════════════════════════════════════════════════════════════╗");
  println!("║   RAXC WebSocket Server                                      ║");
  println!(
    "║   ws://{}                                          ║",
    addr
  );
  println!("║   Send: {{\"contract\": \"pragma solidity ...\"}}                  ║");
  println!("╚══════════════════════════════════════════════════════════════╝\n");

  let state = Arc::new(AppState {
    reports: Arc::new(Mutex::new(HashMap::new())),
  });

  let app = Router::new()
    .route("/ws", get(ws_handler))
    .route("/health", get(|| async { "OK" }))
    .route("/reports/{filename}", get(|Path(filename): Path<String>| async move {
      format!("test: {}", filename)
    }))
    .with_state(state);

  let listener = tokio::net::TcpListener::bind(&addr).await?;
  println!("[✓] WebSocket server listening on ws://{}\n", addr);

  axum::serve(listener, app).await?;

  Ok(())
}
