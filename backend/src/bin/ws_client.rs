/*!
RAXC WebSocket Client — sends a contract to ws_server and prints results.

Usage:
    cargo run --bin ws_client                          # uses built-in DeFiVault demo
    cargo run --bin ws_client -- < contract.sol        # pipe a file
    RAXC_CONTRACT_FILE=path.sol cargo run --bin ws_client
*/

use anyhow::Result;
use futures::{SinkExt, StreamExt};
use serde_json::Value;
use tokio_tungstenite::{connect_async, tungstenite::Message};

const WS_URL: &str = "ws://localhost:3001/ws";

#[tokio::main]
async fn main() -> Result<()> {
  let contract = if let Ok(code) = std::env::var("RAXC_CONTRACT_CODE") {
    code
  } else if let Ok(file_path) = std::env::var("RAXC_CONTRACT_FILE") {
    std::fs::read_to_string(&file_path)
      .map_err(|e| anyhow::anyhow!("Cannot read '{}': {}", file_path, e))?
  } else {
    // Default demo contract
    r#"pragma solidity ^0.7.0;

contract DeFiVault {
    mapping(address => uint256) public balances;
    address[] public depositors;
    address public owner;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        depositors.push(msg.sender);
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Nothing to withdraw");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
        balances[msg.sender] = 0;
    }
}"#
      .to_string()
  };

  let name = contract
    .split_whitespace()
    .skip_while(|w| *w != "contract")
    .nth(1)
    .map(|s| {
      s.trim_matches(|c: char| !c.is_alphanumeric() && c != '_')
        .to_string()
    })
    .unwrap_or_else(|| "Contract".to_string());

  println!("\n╔══════════════════════════════════════════════════════╗");
  println!("║   RAXC WebSocket Client                              ║");
  println!("╚══════════════════════════════════════════════════════╝\n");
  println!("[*] Connecting to {}...", WS_URL);

  let (mut ws, _) = connect_async(WS_URL).await?;
  println!("[✓] Connected\n");

  // Read welcome messages (exactly 2: banner + info)
  for _ in 0..2 {
    if let Some(Ok(Message::Text(text))) = ws.next().await {
      let data: Value = serde_json::from_str(&text)?;
      match data["type"].as_str() {
        Some("banner") => println!("{}", data["text"].as_str().unwrap_or("")),
        Some("info") => println!("  {}", data["text"].as_str().unwrap_or("")),
        _ => {}
      }
    }
  }

  // Send contract
  println!("\n[*] Analyzing: {}\n", name);
  let payload = serde_json::json!({ "contract": contract });
  ws.send(Message::Text(payload.to_string())).await?;

  // Read phase-by-phase results
  while let Some(Ok(msg)) = ws.next().await {
    if let Message::Text(text) = msg {
      let data: Value = serde_json::from_str(&text)?;
      match data["type"].as_str() {
        Some("progress") => {
          let text = data["text"].as_str().unwrap_or("");
          for line in text.lines() {
            if line.starts_with("    ") {
              println!("  \x1b[2m{}\x1b[0m", line);
            } else {
              println!("  \x1b[2m{}\x1b[0m", line);
            }
          }
        }
        Some("info") => {
          println!("{}", data["text"].as_str().unwrap_or(""));
        }
        Some("banner") => {
          println!("{}", data["text"].as_str().unwrap_or(""));
        }
        Some("phase") => {
          let name = data["name"].as_str().unwrap_or("");
          let details = &data["details"];
          println!("\x1b[1;96m{}\x1b[0m", name);
          if let Some(obj) = details.as_object() {
            for (k, v) in obj {
              let key = k.replace('_', " ").replace("  ", " ");
              let val = match v {
                Value::Number(n) => {
                  if let Some(f) = n.as_f64() {
                    if f <= 1.0
                      && (k.contains("score")
                        || k.contains("probability")
                        || k.contains("confidence")
                        || k.contains("likelihood"))
                    {
                      format!("{:.2}%", f * 100.0)
                    } else {
                      format!("{:.0}", f)
                    }
                  } else {
                    v.to_string()
                  }
                }
                Value::Bool(b) => {
                  if *b {
                    "✅ PASS".to_string()
                  } else {
                    "❌ FAIL".to_string()
                  }
                }
                _ => v.to_string().trim_matches('"').to_string(),
              };
              println!("  {}: {}", key, val);
            }
          }
          tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        }
        Some("explanation") => {
          println!("\n\x1b[1;35m[🧠 LLM EXPLANATION]\x1b[0m");
          println!("{}", data["text"].as_str().unwrap_or(""));
        }
        Some("complete") => {
          let s = &data["summary"];
          println!("\n\x1b[36m╔═══════════════════════════════════════════════════════════════════╗\x1b[0m");
          println!(
            "\x1b[36m║        AUTONOMOUS ENGINE — SOVEREIGN EXECUTION COMPLETE           ║\x1b[0m"
          );
          println!("\x1b[36m╚═══════════════════════════════════════════════════════════════════╝\x1b[0m\n");
          println!(
            "  Contract:        {}",
            s["contract"].as_str().unwrap_or("?")
          );
          println!(
            "  Vulnerability:   {}",
            s["vulnerability_found"]
              .as_bool()
              .map_or("?", |v| if v { "YES" } else { "NO" })
          );
          println!(
            "  Risk Level:      {}",
            s["risk_level"].as_str().unwrap_or("?")
          );
          println!(
            "  Confidence:      {:.1}%",
            s["confidence"].as_f64().unwrap_or(0.0) * 100.0
          );
          println!(
            "  Final Verdict:   {}",
            s["final_verdict"].as_str().unwrap_or("?")
          );
          println!(
            "  Report:          {}",
            s["report_path"].as_str().unwrap_or("?")
          );
          println!(
            "  AgentMemory TX:  {}",
            s["storage_tx"].as_str().unwrap_or("—")
          );
          println!(
            "  AuditReport TX:  {}",
            s["report_tx"].as_str().unwrap_or("—")
          );
          println!(
            "  Attestation ID:  {}",
            s["attestation_replay_id"].as_str().unwrap_or("—")
          );
          if let Some(url) = s["agent_explorer_url"].as_str() {
            println!("  Explorer:        {}", url);
          }
          break;
        }
        Some("error") => {
          eprintln!("\n❌ ERROR: {}", data["message"].as_str().unwrap_or(""));
          break;
        }
        _ => {}
      }
    }
  }

  Ok(())
}
