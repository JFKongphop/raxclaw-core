/*!
Example: RAXC Multi-Agent Framework — Sovereign Execution Mode

Full pipeline: Qdrant (RAG) → OpenAI (LLM) → Stylus (on-chain proof).

Prerequisites:
  - Qdrant Cloud: 782 exploit vectors in defi_cases + defi_protocols
  - OpenAI API: GPT-4o-mini + text-embedding-3-small
  - Arbitrum Sepolia: AgentMemory + AuditReport Stylus contracts deployed

Run:
    cargo run --example agent_example_remote
*/

use anyhow::Result;
use raxc::{
  build_openai_client, load_env, AccessControlTool, AgentCore, FlashLoanTool, GasAnalyzerTool,
  MemoryTool, PatternDetectorTool, QdrantStorageClient, RaxcAnalyzerRemote, ReflectionTool,
  StylusClient,
};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
  // Load environment variables
  load_env();

  println!(
    "\x1b[1;96m╔══════════════════════════════════════════════════════════════════════════╗\x1b[0m"
  );
  println!("\x1b[1;96m║\x1b[0m  \x1b[1;96mRAXC Autonomous Exploit Intelligence Core — Sovereign Execution Mode\x1b[0m    \x1b[1;96m║\x1b[0m");
  println!("\x1b[1;96m║\x1b[0m         \x1b[2mDeterministic Exploit Execution + Verification Framework\x1b[0m         \x1b[1;96m║\x1b[0m");
  println!("\x1b[1;96m╚══════════════════════════════════════════════════════════════════════════╝\x1b[0m\n");

  // ─── Connect to Qdrant vector database ────────────────────────────────────────
  println!("\x1b[33m[*] Connecting to Qdrant...\x1b[0m");
  let qdrant = QdrantStorageClient::from_env()?;
  let loaded = qdrant.health().await?;
  println!(
    "\x1b[92m[✓] Qdrant online — {} total exploit vectors loaded\x1b[0m\n",
    loaded
  );

  // ─── Initialize Stylus + OpenAI clients ──────────────────────────────────────
  let stylus = Arc::new(StylusClient::from_env().await?);
  let compute = Arc::new(build_openai_client()?);

  // ─── Create AgentCore (with Stylus memory for on-chain writes) ────────────────
  let mut core = AgentCore::new(qdrant.clone(), stylus, (*compute).clone());

  // ─── Register tools ──────────────────────────────────────────────────────────
  println!("\x1b[33m[*] Registering tools to ToolRegistry...\x1b[0m");
  core.tools.register(Box::new(RaxcAnalyzerRemote::new(
    qdrant,
    (*compute).clone(),
  )));
  core.tools.register(Box::new(GasAnalyzerTool::new()));
  core.tools.register(Box::new(PatternDetectorTool::new()));
  core.tools.register(Box::new(FlashLoanTool::new()));
  core.tools.register(Box::new(AccessControlTool::new()));
  core
    .tools
    .register(Box::new(ReflectionTool::new(compute.clone())));
  // MemoryTool: shares the same MemoryLayer as AgentCore (single StylusClient)
  core
    .tools
    .register(Box::new(MemoryTool::new(Arc::new(core.memory.clone()))));
  // ✅ RaxcAnalyzerRemote   : RAG match against 722 real exploits
  // ✅ ReflectionTool       : LLM Compute self-critique of consensus result
  let default_contract = r#"
pragma solidity ^0.7.0;

contract DeFiVault {
    mapping(address => uint256) public balances;
    address[] public depositors;
    address public owner;
    bool private initialized;

    // ❌ AccessControl: no initializer guard, callable multiple times
    function initialize(address _owner) external {
        owner = _owner;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        depositors.push(msg.sender);
    }

    // ❌ Reentrancy: external call before state update
    // ❌ AccessControl: no onlyOwner guard on withdraw
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Nothing to withdraw");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
        balances[msg.sender] = 0;
    }

    // ❌ FlashLoan: spot price oracle via getReserves — manipulable in one tx
    function getPrice() external view returns (uint256) {
        (uint112 reserve0, uint112 reserve1,) = IUniswapPair(address(this)).getReserves();
        return uint256(reserve0) * 1e18 / uint256(reserve1);
    }

    // ❌ FlashLoan: flash loan callback with no reentrancy guard
    function executeOperation(uint256 amount) external {
        uint256 price = this.getPrice();
        balances[msg.sender] += price * amount;
    }

    // ❌ Gas: array.length in loop, string memory param
    function distributeRewards(string memory label) external {
        for (uint i = 0; i < depositors.length; i++) {
            balances[depositors[i]] += 100;
        }
    }
}

interface IUniswapPair {
    function getReserves() external view returns (uint112, uint112, uint32);
}
  "#;

  // ─── Load contract (inline code, --file path, or built-in DeFiVault demo) ─────────────
  let (contract_code, contract_name) = if let Ok(code) = std::env::var("RAXC_CONTRACT_CODE") {
    // Extract name from "contract FooBar {" pattern
    let name = code
      .split_whitespace()
      .skip_while(|w| *w != "contract")
      .nth(1)
      .map(|s| {
        s.trim_matches(|c: char| !c.is_alphanumeric() && c != '_')
          .to_string()
      })
      .filter(|s| !s.is_empty())
      .unwrap_or_else(|| "Contract".to_string());
    println!(
      "\x1b[33m[*]\x1b[0m Analyzing inline contract: \x1b[97m{}\x1b[0m",
      name
    );
    (code, name)
  } else if let Ok(file_path) = std::env::var("RAXC_CONTRACT_FILE") {
    println!(
      "\x1b[33m[*]\x1b[0m Loading contract from: \x1b[97m{}\x1b[0m",
      file_path
    );
    let code = std::fs::read_to_string(&file_path)
      .map_err(|e| anyhow::anyhow!("Cannot read '{}': {}", file_path, e))?;
    let name = std::path::Path::new(&file_path)
      .file_stem()
      .and_then(|s| s.to_str())
      .unwrap_or("Contract")
      .to_string();
    (code, name)
  } else {
    println!("\x1b[2m    (no --file given — using built-in DeFiVault demo contract)\x1b[0m");
    (default_contract.to_string(), "DeFiVault".to_string())
  };

  // ─── On-chain proof: Stylus contracts on Arbitrum Sepolia ──────────────────
  // AgentMemory + AuditReport handle all audit task tracking on-chain.
  // No external ERC-8183 / ERC-7857 contracts needed.

  // ─── Run analysis ─────────────────────────────────────────────────────────────
  println!("\n\x1b[33m[*]\x1b[0m Initiating autonomous exploit analysis — 13-phase verification pipeline...\n");
  let result = core.analyze(&contract_code, &contract_name).await?;

  // Save markdown report
  let reports_dir = std::path::Path::new("reports");
  std::fs::create_dir_all(reports_dir)?;
  let report_path = reports_dir.join(&result.filename);
  std::fs::write(&report_path, &result.markdown)?;
  println!(
    "\n\x1b[92m✅ Report saved to: {}\x1b[0m\n",
    report_path.display()
  );

  println!(
    "\n\x1b[36m╔══════════════════════════════════════════════════════════════════════════╗\x1b[0m"
  );
  println!(
    "\x1b[36m║                  AUTONOMOUS EXPLOIT INTELLIGENCE RESULT                  ║\x1b[0m"
  );
  println!(
    "\x1b[36m╚══════════════════════════════════════════════════════════════════════════╝\x1b[0m\n"
  );

  println!("\x1b[1;96m📊 BASIC DECISION:\x1b[0m");
  println!(
    "  Vulnerability Found:  {}",
    result.decision.vulnerability_found
  );
  println!("  Risk Level:          {}", result.decision.risk_level);
  if let Some(vuln) = &result.decision.primary_vulnerability {
    println!("  Vulnerability Type:  {}", vuln);
  }
  println!(
    "  Confidence:          {:.1}%",
    result.decision.confidence * 100.0
  );
  println!("  Tool Signals:        {}", result.signals.len());

  tokio::time::sleep(std::time::Duration::from_millis(800)).await;
  println!("\n\x1b[1;96m📈 INTELLIGENCE REPORT:\x1b[0m");
  println!(
    "  Risk Score:          {:.2}%",
    result.intelligence_report.risk_score * 100.0
  );
  println!(
    "  Exploitability:      {:.2}%",
    result.intelligence_report.exploitability_score * 100.0
  );
  println!(
    "  Attack Likelihood:   {:.2}%",
    result.intelligence_report.attack_likelihood * 100.0
  );
  println!(
    "  Classification:      {}",
    result.intelligence_report.final_classification
  );

  tokio::time::sleep(std::time::Duration::from_millis(800)).await;
  println!("\n\x1b[1;96m🧪 ATTACK SIMULATION:\x1b[0m");
  println!(
    "  Execution Path:      {} steps",
    result.attack_simulation.execution_path.len()
  );
  println!(
    "  State Transitions:   {} tracked",
    result.attack_simulation.state_transitions.len()
  );
  println!(
    "  Attacker Type:       {}",
    result.attack_simulation.attacker_model.attacker_type
  );
  println!(
    "  Exploit Status:      {}",
    result.attack_simulation.exploit_verdict.status
  );
  println!(
    "  Success Probability: {:.1}%",
    result.attack_simulation.exploit_verdict.success_probability * 100.0
  );
  println!(
    "  Replay ID:           {}",
    result.attack_simulation.replay_info.replay_id
  );

  tokio::time::sleep(std::time::Duration::from_millis(800)).await;
  println!("\n\x1b[1;96m📊 GRAPH CONSTRUCTION — ATTACK MAP ENGINE:\x1b[0m");
  println!("  Graph Nodes:         {}", result.attack_graph.nodes.len());
  println!("  Graph Edges:         {}", result.attack_graph.edges.len());
  println!("  Root Node:           {}", result.attack_graph.root_node);

  tokio::time::sleep(std::time::Duration::from_millis(800)).await;
  println!("\n\x1b[1;96m✅ CONSISTENCY VERIFICATION — GATEKEEPER:\x1b[0m");
  println!(
    "  Simulation Valid:    {}",
    if result.consistency_check.simulation_valid {
      "✅ PASS"
    } else {
      "❌ FAIL"
    }
  );
  println!(
    "  Graph Consistent:    {}",
    if result.consistency_check.graph_consistent {
      "✅ PASS"
    } else {
      "❌ FAIL"
    }
  );
  println!(
    "  State Correct:       {}",
    if result.consistency_check.state_correct {
      "✅ PASS"
    } else {
      "❌ FAIL"
    }
  );
  println!(
    "  Tool Conflict:       {}",
    if result.consistency_check.tool_conflict {
      "⚠️  YES"
    } else {
      "✅ NO"
    }
  );
  println!(
    "  Consistency Score:   {:.2}%",
    result.consistency_check.consistency_score * 100.0
  );

  tokio::time::sleep(std::time::Duration::from_millis(800)).await;
  println!("\n\x1b[1;96m🎯 FINAL DECISION — SOLE AUTHORITY:\x1b[0m");
  println!(
    "  Final Verdict:       {}",
    result.final_decision.final_verdict
  );
  println!(
    "  Final Confidence:    {:.2}%",
    result.final_decision.final_confidence * 100.0
  );
  println!(
    "  Final Attack Prob:   {:.2}%",
    result.final_decision.final_attack_probability * 100.0
  );
  println!(
    "  Final Risk Score:    {:.2}%",
    result.final_decision.final_risk_score * 100.0
  );

  tokio::time::sleep(std::time::Duration::from_millis(800)).await;
  println!("\n\x1b[1;96m🔐 ATTESTATION — CRYPTOGRAPHIC PROOF:\x1b[0m");
  println!("  Replay ID:           {}", result.attestation.replay_id);
  println!("  Seed:                {}", result.attestation.seed);
  println!(
    "  Trace Hash:          {}",
    result.attestation.execution_trace_hash
  );
  println!("  Timestamp:           {}", result.attestation.timestamp);
  println!(
    "  Verdict:             {}",
    result.attestation.final_verdict
  );

  tokio::time::sleep(std::time::Duration::from_millis(800)).await;
  println!("\n\x1b[1;35m[🧠 LLM EXPLANATION]\x1b[0m");
  println!("\x1b[97m{}\x1b[0m", result.explanation);

  println!("\n\x1b[36m╔════════════════════════════════════════════════════════════════════════════╗\x1b[0m");
  println!(
    "\x1b[36m║         AUTONOMOUS ENGINE — SOVEREIGN EXECUTION COMPLETE                   ║\x1b[0m"
  );
  println!(
    "\x1b[36m╠════════════════════════════════════════════════════════════════════════════╣\x1b[0m"
  );
  println!("\x1b[36m║\x1b[0m  \x1b[92m✓\x1b[0m Qdrant Vector DB — 782 exploit vectors across 2 collections             \x1b[36m║\x1b[0m");
  println!("\x1b[36m║\x1b[0m  \x1b[92m✓\x1b[0m OpenAI LLM — GPT-4o-mini + text-embedding-3-small                       \x1b[36m║\x1b[0m");
  println!("\x1b[36m║\x1b[0m  \x1b[92m✓\x1b[0m Stylus Contracts — AgentMemory + AuditReport on Arbitrum Sepolia        \x1b[36m║\x1b[0m");
  println!("\x1b[36m║\x1b[0m  \x1b[92m✓\x1b[0m 13-phase autonomous pipeline, full attestation                          \x1b[36m║\x1b[0m");
  println!(
    "\x1b[36m╚════════════════════════════════════════════════════════════════════════════╝\x1b[0m"
  );

  // ─── Append on-chain proof section to saved report ────────────────────────────
  let chain_proof = format!(
    "\n\n---\n\n## 🔗 On-Chain Proof (Arbitrum Sepolia Stylus)\n\n\
| Field | Value |\n\
|-------|-------|\n\
| Stylus AgentMemory — JSON Summary | `{}` |\n\
| Stylus AuditReport — Full Report  | `{}` |\n\
| Attestation Replay ID             | `{}` |\n\
| Execution Trace Hash              | `{}` |\n\
| Chain                             | [Arbitrum Sepolia (Chain 421614)](https://sepolia.arbiscan.io) |\n",
    if result.storage_root_hash.is_empty() { "—".to_string() } else { result.storage_root_hash.clone() },
    if result.report_root_hash.is_empty() { "—".to_string() } else { result.report_root_hash.clone() },
    result.attestation.replay_id,
    result.attestation.execution_trace_hash,
  );
  if let Err(e) = std::fs::OpenOptions::new()
    .append(true)
    .open(&report_path)
    .and_then(|mut f| {
      use std::io::Write;
      f.write_all(chain_proof.as_bytes())
    })
  {
    println!("[!] Could not append chain proof to report: {}", e);
  }

  Ok(())
}
