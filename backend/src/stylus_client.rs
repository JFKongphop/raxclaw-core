//! Stylus Contract Client — on-chain long-context memory via Arbitrum Sepolia.
//! Matches stylus/caller/src/bin/ pattern exactly.

use alloy::{
  network::EthereumWallet,
  primitives::{Address, U256},
  providers::ProviderBuilder,
  signers::local::PrivateKeySigner,
  sol,
};
use anyhow::Context;
use std::str::FromStr;

sol! {
  #[sol(rpc)]
  interface IAgentMemory {
    function pushMemory(uint256 tokenId, bytes calldata summaryJson, string calldata description) external;
    function getMemoryData(uint256 tokenId, uint256 index) external view returns (bytes memory);
    function memoryCount(uint256 tokenId) external view returns (uint256);
  }

  #[sol(rpc)]
  interface IAuditReport {
    function createAudit(string calldata contractName) external returns (uint256 taskId);
    function finalizeAudit(uint256 taskId, uint8 riskLevel, uint64 confidence, string calldata vulnType, bytes calldata reportMarkdown) external;
    function getReport(uint256 taskId) external view returns (bytes memory);
    function recordCount() external view returns (uint256);
  }
}

pub struct StylusClient {
  wallet: EthereumWallet,
  rpc_url: String,
  agent_memory_addr: Address,
  audit_report_addr: Address,
  agent_token_id: U256,
}

impl StylusClient {
  pub async fn from_env() -> anyhow::Result<Self> {
    let rpc = std::env::var("ARBITRUM_SEPOLIA").context("ARBITRUM_SEPOLIA not set")?;
    let pk = std::env::var("PRIVATE_KEY").context("PRIVATE_KEY not set")?;
    let signer = PrivateKeySigner::from_str(&pk)?;
    let wallet = EthereumWallet::from(signer);

    Ok(Self {
      wallet,
      rpc_url: rpc,
      agent_memory_addr: std::env::var("AGENT_MEMORY")
        .context("AGENT_MEMORY not set")?
        .parse()?,
      audit_report_addr: std::env::var("AUDIT_REPORT")
        .context("AUDIT_REPORT not set")?
        .parse()?,
      agent_token_id: U256::from_str(
        &std::env::var("AGENT_TOKEN_ID").unwrap_or_else(|_| "0".to_string()),
      )
      .unwrap_or(U256::ZERO),
    })
  }

  async fn connect(&self) -> anyhow::Result<impl alloy::providers::Provider> {
    Ok(
      ProviderBuilder::new()
        .wallet(self.wallet.clone())
        .connect(&self.rpc_url)
        .await?,
    )
  }

  pub async fn push_memory(&self, json: &str, desc: &str) -> anyhow::Result<String> {
    let provider = self.connect().await?;
    let c = IAgentMemory::new(self.agent_memory_addr, &provider);
    let r = c
      .pushMemory(
        self.agent_token_id,
        json.as_bytes().to_vec().into(),
        desc.to_string(),
      )
      .send()
      .await?
      .get_receipt()
      .await?;
    println!(
      "\x1b[94m[Memory]\x1b[0m         Pushed             | TX: 0x{:x}",
      r.transaction_hash
    );
    Ok(format!("0x{:x}", r.transaction_hash))
  }

  pub async fn read_all_memory(&self) -> anyhow::Result<Vec<(U256, String)>> {
    let provider = self.connect().await?;
    let c = IAgentMemory::new(self.agent_memory_addr, &provider);
    let total = c.memoryCount(self.agent_token_id).call().await?;
    let mut entries = Vec::new();
    for i in 0..total.min(U256::from(50)).to::<u64>() {
      if let Ok(bytes) = c
        .getMemoryData(self.agent_token_id, U256::from(i))
        .call()
        .await
      {
        entries.push((U256::from(i), String::from_utf8_lossy(&bytes).to_string()));
      }
    }
    Ok(entries)
  }

  pub async fn create_audit_task(&self, name: &str) -> anyhow::Result<U256> {
    let provider = self.connect().await?;
    let c = IAuditReport::new(self.audit_report_addr, &provider);
    let current = c.recordCount().call().await?;
    let r = c
      .createAudit(name.to_string())
      .send()
      .await?
      .get_receipt()
      .await?;
    println!(
      "\x1b[35m[AuditReport]\x1b[0m    Task #{} created   | TX: 0x{:x}",
      current, r.transaction_hash
    );
    Ok(current)
  }

  pub async fn finalize_audit(
    &self,
    tid: U256,
    risk: u8,
    conf: u64,
    vtype: &str,
    report: &str,
  ) -> anyhow::Result<String> {
    let provider = self.connect().await?;
    let c = IAuditReport::new(self.audit_report_addr, &provider);
    let r = c
      .finalizeAudit(
        tid,
        risk,
        conf,
        vtype.to_string(),
        report.as_bytes().to_vec().into(),
      )
      .send()
      .await?
      .get_receipt()
      .await?;
    println!(
      "\x1b[35m[AuditReport]\x1b[0m    Task #{} finalized | TX: 0x{:x}",
      tid, r.transaction_hash
    );
    Ok(format!("0x{:x}", r.transaction_hash))
  }

  pub async fn get_report(&self, tid: U256) -> anyhow::Result<String> {
    let provider = self.connect().await?;
    let c = IAuditReport::new(self.audit_report_addr, &provider);
    let result = c.getReport(tid).call().await?;
    Ok(String::from_utf8_lossy(&result).to_string())
  }
}
