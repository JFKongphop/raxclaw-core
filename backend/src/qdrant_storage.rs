/*!
Qdrant Vector Database Client — fast semantic search for the 722-exploit RAG pipeline.

Replaces 0G Storage's in-memory cosine similarity with Qdrant's HNSW-indexed search.
Collections: defi_cases (vulnerability patterns) + defi_protocols (real exploits).

Every point stores a 1536-dim OpenAI embedding plus metadata payload.
Search queries both collections, merges, and returns top-k by score.

Env vars required:
  QDRANT_ENDPOINT   — e.g. https://xxx.cloud.qdrant.io
  QDRANT_API_KEY    — API key for cloud access
*/

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

// ─── Shared result type (same shape as og_storage::RemoteExploitResult) ──────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QdrantExploitResult {
  pub score: f64,
  pub exploit_name: String,
  pub vuln_type: String,
  pub chain: String,
  pub date: String,
  pub total_lost: String,
  pub source: String,
  pub code_snippet: String,
  pub attack_tx: String,
  pub embedding_dim: usize,
  pub collection: String,
}

// ─── Qdrant REST API types ────────────────────────────────────────────────────

#[derive(Serialize)]
struct SearchRequest {
  vector: Vec<f64>,
  limit: usize,
  #[serde(rename = "with_payload")]
  with_payload: bool,
}

#[derive(Deserialize)]
struct SearchResponse {
  result: Vec<ScoredPoint>,
}

#[derive(Deserialize)]
struct ScoredPoint {
  #[allow(dead_code)]
  id: serde_json::Value,
  score: f64,
  payload: Option<ExploitPayload>,
}

#[derive(Deserialize)]
struct ExploitPayload {
  exploit_name: Option<String>,
  vuln_type: Option<String>,
  chain: Option<String>,
  date: Option<String>,
  total_lost: Option<String>,
  source: Option<String>,
  code_snippet: Option<String>,
  attack_tx: Option<String>,
  embedding_dim: Option<usize>,
}

// ─── Client ───────────────────────────────────────────────────────────────────

/// Qdrant-backed vector search client.
/// Drop-in replacement for RemoteOgStorageClient — same `query` + `health` API.
#[derive(Clone)]
pub struct QdrantStorageClient {
  endpoint: String,
  api_key: String,
  http: reqwest::Client,
  collections: Vec<String>,
}

impl QdrantStorageClient {
  /// Create a new client from env vars.
  /// Reads QDRANT_ENDPOINT and QDRANT_API_KEY from environment.
  pub fn from_env() -> Result<Self> {
    let endpoint = std::env::var("QDRANT_ENDPOINT").context("QDRANT_ENDPOINT not set in .env")?;
    let api_key = std::env::var("QDRANT_API_KEY").context("QDRANT_API_KEY not set in .env")?;

    Ok(Self {
      endpoint: endpoint.trim_end_matches('/').to_string(),
      api_key,
      http: reqwest::Client::new(),
      collections: vec!["defi_cases".to_string(), "defi_protocols".to_string()],
    })
  }

  /// Create with explicit config
  pub fn new(endpoint: String, api_key: String) -> Self {
    Self {
      endpoint: endpoint.trim_end_matches('/').to_string(),
      api_key,
      http: reqwest::Client::new(),
      collections: vec!["defi_cases".to_string(), "defi_protocols".to_string()],
    }
  }

  /// Search both collections, merge by score, return top-k.
  pub async fn query(&self, embedding: &[f64], top_k: usize) -> Result<Vec<QdrantExploitResult>> {
    let mut all_results: Vec<QdrantExploitResult> = Vec::new();

    for collection in &self.collections {
      let url = format!("{}/collections/{}/points/search", self.endpoint, collection);

      let body = SearchRequest {
        vector: embedding.to_vec(),
        limit: top_k,
        with_payload: true,
      };

      let resp = self
        .http
        .post(&url)
        .header("api-key", &self.api_key)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await;

      match resp {
        Ok(r) if r.status().is_success() => {
          let data: SearchResponse = r.json().await.with_context(|| {
            format!(
              "Failed to parse Qdrant response for collection '{}'",
              collection
            )
          })?;

          for point in data.result {
            let payload = point.payload.unwrap_or(ExploitPayload {
              exploit_name: None,
              vuln_type: None,
              chain: None,
              date: None,
              total_lost: None,
              source: None,
              code_snippet: None,
              attack_tx: None,
              embedding_dim: None,
            });

            all_results.push(QdrantExploitResult {
              score: point.score,
              exploit_name: payload.exploit_name.unwrap_or_else(|| "Unknown".into()),
              vuln_type: payload.vuln_type.unwrap_or_else(|| "Unknown".into()),
              chain: payload.chain.unwrap_or_else(|| "Unknown".into()),
              date: payload.date.unwrap_or_else(|| "N/A".into()),
              total_lost: payload.total_lost.unwrap_or_else(|| "N/A".into()),
              source: payload.source.unwrap_or_else(|| "Unknown".into()),
              code_snippet: payload.code_snippet.unwrap_or_else(|| "N/A".into()),
              attack_tx: payload.attack_tx.unwrap_or_else(|| String::new()),
              embedding_dim: payload.embedding_dim.unwrap_or(1536),
              collection: collection.clone(),
            });
          }
        }
        Ok(r) => {
          let status = r.status();
          let body = r.text().await.unwrap_or_default();
          eprintln!(
            "[Qdrant]   Collection '{}' search returned {}: {}",
            collection,
            status,
            &body[..body.len().min(200)]
          );
        }
        Err(e) => {
          eprintln!(
            "[Qdrant]   Collection '{}' request failed: {}",
            collection, e
          );
        }
      }
    }

    // Sort by score descending, take top_k
    all_results.sort_by(|a, b| {
      b.score
        .partial_cmp(&a.score)
        .unwrap_or(std::cmp::Ordering::Equal)
    });
    all_results.truncate(top_k);

    println!(
      "[Qdrant]         Searched {} collections → {} total hits, returning top {}",
      self.collections.len(),
      all_results.len(),
      all_results.len().min(top_k)
    );

    Ok(all_results)
  }

  /// Health check — verify Qdrant is reachable and collections exist.
  pub async fn health(&self) -> Result<usize> {
    let url = format!("{}/collections", self.endpoint);

    let resp = self
      .http
      .get(&url)
      .header("api-key", &self.api_key)
      .send()
      .await
      .context("Failed to reach Qdrant — check QDRANT_ENDPOINT")?;

    if !resp.status().is_success() {
      let status = resp.status();
      let body = resp.text().await.unwrap_or_default();
      anyhow::bail!("Qdrant health check failed {}: {}", status, body);
    }

    // Count total points across both collections
    let mut total_points = 0usize;
    for collection in &self.collections {
      let coll_url = format!("{}/collections/{}", self.endpoint, collection);
      if let Ok(r) = self
        .http
        .get(&coll_url)
        .header("api-key", &self.api_key)
        .send()
        .await
      {
        if let Ok(data) = r.json::<serde_json::Value>().await {
          total_points += data["result"]["points_count"].as_u64().unwrap_or(0) as usize;
        }
      }
    }

    println!(
      "[Qdrant]   Connected — {} total points across {} collections",
      total_points,
      self.collections.len()
    );

    Ok(total_points)
  }
}
