/*!
OpenAI Client — LLM inference interface for GPT-4o-mini / GPT-4.

OpenAI-compatible chat completions API.
Replaces 0G Compute (Qwen) for all reasoning and report generation.
*/

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// OpenAI client for LLM inference — same API as OgComputeClient for drop-in replacement.
#[derive(Clone)]
pub struct OpenAiClient {
  endpoint: String,
  model: String,
  api_key: String,
  http: Client,
}

#[derive(Serialize, Deserialize)]
struct ChatMessage {
  role: String,
  content: String,
}

#[derive(Serialize)]
struct ChatCompletionRequest {
  model: String,
  messages: Vec<ChatMessage>,
  #[serde(skip_serializing_if = "Option::is_none")]
  max_tokens: Option<u32>,
}

#[derive(Deserialize)]
struct ChatChoice {
  message: ChatMessage,
}

#[derive(Deserialize)]
struct ChatCompletionResponse {
  choices: Vec<ChatChoice>,
}

impl OpenAiClient {
  /// Create from env vars: OPENAI_API_KEY + OPENAI_MODEL (defaults to gpt-4o-mini).
  pub fn from_env() -> Result<Self> {
    let api_key = std::env::var("OPENAI_API_KEY").context("OPENAI_API_KEY not set in .env")?;
    let model = std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o-mini".to_string());

    Ok(Self {
      endpoint: "https://api.openai.com/v1/chat/completions".to_string(),
      model,
      api_key,
      http: Client::new(),
    })
  }

  /// Create with explicit config
  #[allow(dead_code)]
  pub fn new(api_key: String, model: String) -> Self {
    Self {
      endpoint: "https://api.openai.com/v1/chat/completions".to_string(),
      model,
      api_key,
      http: Client::new(),
    }
  }

  /// Run inference — returns the model's response text.
  /// max_tokens = 4096 (safe limit for GPT-4o-mini detailed reports).
  pub async fn infer(&self, prompt: &str) -> Result<String> {
    self.infer_with_max_tokens(prompt, Some(4096)).await
  }

  /// Run inference with custom max_tokens parameter.
  pub async fn infer_with_max_tokens(
    &self,
    prompt: &str,
    max_tokens: Option<u32>,
  ) -> Result<String> {
    let req = ChatCompletionRequest {
      model: self.model.clone(),
      messages: vec![
        ChatMessage {
          role: "system".to_string(),
          content: "You are a smart contract security expert.".to_string(),
        },
        ChatMessage {
          role: "user".to_string(),
          content: prompt.to_string(),
        },
      ],
      max_tokens,
    };

    let http_resp = self
      .http
      .post(&self.endpoint)
      .bearer_auth(&self.api_key)
      .json(&req)
      .send()
      .await
      .context("Failed to send inference request to OpenAI")?;

    if !http_resp.status().is_success() {
      let status = http_resp.status();
      let body = http_resp.text().await.unwrap_or_default();
      anyhow::bail!("OpenAI error {}: {}", status, body);
    }

    let resp: ChatCompletionResponse = http_resp
      .json()
      .await
      .context("Failed to parse OpenAI inference response")?;

    Ok(
      resp
        .choices
        .into_iter()
        .next()
        .map(|c| c.message.content)
        .unwrap_or_default(),
    )
  }

  pub fn model(&self) -> &str {
    &self.model
  }
}
