use thiserror::Error;

#[derive(Error, Debug)]
pub enum CVEError {
    #[error("Network request failed: {0}")]
    NetworkError(#[from] reqwest::Error),
    
    #[error("JSON parsing failed: {0}")]
    JsonError(#[from] serde_json::Error),
    
    #[error("CVE not found: {0}")]
    NotFound(String),
    
    #[error("Invalid CVE format: {0}")]
    InvalidFormat(String),
    
    #[error("Analysis failed: {0}")]
    AnalysisError(String),
    
    #[error("Database error: {0}")]
    DatabaseError(String),
}

