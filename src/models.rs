use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CVE{
    pub id: String,
    pub description: String,
    #[serde(rename = "publishedDate")]
    pub publishedDate: DateTime<Utc>,
    #[serde(rename = "lastModifiedDate")]
    pub lastModifiedDate: DateTime<Utc>,
    pub cvss: Option<CVSSScore>,
    pub references: Vec<Reference>,
    pub vulnerable_configurations: Vec<VulnerableConfiguration>,
    pub exploitability: Exploitability,
    pub remediation: Remediation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CVSSScore{
    pub base_score: f32,
    pub severity: Severity,
    pub vector_string: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl From<f32> for Severity {
    fn from(score: f32) -> Self {
        match score{
            0.0..=3.9 => Severity::Low,
            4.0..=6.9 => Severity::Medium,
            7.0..=8.9 => Severity::High,
            _ => Severity::Critical,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference{
    pub url: String,
    pub name: Option<String>,
    #[serde(rename = "refsource")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerableConfiguration{
    pub cpe: String,
    pub version_start: Option<String>,
    pub version_end: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exploitability {
    pub complexity: ExploitComplexity,
    pub privileges_required: PrivilegesRequired,
    pub user_interaction: bool,
    pub attack_vector: AttackVector,
    pub exploitation_steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ExploitComplexity {
    Low,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PrivilegesRequired {
    None,
    Low,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AttackVector {
    Network,
    Adjacent,
    Local,
    Physical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remediation {
    pub patches: Vec<PatchInfo>,
    pub workarounds: Vec<String>,
    pub mitigation_strategies: Vec<MitigationStrategy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchInfo {
    pub version: String,
    pub release_date: DateTime<Utc>,
    pub patch_url: String,
    pub quality_analysis: PatchQuality,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchQuality {
    pub completeness: f32, // 0.0 to 1.0
    pub regression_risk: f32, // 0.0 to 1.0
    pub performance_impact: f32, // 0.0 to 1.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationStrategy {
    pub category: MitigationCategory,
    pub description: String,
    pub implementation_difficulty: DifficultyLevel,
    pub effectiveness: f32, // 0.0 to 1.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MitigationCategory {
    CodeChange,
    Configuration,
    NetworkSecurity,
    Monitoring,
    Process,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DifficultyLevel {
    Easy,
    Moderate,
    Hard,
    Expert,
}

