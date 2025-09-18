//! # CVE Explorer Pro v0.1.1
//!
//! A comprehensive Rust library for deep CVE vulnerability analysis and exploitation path exploration.
//!
//! ## Overview
//!
//! CVE Explorer Pro provides sophisticated tools for cybersecurity professionals to analyze Common 
//! Vulnerabilities and Exposures (CVE) with unprecedented depth. The library combines automated data 
//! fetching, intelligent root cause analysis, and detailed exploitation path mapping to deliver 
//! actionable security insights.
//!
//! ## Core Features
//!
//! - **🔍 CVE Data Fetching**: Seamless integration with NIST's National Vulnerability Database (NVD)
//! - **🧠 Root Cause Analysis**: Advanced algorithmic analysis to identify vulnerability origins
//! - **🎯 Exploitation Path Mapping**: Detailed attack surface and privilege escalation analysis
//! - **🛡️ Security Assessment**: CVSS scoring with contextual risk evaluation
//! - **📊 Multiple Output Formats**: JSON, detailed reports, and executive summaries
//! - **🔧 Proof-of-Concept Generation**: Automated security testing template creation
//!
//! ## Quick Start
//!
//! ### Basic CVE Analysis
//!
//! ```rust,no_run
//! use cve_explorer_pro::{CVEFetcher, RootCauseAnalyzer};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Initialize fetcher (optionally with NVD API key for higher rate limits)
//! let fetcher = CVEFetcher::new(None);
//! 
//! // Fetch CVE data
//! let cve = fetcher.fetch_cve("CVE-2021-34527").await?;
//!
//! // Perform root cause analysis
//! let analyzer = RootCauseAnalyzer;
//! let analysis = analyzer.analyze_vulnerability(&cve);
//!
//! println!("Primary cause: {:?}", analysis.primary_cause);
//! println!("CVSS Score: {:.1}", cve.cvss.as_ref().unwrap().base_score);
//! # Ok(())
//! # }
//! ```
//!
//! ### Exploitation Path Analysis
//!
//! ```rust,no_run
//! use cve_explorer_pro::{CVEFetcher, ExploitationPathAnalyzer};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let fetcher = CVEFetcher::new(None);
//! let cve = fetcher.fetch_cve("CVE-2021-34527").await?;
//!
//! // Analyze exploitation paths
//! let exploit_analyzer = ExploitationPathAnalyzer;
//! let exploitation = exploit_analyzer.analyze_exploitation_path(&cve);
//!
//! println!("Attack Surface Entry Points: {}", exploitation.attack_surface.entry_points.len());
//! println!("Exploitation Complexity: {:.1}/10", exploitation.exploitation_complexity.overall_score);
//! # Ok(())
//! # }
//! ```
//!
//! ## Architecture
//!
//! The library is organized into several specialized modules:
//!
//! - [`models`]: Core data structures representing CVE information, CVSS scores, and analysis results
//! - [`fetcher`]: HTTP client for retrieving CVE data from the NIST NVD API with rate limiting
//! - [`analyzer`]: Root cause analysis engine with pattern recognition and categorization
//! - [`exploitation`]: Exploitation path analysis with attack surface mapping and complexity scoring
//! - [`error`]: Comprehensive error handling with detailed error contexts
//!
//! ## Analysis Types
//!
//! ### Root Cause Analysis
//! 
//! Identifies the fundamental causes of vulnerabilities through:
//! - Primary cause categorization (Input Validation, Memory Management, etc.)
//! - Contributing factor analysis
//! - Architectural flaw detection
//! - Development process issue identification
//!
//! ### Exploitation Path Analysis
//!
//! Maps potential attack vectors including:
//! - Attack surface enumeration
//! - Entry point identification
//! - Trust boundary analysis
//! - Privilege escalation path mapping
//! - Proof-of-concept template generation
//!
//! ## Version 0.1.1 Changes
//!
//! - **Code Quality**: Removed mock-up code for improved reliability
//! - **Stability**: Enhanced error handling and edge case management
//! - **Performance**: Optimized analysis algorithms
//! - **Documentation**: Comprehensive API documentation and examples

pub mod models;
pub mod error;
pub mod fetcher;
pub mod analyzer;
pub mod exploitation;

pub use models::*;
pub use error::*;
pub use fetcher::*;
pub use analyzer::*;
pub use exploitation::*;

use clap::Parser;

/// Command-line interface for CVE Explorer Pro.
///
/// This structure defines the command-line arguments and options available
/// when using CVE Explorer Pro as a CLI tool.
///
/// ## Usage Examples
///
/// Basic analysis:
/// ```bash
/// cve-explorer --cve CVE-2021-34527
/// ```
///
/// Exploitation analysis with JSON output:
/// ```bash
/// cve-explorer --cve CVE-2021-34527 --mode exploitation --format json
/// ```
///
/// Full analysis with API key:
/// ```bash
/// cve-explorer --cve CVE-2021-34527 --mode full --api-key YOUR_NVD_KEY
/// ```
#[derive(Parser)]
#[command(name = "cve-explorer")]
#[command(about = "Deep dive CVE analysis tool with advanced exploitation path mapping", long_about = None)]
#[command(version = "0.1.1")]
pub struct Cli {
    /// CVE identifier to analyze (e.g., CVE-2021-34527, CVE-2020-1472)
    /// 
    /// The CVE ID should follow the standard format: CVE-YYYY-NNNN
    /// where YYYY is the year and NNNN is the sequence number.
    #[arg(short, long)]
    pub cve: String,

    /// Analysis mode to execute
    /// 
    /// Available modes:
    /// - `basic`: Root cause analysis and basic vulnerability assessment
    /// - `exploitation`: Attack surface mapping and exploitation path analysis
    /// - `full`: Complete analysis including both root cause and exploitation paths
    #[arg(short, long, default_value = "basic")]
    pub mode: String,

    /// Output format for results
    /// 
    /// Available formats:
    /// - `json`: Machine-readable JSON output for integration
    /// - `detailed`: Human-readable detailed analysis report
    /// - `summary`: Concise overview with key findings
    #[arg(short, long, default_value = "detailed")]
    pub format: String,

    /// NVD API key for enhanced rate limits and priority access
    /// 
    /// Register at <https://nvd.nist.gov/developers/request-an-api-key>
    /// to obtain a free API key for higher rate limits (50 requests/30 seconds
    /// vs 5 requests/30 seconds without key).
    #[arg(long)]
    pub api_key: Option<String>,
}

/// Displays a concise summary of CVE analysis results.
///
/// This function provides a brief overview including:
/// - CVE ID and publication date
/// - Primary vulnerability cause
/// - CVSS severity rating
/// - Key prevention recommendations
///
/// # Arguments
///
/// * `cve` - The CVE data structure
/// * `analysis` - Root cause analysis results
///
/// # Example
///
/// ```rust,no_run
/// # use cve_explorer_pro::{CVE, RootCauseAnalysis, display_summary};
/// # fn example(cve: &CVE, analysis: &RootCauseAnalysis) {
/// display_summary(&cve, &analysis);
/// # }
/// ```
pub fn display_summary(cve: &CVE, analysis: &RootCauseAnalysis) {
    println!("\n📋 CVE SUMMARY");
    println!("ID: {}", cve.id);
    println!("Published: {}", cve.publishedDate.format("%Y-%m-%d"));
    println!("Primary Cause: {:?}", analysis.primary_cause);
    println!("Severity: {:?}", cve.cvss.as_ref().map(|c| &c.severity));
    
    println!("\n🔧 PREVENTION RECOMMENDATIONS");
    for rec in &analysis.prevention_recommendations {
        println!("- {} ({:?})", rec.description, rec.priority);
    }
}

pub fn display_detailed_analysis(cve: &CVE, analysis: &RootCauseAnalysis) {
    println!("\n🔬 DETAILED CVE ANALYSIS");
    println!("═══════════════════════════");
    
    println!("\n📄 CVE Details:");
    println!("  ID: {}", cve.id);
    println!("  Published: {}", cve.publishedDate.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("  Last Modified: {}", cve.lastModifiedDate.format("%Y-%m-%d %H:%M:%S UTC"));
    
    if let Some(cvss) = &cve.cvss {
        println!("  CVSS Score: {:.1} ({:?})", cvss.base_score, cvss.severity);
        println!("  Vector: {}", cvss.vector_string);
    }
    
    println!("\n🐛 PRIMARY CAUSE:");
    println!("  {:?}", analysis.primary_cause);
    
    println!("\n🔍 CONTRIBUTING FACTORS:");
    for factor in &analysis.contributing_factors {
        println!("  • {:?}", factor);
    }
    
    println!("\n🏗️  ARCHITECTURAL FLAWS:");
    for flaw in &analysis.architectural_flaws {
        println!("  • {:?}: {} (Impact: {:?})", 
            flaw.category, flaw.description, flaw.impact_level);
    }
    
    println!("\n📝 DEVELOPMENT PROCESS ISSUES:");
    for issue in &analysis.development_process_issues {
        println!("  • {:?}: {} -> {}", 
            issue.category, issue.description, issue.recommendation);
    }
    
    println!("\n🛡️  PREVENTION RECOMMENDATIONS:");
    for rec in &analysis.prevention_recommendations {
        println!("  [{:?}] {:?} - {}", 
            rec.priority, rec.category, rec.description);
        println!("    Implementation: {}", rec.implementation_guide);
    }
}

pub fn display_exploitation_analysis(_cve: &CVE, analysis: &ExploitationAnalysis) {
    println!("\n💣 EXPLOITATION PATH ANALYSIS");
    println!("══════════════════════════════");
    
    println!("\n🎯 ATTACK SURFACE");
    for entry_point in &analysis.attack_surface.entry_points {
        println!("  🔌 {}{}", 
            format!("{:?}", entry_point.interface_type), 
            if let Some(proto) = &entry_point.protocol {
                format!(" ({})", proto)
            } else {
                "".to_string()
            }
        );
        println!("     Auth Required: {}", entry_point.authentication_required);
        println!("     Description: {}", entry_point.description);
    }
    
    println!("\n🔒 TRUST BOUNDARIES");
    for boundary in &analysis.attack_surface.trust_boundaries {
        println!("  🛡️  {}", boundary.name);
        println!("     Protection: {}", boundary.protection_mechanism);
        println!("     Bypass Technique: {}", boundary.bypass_technique);
    }
    
    println!("\n⛓️  PRIVILEGE ESCALATION CHAIN");
    for step in &analysis.privilege_escalation_chain {
        println!("  {}. {} → {}", step.step_number, step.current_privilege, step.gained_privilege);
        println!("     Technique: {}", step.technique);
    }
    
    println!("\n📊 EXPLOITATION COMPLEXITY");
    println!("  Overall Score: {:.1}", analysis.exploitation_complexity.overall_score);
    println!("  Difficulty: {:?}", analysis.exploitation_complexity.difficulty_level);
    println!("  Estimated Time: {}-{} hours (typically {})",
        analysis.exploitation_complexity.time_estimate.min_hours,
        analysis.exploitation_complexity.time_estimate.max_hours,
        analysis.exploitation_complexity.time_estimate.typical_hours
    );
    
    println!("\n🛠️  REQUIRED SKILLS");
    for skill in &analysis.exploitation_complexity.required_skills {
        println!("  • {} ({:?})", skill.skill, skill.proficiency_required);
    }
    
    println!("\n🧪 PROOF OF CONCEPT TEMPLATE");
    println!("  Language: {}", analysis.proof_of_concept_framework.language);
    println!("  Framework: {}", analysis.proof_of_concept_framework.framework);
    println!("  Safety Notes:");
    for note in &analysis.proof_of_concept_framework.safety_notes {
        println!("    {}", note);
    }
    
    println!("\n🚀 EXPLOITATION STEPS:");
    for (i, step) in analysis.proof_of_concept_framework.exploitation_steps.iter().enumerate() {
        println!("  {}. {}", i + 1, step);
    }
}

pub fn display_full_analysis(
    cve: &CVE, 
    root_cause: &RootCauseAnalysis,
    exploitation: &ExploitationAnalysis
) {
    display_detailed_analysis(cve, root_cause);
    display_exploitation_analysis(cve, exploitation);
}

pub fn display_json_output(
    cve: &CVE, 
    root_cause: Option<&RootCauseAnalysis>,
    exploitation: Option<&ExploitationAnalysis>
) -> anyhow::Result<()> {
    let output = serde_json::json!({
        "cve": cve,
        "root_cause_analysis": root_cause,
        "exploitation_analysis": exploitation
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

