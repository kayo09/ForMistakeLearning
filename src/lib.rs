//! # CVE Explorer Pro
//!
//! A comprehensive Rust library for deep CVE vulnerability analysis and exploitation path exploration.
//!
//! This library provides tools for:
//! - Fetching CVE data from the NIST National Vulnerability Database
//! - Performing root cause analysis of vulnerabilities
//! - Analyzing exploitation paths and attack surfaces
//! - Generating proof-of-concept templates
//! - Producing detailed security reports
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use cve_explorer_pro::{CVEFetcher, RootCauseAnalyzer};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let fetcher = CVEFetcher::new(None);
//! let cve = fetcher.fetch_cve("CVE-2021-34527").await?;
//!
//! let analyzer = RootCauseAnalyzer;
//! let analysis = analyzer.analyze_vulnerability(&cve);
//!
//! println!("Primary cause: {:?}", analysis.primary_cause);
//! # Ok(())
//! # }
//! ```
//!
//! ## Modules
//!
//! - [`models`]: Core data structures for CVE information
//! - [`fetcher`]: CVE data fetching from external APIs
//! - [`analyzer`]: Root cause analysis functionality
//! - [`exploitation`]: Exploitation path analysis
//! - [`error`]: Error handling types

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

#[derive(Parser)]
#[command(name = "cve-explorer")]
#[command(about = "Deep dive CVE analysis tool", long_about = None)]
pub struct Cli {
    /// CVE identifier (e.g., CVE-2021-34527)
    #[arg(short, long)]
    pub cve: String,

    /// Analysis mode (basic, exploitation, full)
    #[arg(short, long, default_value = "basic")]
    pub mode: String,

    /// Output format (json, detailed, summary)
    #[arg(short, long, default_value = "detailed")]
    pub format: String,

    /// NVD API key for higher rate limits
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

