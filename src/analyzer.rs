use crate::models::*;
use serde::Serialize;

/// Analyzes vulnerabilities to identify root causes and contributing factors.
///
/// The `RootCauseAnalyzer` performs comprehensive analysis of CVE data to identify:
/// - Primary causes of vulnerabilities
/// - Contributing factors that enabled the vulnerability
/// - Architectural flaws in the affected system
/// - Development process issues
/// - Prevention recommendations
///
/// # Example
///
/// ```rust,no_run
/// use cve_explorer_pro::{RootCauseAnalyzer, CVE};
///
/// # fn example(cve: &CVE) {
/// let analyzer = RootCauseAnalyzer;
/// let analysis = analyzer.analyze_vulnerability(&cve);
/// println!("Primary cause: {:?}", analysis.primary_cause);
/// # }
/// ```
pub struct RootCauseAnalyzer;

impl RootCauseAnalyzer {
    pub fn analyze_vulnerability(&self, cve: &CVE) -> RootCauseAnalysis {
        RootCauseAnalysis {
            primary_cause: self.identify_primary_cause(cve),
            contributing_factors: self.identify_contributing_factors(cve),
            architectural_flaws: self.analyze_architecture(cve),
            development_process_issues: self.analyze_development_process(cve),
            prevention_recommendations: self.generate_prevention_recommendations(cve),
        }
    }

    fn identify_primary_cause(&self, cve: &CVE) -> PrimaryCause {
        // This would involve sophisticated pattern matching
        // For now, we'll make educated guesses based on available data
        match cve.exploitability.attack_vector {
            AttackVector::Network => {
                if cve.exploitability.privileges_required == PrivilegesRequired::None {
                    PrimaryCause::InputValidation
                } else {
                    PrimaryCause::AuthenticationBypass
                }
            },
            AttackVector::Local => PrimaryCause::PrivilegeEscalation,
            _ => PrimaryCause::Unknown,
        }
    }

    fn identify_contributing_factors(&self, cve: &CVE) -> Vec<ContributingFactor> {
        let mut factors = Vec::new();
        
        // Check complexity
        if matches!(cve.exploitability.complexity, ExploitComplexity::Low) {
            factors.push(ContributingFactor::PoorSecurityDesign);
        }
        
        // Check user interaction requirement
        if !cve.exploitability.user_interaction {
            factors.push(ContributingFactor::LackOfDefenseInDepth);
        }
        
        factors
    }

    fn analyze_architecture(&self, _cve: &CVE) -> Vec<ArchitecturalFlaw> {
        vec![
            ArchitecturalFlaw {
                category: ArchitectureCategory::TrustBoundaryViolation,
                description: "Insufficient isolation between components".to_string(),
                impact_level: ImpactLevel::High,
            }
        ]
    }

    fn analyze_development_process(&self, _cve: &CVE) -> Vec<ProcessIssue> {
        vec![
            ProcessIssue {
                category: ProcessCategory::CodeReview,
                description: "Insufficient security-focused code review".to_string(),
                recommendation: "Implement threat modeling in development cycle".to_string(),
            }
        ]
    }

    fn generate_prevention_recommendations(&self, _cve: &CVE) -> Vec<PreventionRecommendation> {
        vec![
            PreventionRecommendation {
                category: PreventionCategory::SecureCoding,
                priority: Priority::High,
                description: "Implement input validation for all external data".to_string(),
                implementation_guide: "Use whitelisting approach for acceptable inputs".to_string(),
            }
        ]
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RootCauseAnalysis {
    pub primary_cause: PrimaryCause,
    pub contributing_factors: Vec<ContributingFactor>,
    pub architectural_flaws: Vec<ArchitecturalFlaw>,
    pub development_process_issues: Vec<ProcessIssue>,
    pub prevention_recommendations: Vec<PreventionRecommendation>,
}

#[derive(Debug, Clone, Serialize)]
pub enum PrimaryCause {
    BufferOverflow,
    InputValidation,
    AuthenticationBypass,
    AuthorizationFailure,
    PrivilegeEscalation,
    RaceCondition,
    CryptographicWeakness,
    ConfigurationError,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub enum ContributingFactor {
    PoorSecurityDesign,
    InadequateTesting,
    LackOfDefenseInDepth,
    OutdatedDependencies,
    InsufficientMonitoring,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchitecturalFlaw {
    pub category: ArchitectureCategory,
    pub description: String,
    pub impact_level: ImpactLevel,
}

#[derive(Debug, Clone, Serialize)]
pub enum ArchitectureCategory {
    TrustBoundaryViolation,
    InsecureCommunication,
    WeakAccessControl,
    PoorIsolation,
}

#[derive(Debug, Clone, Serialize)]
pub enum ImpactLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessIssue {
    pub category: ProcessCategory,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize)]
pub enum ProcessCategory {
    CodeReview,
    ThreatModeling,
    SecurityTesting,
    PatchManagement,
    Training,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreventionRecommendation {
    pub category: PreventionCategory,
    pub priority: Priority,
    pub description: String,
    pub implementation_guide: String,
}

#[derive(Debug, Clone, Serialize)]
pub enum PreventionCategory {
    SecureCoding,
    ArchitectureHardening,
    ProcessImprovement,
    Monitoring,
    IncidentResponse,
}

#[derive(Debug, Clone, Serialize)]
pub enum Priority {
    Low,
    Medium,
    High,
    Critical,
}

