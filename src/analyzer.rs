use crate::models::*;
use serde::Serialize;
use std::collections::HashMap;

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
        // Detailed analysis based on CVSS vector and vulnerability characteristics
        if let Some(cvss) = &cve.cvss {
            let vector = &cvss.vector_string;
            
            // Remote Code Execution patterns
            if vector.contains("I:H") && vector.contains("C:H") && vector.contains("AV:N") {
                if vector.contains("AC:L") && vector.contains("PR:N") && vector.contains("UI:N") {
                    return PrimaryCause::RemoteCodeExecution;
                }
            }
            
            // SQL Injection patterns
            if vector.contains("C:H") && vector.contains("I:H") && vector.contains("AC:L") {
                if self.description_indicates_sql_injection(&cve.description) {
                    return PrimaryCause::SqlInjection;
                }
            }
            
            // XSS patterns
            if vector.contains("C:L") && vector.contains("I:L") && vector.contains("S:C") {
                if self.description_indicates_xss(&cve.description) {
                    return PrimaryCause::CrossSiteScripting;
                }
            }
            
            // Buffer Overflow patterns
            if vector.contains("A:H") && vector.contains("AC:L") {
                if self.description_indicates_buffer_overflow(&cve.description) {
                    return PrimaryCause::BufferOverflow;
                }
            }
            
            // Path Traversal patterns
            if vector.contains("C:H") && vector.contains("AV:N") {
                if self.description_indicates_path_traversal(&cve.description) {
                    return PrimaryCause::PathTraversal;
                }
            }
            
            // Authentication Bypass patterns
            if vector.contains("C:H") && vector.contains("PR:N") {
                if self.description_indicates_auth_bypass(&cve.description) {
                    return PrimaryCause::AuthenticationBypass;
                }
            }
            
            // CSRF patterns
            if vector.contains("UI:R") && vector.contains("C:L") && vector.contains("I:L") {
                if self.description_indicates_csrf(&cve.description) {
                    return PrimaryCause::CrossSiteRequestForgery;
                }
            }
            
            // Deserialization patterns
            if vector.contains("I:H") && vector.contains("C:H") {
                if self.description_indicates_deserialization(&cve.description) {
                    return PrimaryCause::InsecureDeserialization;
                }
            }
        }
        
        // Fallback to exploitability-based determination
        match (&cve.exploitability.attack_vector, &cve.exploitability.privileges_required) {
            (AttackVector::Network, PrivilegesRequired::None) => {
                if cve.exploitability.complexity == ExploitComplexity::Low {
                    PrimaryCause::RemoteCodeExecution
                } else {
                    PrimaryCause::InputValidation
                }
            },
            (AttackVector::Network, _) => PrimaryCause::AuthenticationBypass,
            (AttackVector::Local, _) => PrimaryCause::PrivilegeEscalation,
            (AttackVector::Adjacent, _) => PrimaryCause::NetworkPropagation,
            (AttackVector::Physical, _) => PrimaryCause::PhysicalAccess,
        }
    }

    fn description_indicates_sql_injection(&self, description: &str) -> bool {
        let indicators = ["sql injection", "sql query", "database query", "execute arbitrary sql"];
        indicators.iter().any(|&indicator| 
            description.to_lowercase().contains(indicator)
        )
    }

    fn description_indicates_xss(&self, description: &str) -> bool {
        let indicators = ["cross site scripting", "xss", "script injection", "javascript execution"];
        indicators.iter().any(|&indicator| 
            description.to_lowercase().contains(indicator)
        )
    }

    fn description_indicates_buffer_overflow(&self, description: &str) -> bool {
        let indicators = ["buffer overflow", "memory corruption", "stack overflow", "heap overflow"];
        indicators.iter().any(|&indicator| 
            description.to_lowercase().contains(indicator)
        )
    }

    fn description_indicates_path_traversal(&self, description: &str) -> bool {
        let indicators = ["path traversal", "directory traversal", "file inclusion", "../"];
        indicators.iter().any(|&indicator| 
            description.to_lowercase().contains(indicator)
        )
    }

    fn description_indicates_auth_bypass(&self, description: &str) -> bool {
        let indicators = ["authentication bypass", "authorization bypass", "access control", "privilege escalation"];
        indicators.iter().any(|&indicator| 
            description.to_lowercase().contains(indicator)
        )
    }

    fn description_indicates_csrf(&self, description: &str) -> bool {
        let indicators = ["csrf", "cross-site request forgery", "request forgery"];
        indicators.iter().any(|&indicator| 
            description.to_lowercase().contains(indicator)
        )
    }

    fn description_indicates_deserialization(&self, description: &str) -> bool {
        let indicators = ["deserialization", "object deserialization", "unsafe deserialization"];
        indicators.iter().any(|&indicator| 
            description.to_lowercase().contains(indicator)
        )
    }

    fn identify_contributing_factors(&self, cve: &CVE) -> Vec<ContributingFactor> {
        let mut factors = Vec::new();
        let mut factor_weights = HashMap::new();
        
        // Analyze exploitability characteristics
        match cve.exploitability.complexity {
            ExploitComplexity::Low => {
                factor_weights.insert(ContributingFactor::PoorSecurityDesign, 3);
                factor_weights.insert(ContributingFactor::InadequateTesting, 2);
            }
            ExploitComplexity::High => {
                factor_weights.insert(ContributingFactor::InadequateTesting, 3);
                factor_weights.insert(ContributingFactor::LackOfDefenseInDepth, 2);
            }
        }
        
        // Check user interaction requirement
        if !cve.exploitability.user_interaction {
            factor_weights.insert(ContributingFactor::LackOfDefenseInDepth, 3);
        } else {
            factor_weights.insert(ContributingFactor::SocialEngineering, 2);
        }
        
        // Analyze CVSS data
        if let Some(cvss) = &cve.cvss {
            // High severity indicates serious issues
            if cvss.base_score >= 9.0 {
                factor_weights.insert(ContributingFactor::OutdatedDependencies, 3);
                factor_weights.insert(ContributingFactor::InadequateArchitecture, 3);
            } else if cvss.base_score >= 7.0 {
                factor_weights.insert(ContributingFactor::PoorSecurityDesign, 2);
            }
            
            // Network accessibility increases risk
            if cvss.vector_string.contains("AV:N") {
                factor_weights.insert(ContributingFactor::ExposedServices, 3);
            }
            
            // No privileges required indicates broad exposure
            if cvss.vector_string.contains("PR:N") {
                factor_weights.insert(ContributingFactor::WeakAccessControl, 3);
            }
            
            // No user interaction makes exploitation easier
            if cvss.vector_string.contains("UI:N") {
                factor_weights.insert(ContributingFactor::LackOfUserAwareness, 2);
            }
        }
        
        // Check vulnerable configurations
        if !cve.vulnerable_configurations.is_empty() {
            factor_weights.insert(ContributingFactor::ConfigurationError, 3);
            if cve.vulnerable_configurations.len() > 5 {
                factor_weights.insert(ContributingFactor::InadequateConfigurationManagement, 3);
            }
        }
        
        // Check references for additional clues
        let reference_count = cve.references.len();
        if reference_count > 10 {
            factor_weights.insert(ContributingFactor::WellKnownVulnerability, 2);
        }
        
        // Convert weighted factors to list, sorted by weight
        let mut weighted_factors: Vec<(ContributingFactor, i32)> = factor_weights.into_iter().collect();
        weighted_factors.sort_by(|a, b| b.1.cmp(&a.1));
        
        // Take top factors (at least 2, at most 5)
        let factor_count = weighted_factors.len().min(5).max(2);
        for (factor, _) in weighted_factors.into_iter().take(factor_count) {
            factors.push(factor);
        }
        
        if factors.is_empty() {
            factors.push(ContributingFactor::PoorSecurityDesign);
        }
        
        factors
    }

    fn analyze_architecture(&self, cve: &CVE) -> Vec<ArchitecturalFlaw> {
        let mut flaws = Vec::new();
        
        // Analyze vulnerable configurations for specific architectural issues
        let config_count = cve.vulnerable_configurations.len();
        if config_count > 0 {
            let impact_description = if config_count == 1 {
                "Single vulnerable configuration identified".to_string()
            } else {
                format!("{} vulnerable configurations identified, indicating widespread exposure", config_count)
            };
            
            flaws.push(ArchitecturalFlaw {
                category: ArchitectureCategory::TrustBoundaryViolation,
                description: impact_description,
                impact_level: if config_count > 5 { 
                    ImpactLevel::Critical 
                } else if config_count > 2 { 
                    ImpactLevel::High 
                } else { 
                    ImpactLevel::Medium 
                },
            });
        }
        
        // Analyze attack vector for architecture implications
        match &cve.exploitability.attack_vector {
            AttackVector::Network => {
                flaws.push(ArchitecturalFlaw {
                    category: ArchitectureCategory::InsecureCommunication,
                    description: "Network-based attack vector indicates potential for remote exploitation across network boundaries".to_string(),
                    impact_level: ImpactLevel::Critical,
                });
                
                // Check if it's a web application vulnerability
                if self.description_indicates_web_vuln(&cve.description) {
                    flaws.push(ArchitecturalFlaw {
                        category: ArchitectureCategory::WebApplicationSecurity,
                        description: "Web application vulnerability exposes front-end and back-end integration points".to_string(),
                        impact_level: ImpactLevel::High,
                    });
                }
            },
            AttackVector::Adjacent => {
                flaws.push(ArchitecturalFlaw {
                    category: ArchitectureCategory::WeakAccessControl,
                    description: "Adjacent network attack vector suggests inadequate network segmentation".to_string(),
                    impact_level: ImpactLevel::High,
                });
            },
            AttackVector::Local => {
                flaws.push(ArchitecturalFlaw {
                    category: ArchitectureCategory::PoorIsolation,
                    description: "Local attack vector indicates insufficient process and user isolation".to_string(),
                    impact_level: ImpactLevel::Medium,
                });
            },
            AttackVector::Physical => {
                flaws.push(ArchitecturalFlaw {
                    category: ArchitectureCategory::PhysicalSecurity,
                    description: "Physical attack vector indicates inadequate physical security controls".to_string(),
                    impact_level: ImpactLevel::Medium,
                });
            },
        }
        
        // Check for privilege escalation opportunities
        if cve.exploitability.privileges_required != PrivilegesRequired::None {
            flaws.push(ArchitecturalFlaw {
                category: ArchitectureCategory::PrivilegeSeparation,
                description: "Privilege requirements indicate potential for privilege escalation chains".to_string(),
                impact_level: ImpactLevel::High,
            });
        }
        
        // Analyze CVSS for specific architectural weaknesses
        if let Some(cvss) = &cve.cvss {
            if cvss.vector_string.contains("S:C") {
                flaws.push(ArchitecturalFlaw {
                    category: ArchitectureCategory::ScopeControl,
                    description: "Changed scope indicates vulnerability can affect other components beyond the vulnerable one".to_string(),
                    impact_level: ImpactLevel::High,
                });
            }
        }
        
        flaws
    }

    fn description_indicates_web_vuln(&self, description: &str) -> bool {
        let indicators = ["web application", "http", "html", "javascript", "browser", "web server"];
        indicators.iter().any(|&indicator| 
            description.to_lowercase().contains(indicator)
        )
    }

    fn analyze_development_process(&self, cve: &CVE) -> Vec<ProcessIssue> {
        let mut issues = Vec::new();
        
        // Analyze timeline for process issues
        let days_between = (cve.lastModifiedDate - cve.publishedDate).num_days();
        if days_between > 730 {
            // Over 2 years between publication and last modification
            issues.push(ProcessIssue {
                category: ProcessCategory::PatchManagement,
                description: format!("Significant delay ({days_between} days) between initial publication and last modification, indicating slow vulnerability response", days_between = days_between),
                recommendation: "Implement faster vulnerability triage and patch deployment procedures with SLA tracking".to_string(),
            });
        } else if days_between > 365 {
            issues.push(ProcessIssue {
                category: ProcessCategory::PatchManagement,
                description: format!("Moderate delay ({days_between} days) in addressing vulnerability updates", days_between = days_between),
                recommendation: "Establish regular vulnerability review cycles and automated patch management".to_string(),
            });
        }
        
        // Analyze severity for development process implications
        if let Some(cvss) = &cve.cvss {
            if cvss.base_score >= 9.0 {
                issues.push(ProcessIssue {
                    category: ProcessCategory::ThreatModeling,
                    description: "Critical vulnerability indicates fundamental design flaws were not caught during threat modeling".to_string(),
                    recommendation: "Integrate comprehensive threat modeling into architecture review processes".to_string(),
                });
            } else if cvss.base_score >= 7.0 {
                issues.push(ProcessIssue {
                    category: ProcessCategory::CodeReview,
                    description: "High-severity vulnerability suggests insufficient security-focused code review practices".to_string(),
                    recommendation: "Implement mandatory security code reviews and automated static analysis tools".to_string(),
                });
            }
        }
        
        // Check number of references for awareness issues
        if cve.references.len() > 15 {
            issues.push(ProcessIssue {
                category: ProcessCategory::SecurityAwareness,
                description: "Extensive documentation and references suggest this is a well-known vulnerability that should have been prevented".to_string(),
                recommendation: "Improve developer security training and establish secure coding standards".to_string(),
            });
        }
        
        // Generic process improvement suggestion
        issues.push(ProcessIssue {
            category: ProcessCategory::SecurityTesting,
            description: "Vulnerability indicates gaps in automated and manual security testing coverage".to_string(),
            recommendation: "Expand security testing to include dynamic analysis, penetration testing, and dependency scanning".to_string(),
        });
        
        issues
    }

    fn generate_prevention_recommendations(&self, cve: &CVE) -> Vec<PreventionRecommendation> {
        let mut recommendations = Vec::new();
        
        // Base recommendations on CVSS score and vector
        if let Some(cvss) = &cve.cvss {
            let priority = if cvss.base_score >= 9.0 {
                Priority::Critical
            } else if cvss.base_score >= 7.0 {
                Priority::High
            } else if cvss.base_score >= 4.0 {
                Priority::Medium
            } else {
                Priority::Low
            };
            
            let severity_context = if cvss.base_score >= 9.0 {
                "critical"
            } else if cvss.base_score >= 7.0 {
                "high"
            } else if cvss.base_score >= 4.0 {
                "medium"
            } else {
                "low"
            };
            
            // Specific recommendations based on vulnerability type
            match self.identify_primary_cause(cve) {
                PrimaryCause::SqlInjection => {
                    recommendations.push(PreventionRecommendation {
                        category: PreventionCategory::SecureCoding,
                        priority: priority.clone(),
                        description: format!("Implement parameterized queries and input validation to prevent SQL injection in {}-severity contexts", severity_context).to_string(),
                        implementation_guide: "Use prepared statements with parameterized queries. Validate and sanitize all user inputs. Employ ORM frameworks with built-in protection.".to_string(),
                    });
                },
                PrimaryCause::CrossSiteScripting => {
                    recommendations.push(PreventionRecommendation {
                        category: PreventionCategory::SecureCoding,
                        priority: priority.clone(),
                        description: format!("Implement context-aware output encoding to prevent XSS in {}-severity contexts", severity_context).to_string(),
                        implementation_guide: "Use contextual output encoding libraries. Implement Content Security Policy (CSP). Validate and sanitize user inputs.".to_string(),
                    });
                },
                PrimaryCause::BufferOverflow => {
                    recommendations.push(PreventionRecommendation {
                        category: PreventionCategory::SecureCoding,
                        priority: priority.clone(),
                        description: format!("Implement memory-safe programming practices to prevent buffer overflows in {}-severity contexts", severity_context).to_string(),
                        implementation_guide: "Use memory-safe languages when possible. Implement stack canaries, ASLR, and DEP. Perform bounds checking on all buffer operations.".to_string(),
                    });
                },
                PrimaryCause::PathTraversal => {
                    recommendations.push(PreventionRecommendation {
                        category: PreventionCategory::SecureCoding,
                        priority: priority.clone(),
                        description: format!("Implement path canonicalization and access controls to prevent path traversal in {}-severity contexts", severity_context).to_string(),
                        implementation_guide: "Canonicalize file paths before processing. Implement strict allowlists for accessible files. Validate file paths against expected directories.".to_string(),
                    });
                },
                PrimaryCause::AuthenticationBypass => {
                    recommendations.push(PreventionRecommendation {
                        category: PreventionCategory::AccessControl,
                        priority: priority.clone(),
                        description: format!("Implement robust authentication and session management to prevent bypass in {}-severity contexts", severity_context).to_string(),
                        implementation_guide: "Use strong authentication mechanisms. Implement proper session management. Enforce access controls at every layer.".to_string(),
                    });
                },
                PrimaryCause::CrossSiteRequestForgery => {
                    recommendations.push(PreventionRecommendation {
                        category: PreventionCategory::WebSecurity,
                        priority: priority.clone(),
                        description: format!("Implement anti-CSRF tokens and same-site cookies to prevent CSRF in {}-severity contexts", severity_context).to_string(),
                        implementation_guide: "Use synchronized tokens pattern. Implement same-site cookie attributes. Validate referrer headers for additional protection.".to_string(),
                    });
                },
                PrimaryCause::InsecureDeserialization => {
                    recommendations.push(PreventionRecommendation {
                        category: PreventionCategory::SecureCoding,
                        priority: priority.clone(),
                        description: format!("Avoid deserializing untrusted data or implement signing/integrity checks in {}-severity contexts", severity_context).to_string(),
                        implementation_guide: "Never deserialize untrusted data. Use safe serialization formats. Implement digital signatures for serialized data.".to_string(),
                    });
                },
                _ => {
                    // Generic input validation recommendation
                    recommendations.push(PreventionRecommendation {
                        category: PreventionCategory::SecureCoding,
                        priority: priority.clone(),
                        description: format!("Implement comprehensive input validation and sanitization appropriate for {}-severity vulnerabilities", severity_context).to_string(),
                        implementation_guide: "Use allow-list validation for all user-controlled inputs. Implement proper output encoding. Apply defense-in-depth principles.".to_string(),
                    });
                }
            }
            
            // Network security for network-based attacks
            if cvss.vector_string.contains("AV:N") {
                recommendations.push(PreventionRecommendation {
                    category: PreventionCategory::NetworkSecurity,
                    priority: priority.clone(),
                    description: format!("Implement network segmentation and access controls appropriate for {}-severity network vulnerabilities", severity_context).to_string(),
                    implementation_guide: "Deploy firewalls, IDS/IPS systems, and network microsegmentation. Implement zero-trust network architecture.".to_string(),
                });
            }
            
            // Monitoring for critical/high vulnerabilities
            if cvss.base_score >= 7.0 {
                recommendations.push(PreventionRecommendation {
                    category: PreventionCategory::Monitoring,
                    priority: Priority::High,
                    description: "Enhance monitoring and alerting for exploitation attempts of high-severity vulnerabilities".to_string(),
                    implementation_guide: "Implement log analysis with SIEM tools. Set up real-time alerts for suspicious activities. Conduct regular security audits.".to_string(),
                });
            }
            
            // Defense in depth for vulnerabilities requiring no privileges
            if cvss.vector_string.contains("PR:N") {
                recommendations.push(PreventionRecommendation {
                    category: PreventionCategory::ArchitectureHardening,
                    priority: Priority::High,
                    description: "Implement defense-in-depth controls to protect against unauthenticated attacks".to_string(),
                    implementation_guide: "Layer security controls throughout the architecture. Implement multi-factor authentication. Use application-level firewalls.".to_string(),
                });
            }
        }
        
        // Generic process improvement recommendation
        recommendations.push(PreventionRecommendation {
            category: PreventionCategory::ProcessImprovement,
            priority: Priority::Medium,
            description: "Establish comprehensive security development lifecycle (SDL) practices".to_string(),
            implementation_guide: "Integrate security into every phase of development. Conduct regular threat modeling. Implement security champions program.".to_string(),
        });
        
        recommendations
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
    SqlInjection,
    CrossSiteScripting,
    InputValidation,
    AuthenticationBypass,
    AuthorizationFailure,
    PrivilegeEscalation,
    CrossSiteRequestForgery,
    InsecureDeserialization,
    RemoteCodeExecution,
    NetworkPropagation,
    RaceCondition,
    CryptographicWeakness,
    ConfigurationError,
    PathTraversal,
    PhysicalAccess,
    Unknown,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
pub enum ContributingFactor {
    PoorSecurityDesign,
    InadequateTesting,
    LackOfDefenseInDepth,
    OutdatedDependencies,
    InsufficientMonitoring,
    ConfigurationError,
    ExposedServices,
    WeakAccessControl,
    SocialEngineering,
    LackOfUserAwareness,
    InadequateArchitecture,
    WellKnownVulnerability,
    InadequateConfigurationManagement,
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
    WebApplicationSecurity,
    PrivilegeSeparation,
    ScopeControl,
    PhysicalSecurity,
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
    SecurityAwareness,
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
    NetworkSecurity,
    Monitoring,
    IncidentResponse,
    AccessControl,
    WebSecurity,
}

#[derive(Debug, Clone, Serialize)]
pub enum Priority {
    Low,
    Medium,
    High,
    Critical,
}
