use crate::models::*;
use crate::error::CVEError;
use reqwest::Client;
use anyhow::Result;
use chrono::{DateTime, Utc, TimeZone};
use serde_json::Value;

const NVD_API_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

pub struct CVEFetcher {
    client: Client,
    api_key: Option<String>,
}

impl CVEFetcher {
    pub fn new(api_key: Option<String>) -> Self {
        Self {
            client: Client::new(),
            api_key,
        }
    }

    pub async fn fetch_cve(&self, cve_id: &str) -> Result<CVE, CVEError> {
        let url = format!("{}?cveId={}", NVD_API_BASE, cve_id);
        
        let mut request = self.client.get(&url);
        
        if let Some(key) = &self.api_key {
            request = request.header("apiKey", key);
        }
        
        let response = request.send().await?;
        
        if !response.status().is_success() {
            return Err(CVEError::NotFound(cve_id.to_string()));
        }
        
        let json: Value = response.json().await?;
        
        self.parse_nvd_response(json, cve_id).await
    }

    // Helper function to parse datetime with milliseconds
    fn parse_nvd_datetime(&self, date_str: &str) -> Result<DateTime<Utc>, CVEError> {
        // Try parsing with milliseconds first
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(date_str, "%Y-%m-%dT%H:%M:%S%.3f") {
            return Ok(Utc.from_utc_datetime(&dt));
        }
        // Fallback to standard format without milliseconds
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(date_str, "%Y-%m-%dT%H:%M:%S") {
            return Ok(Utc.from_utc_datetime(&dt));
        }
        // Try RFC3339 format
        if let Ok(dt) = DateTime::parse_from_rfc3339(date_str) {
            return Ok(dt.with_timezone(&Utc));
        }
        
        Err(CVEError::InvalidFormat(format!("Failed to parse datetime: {}", date_str)))
    }

    async fn parse_nvd_response(&self, json: Value, cve_id: &str) -> Result<CVE, CVEError> {
        let vulns = json["vulnerabilities"]
            .as_array()
            .ok_or_else(|| CVEError::InvalidFormat("No vulnerabilities array".to_string()))?;

        if vulns.is_empty() {
            return Err(CVEError::NotFound(cve_id.to_string()));
        }

        let cve_data = &vulns[0]["cve"];

        // Extract basic metadata
        let id = cve_data["id"].as_str().unwrap_or("").to_string();
        
        let published_str = cve_data["published"].as_str()
            .ok_or_else(|| CVEError::InvalidFormat("Missing published date".into()))?;
        let published_date = self.parse_nvd_datetime(published_str)?;

        let last_modified_str = cve_data["lastModified"].as_str()
            .ok_or_else(|| CVEError::InvalidFormat("Missing last modified date".into()))?;
        let last_modified_date = self.parse_nvd_datetime(last_modified_str)?;

        // Description (English only)
        let description = cve_data["descriptions"]
            .as_array()
            .and_then(|descs| {
                descs.iter().find_map(|d| {
                    if d["lang"] == "en" {
                        Some(d["value"].as_str().unwrap_or("").to_string())
                    } else {
                        None
                    }
                })
            })
            .unwrap_or_default();

        // CVSS Score (prefer CVSS v3.1 primary, fallback to v3.0)
        let mut cvss: Option<CVSSScore> = None;
        
        if let Some(metrics) = cve_data["metrics"].as_object() {
            // Try CVSS v3.1 first
            if let Some(cvss_v31) = metrics.get("cvssMetricV31").and_then(|m| m.as_array()) {
                if let Some(primary_metric) = cvss_v31.iter().find(|m| m["type"] == "Primary") {
                    if let Some(cvss_data) = primary_metric.get("cvssData").and_then(|d| d.as_object()) {
                        let base_score = cvss_data.get("baseScore").and_then(|s| s.as_f64()).unwrap_or(0.0) as f32;
                        let vector_string = cvss_data.get("vectorString").and_then(|s| s.as_str()).unwrap_or("").to_string();
                        let severity = Severity::from(base_score);
                        
                        cvss = Some(CVSSScore {
                            base_score,
                            severity,
                            vector_string,
                        });
                    }
                }
            }
            // Fallback to CVSS v3.0
            else if let Some(cvss_v30) = metrics.get("cvssMetricV30").and_then(|m| m.as_array()) {
                if let Some(primary_metric) = cvss_v30.iter().find(|m| m["type"] == "Primary") {
                    if let Some(cvss_data) = primary_metric.get("cvssData").and_then(|d| d.as_object()) {
                        let base_score = cvss_data.get("baseScore").and_then(|s| s.as_f64()).unwrap_or(0.0) as f32;
                        let vector_string = cvss_data.get("vectorString").and_then(|s| s.as_str()).unwrap_or("").to_string();
                        let severity = Severity::from(base_score);
                        
                        cvss = Some(CVSSScore {
                            base_score,
                            severity,
                            vector_string,
                        });
                    }
                }
            }
            // Fallback to CVSS v2
            else if let Some(cvss_v2) = metrics.get("cvssMetricV2").and_then(|m| m.as_array()) {
                if let Some(primary_metric) = cvss_v2.iter().find(|m| m["type"] == "Primary") {
                    if let Some(cvss_data) = primary_metric.get("cvssData").and_then(|d| d.as_object()) {
                        let base_score = cvss_data.get("baseScore").and_then(|s| s.as_f64()).unwrap_or(0.0) as f32;
                        let vector_string = cvss_data.get("vectorString").and_then(|s| s.as_str()).unwrap_or("").to_string();
                        let severity = Severity::from(base_score);
                        
                        cvss = Some(CVSSScore {
                            base_score,
                            severity,
                            vector_string,
                        });
                    }
                }
            }
        }

        // References
        let references = cve_data["references"]
            .as_array()
            .map(|refs| {
                refs.iter()
                    .filter_map(|r| {
                        Some(Reference {
                            url: r["url"].as_str()?.to_string(),
                            name: r["url"].as_str().map(|s| s.to_string()), // Using URL as name fallback
                            source: r["source"].as_str().map(|s| s.to_string()),
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        // Vulnerable Configurations
        let vulnerable_configurations = cve_data["configurations"]
            .as_array()
            .map(|configs| {
                configs
                    .iter()
                    .flat_map(|config| config["nodes"].as_array())
                    .flatten()
                    .flat_map(|node| node["cpeMatch"].as_array())
                    .flatten()
                    .filter_map(|cpe_match| {
                        if cpe_match["vulnerable"].as_bool().unwrap_or(false) {
                            Some(VulnerableConfiguration {
                                cpe: cpe_match["criteria"].as_str()?.to_string(),
                                version_start: cpe_match["versionStartIncluding"]
                                    .as_str()
                                    .map(|s| s.to_string()),
                                version_end: cpe_match["versionEndExcluding"]
                                    .as_str()
                                    .or_else(|| cpe_match["versionEndIncluding"].as_str())
                                    .map(|s| s.to_string()),
                            })
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        // Exploitability (derived from CVSS data)
        let exploitability = {
            let (complexity, attack_vector, privileges_required, user_interaction) = 
                if cvss.is_some(){
                    // Extract from CVSS vector string or data
                    let cvss_data = if let Some(metrics) = cve_data["metrics"].as_object() {
                        if let Some(cvss_v31) = metrics.get("cvssMetricV31").and_then(|m| m.as_array()) {
                            if let Some(primary_metric) = cvss_v31.iter().find(|m| m["type"] == "Primary") {
                                primary_metric.get("cvssData").and_then(|d| d.as_object())
                            } else { None }
                        } else { None }
                    } else { None };

                    let complexity = if let Some(data) = &cvss_data {
                        match data.get("attackComplexity").and_then(|ac| ac.as_str()).unwrap_or("LOW") {
                            "HIGH" => ExploitComplexity::High,
                            _ => ExploitComplexity::Low,
                        }
                    } else {
                        ExploitComplexity::Low
                    };

                    let attack_vector = if let Some(data) = &cvss_data {
                        match data.get("attackVector").and_then(|av| av.as_str()).unwrap_or("NETWORK") {
                            "NETWORK" => AttackVector::Network,
                            "ADJACENT_NETWORK" => AttackVector::Adjacent,
                            "LOCAL" => AttackVector::Local,
                            "PHYSICAL" => AttackVector::Physical,
                            _ => AttackVector::Network,
                        }
                    } else {
                        AttackVector::Network
                    };

                    let privileges_required = if let Some(data) = &cvss_data {
                        match data.get("privilegesRequired").and_then(|pr| pr.as_str()).unwrap_or("NONE") {
                            "NONE" => PrivilegesRequired::None,
                            "LOW" => PrivilegesRequired::Low,
                            "HIGH" => PrivilegesRequired::High,
                            _ => PrivilegesRequired::None,
                        }
                    } else {
                        PrivilegesRequired::None
                    };

                    let user_interaction = if let Some(data) = &cvss_data {
                        data.get("userInteraction").and_then(|ui| ui.as_str()).unwrap_or("NONE") == "NONE"
                    } else {
                        true
                    };

                    (complexity, attack_vector, privileges_required, user_interaction)
                } else {
                    // Defaults if no CVSS data
                    (ExploitComplexity::Low, AttackVector::Network, PrivilegesRequired::None, false)
                };

            Exploitability {
                complexity,
                privileges_required,
                user_interaction,
                attack_vector,
                exploitation_steps: vec![
                    "Identify vulnerable system".to_string(),
                    "Craft malicious payload".to_string(),
                    "Execute attack".to_string(),
                ],
            }
        };

        // Remediation (basic stub - could be enhanced)
        let remediation = Remediation {
            patches: vec![], // No patch info in NVD API directly
            workarounds: vec![
                "Update to a non-vulnerable version".to_string(),
                "Apply vendor-supplied patches".to_string(),
            ],
            mitigation_strategies: vec![
                MitigationStrategy {
                    category: MitigationCategory::CodeChange,
                    description: "Validate and sanitize all user inputs used in logging".to_string(),
                    implementation_difficulty: DifficultyLevel::Moderate,
                    effectiveness: 0.9,
                },
                MitigationStrategy {
                    category: MitigationCategory::Configuration,
                    description: "Implement proper input validation and output encoding".to_string(),
                    implementation_difficulty: DifficultyLevel::Easy,
                    effectiveness: 0.8,
                },
            ],
        };

        Ok(CVE {
            id,
            description,
            publishedDate: published_date,
            lastModifiedDate: last_modified_date,
            cvss,
            references,
            vulnerable_configurations,
            exploitability,
            remediation,
        })
    }
}

