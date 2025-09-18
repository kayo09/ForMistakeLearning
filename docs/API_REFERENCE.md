# CVE Explorer Pro API Reference v0.1.1

## Overview

This document provides a comprehensive reference for all public APIs in CVE Explorer Pro v0.1.1. The library is organized into several modules, each providing specific functionality for CVE analysis.

## Module Structure

```
cve_explorer_pro/
├── models/          # Core data structures
├── fetcher/         # CVE data fetching
├── analyzer/        # Root cause analysis
├── exploitation/    # Exploitation path analysis
└── error/          # Error handling
```

## Core Data Structures

### CVE

The primary data structure representing a Common Vulnerability and Exposure.

```rust
pub struct CVE {
    pub id: String,
    pub description: String,
    pub publishedDate: DateTime<Utc>,
    pub lastModifiedDate: DateTime<Utc>,
    pub cvss: Option<CVSSScore>,
    pub references: Vec<Reference>,
    pub vulnerable_configurations: Vec<VulnerableConfiguration>,
    pub exploitability: Exploitability,
    pub remediation: Remediation,
}
```

#### Fields

- **`id`**: CVE identifier (e.g., "CVE-2021-34527")
- **`description`**: Detailed vulnerability description from NVD
- **`publishedDate`**: When the CVE was first published
- **`lastModifiedDate`**: Last modification timestamp
- **`cvss`**: CVSS scoring information (optional)
- **`references`**: External references and links
- **`vulnerable_configurations`**: Affected software configurations
- **`exploitability`**: Exploitation characteristics
- **`remediation`**: Patch and mitigation information

### CVSSScore

CVSS (Common Vulnerability Scoring System) scoring information.

```rust
pub struct CVSSScore {
    pub base_score: f32,
    pub severity: Severity,
    pub vector_string: String,
}
```

#### Fields

- **`base_score`**: CVSS base score (0.0-10.0)
- **`severity`**: Severity level (Low, Medium, High, Critical)
- **`vector_string`**: CVSS vector string

### Severity

Enumeration of vulnerability severity levels.

```rust
pub enum Severity {
    Low,        // 0.0-3.9
    Medium,     // 4.0-6.9
    High,       // 7.0-8.9
    Critical,   // 9.0-10.0
}
```

### Exploitability

Information about how a vulnerability can be exploited.

```rust
pub struct Exploitability {
    pub complexity: ExploitComplexity,
    pub privileges_required: PrivilegesRequired,
    pub user_interaction: bool,
    pub attack_vector: AttackVector,
    pub exploitation_steps: Vec<String>,
}
```

#### Fields

- **`complexity`**: Exploitation complexity (Low, High)
- **`privileges_required`**: Required privilege level (None, Low, High)
- **`user_interaction`**: Whether user interaction is required
- **`attack_vector`**: Attack vector type (Network, Adjacent, Local, Physical)
- **`exploitation_steps`**: Steps needed for exploitation

## CVE Fetching

### CVEFetcher

Client for fetching CVE data from the NIST National Vulnerability Database.

```rust
pub struct CVEFetcher {
    // Internal implementation
}
```

#### Methods

##### `new(api_key: Option<String>) -> Self`

Creates a new CVE fetcher instance.

**Parameters:**
- `api_key`: Optional NVD API key for higher rate limits

**Returns:** New `CVEFetcher` instance

**Example:**
```rust
let fetcher = CVEFetcher::new(Some("your_api_key".to_string()));
```

##### `fetch_cve(cve_id: &str) -> Result<CVE, CVEError>`

Fetches CVE data from the NVD API.

**Parameters:**
- `cve_id`: CVE identifier (e.g., "CVE-2021-34527")

**Returns:** `Result<CVE, CVEError>`

**Errors:**
- `CVEError::NotFound`: CVE not found in database
- `CVEError::NetworkError`: Network connectivity issues
- `CVEError::ParseError`: Failed to parse response
- `CVEError::RateLimited`: API rate limit exceeded

**Example:**
```rust
match fetcher.fetch_cve("CVE-2021-34527").await {
    Ok(cve) => println!("Found CVE: {}", cve.id),
    Err(CVEError::NotFound) => println!("CVE not found"),
    Err(e) => eprintln!("Error: {}", e),
}
```

## Root Cause Analysis

### RootCauseAnalyzer

Performs root cause analysis to identify vulnerability origins.

```rust
pub struct RootCauseAnalyzer;
```

#### Methods

##### `analyze_vulnerability(cve: &CVE) -> RootCauseAnalysis`

Analyzes a CVE to determine root causes and contributing factors.

**Parameters:**
- `cve`: CVE data structure to analyze

**Returns:** `RootCauseAnalysis` containing analysis results

**Example:**
```rust
let analyzer = RootCauseAnalyzer;
let analysis = analyzer.analyze_vulnerability(&cve);
println!("Primary cause: {:?}", analysis.primary_cause);
```

### RootCauseAnalysis

Results of root cause analysis.

```rust
pub struct RootCauseAnalysis {
    pub primary_cause: VulnerabilityCategory,
    pub contributing_factors: Vec<ContributingFactor>,
    pub architectural_flaws: Vec<ArchitecturalFlaw>,
    pub development_process_issues: Vec<ProcessIssue>,
    pub prevention_recommendations: Vec<PreventionRecommendation>,
}
```

#### Fields

- **`primary_cause`**: Primary vulnerability category
- **`contributing_factors`**: Additional contributing factors
- **`architectural_flaws`**: Design-level security issues
- **`development_process_issues`**: Process-related problems
- **`prevention_recommendations`**: Suggested prevention measures

### VulnerabilityCategory

Primary vulnerability categories.

```rust
pub enum VulnerabilityCategory {
    InputValidation,
    MemoryManagement,
    Authentication,
    Authorization,
    Cryptography,
    ConfigurationManagement,
    SessionManagement,
    ErrorHandling,
    APIDesign,
    DataExposure,
    RaceCondition,
    ResourceManagement,
    CodeInjection,
    BusinessLogic,
    Unknown,
}
```

## Exploitation Analysis

### ExploitationPathAnalyzer

Analyzes exploitation paths and attack surfaces.

```rust
pub struct ExploitationPathAnalyzer;
```

#### Methods

##### `analyze_exploitation_path(cve: &CVE) -> ExploitationAnalysis`

Performs comprehensive exploitation path analysis.

**Parameters:**
- `cve`: CVE data structure to analyze

**Returns:** `ExploitationAnalysis` containing attack surface mapping

**Example:**
```rust
let exploit_analyzer = ExploitationPathAnalyzer;
let exploitation = exploit_analyzer.analyze_exploitation_path(&cve);
println!("Complexity: {:.1}/10", exploitation.exploitation_complexity.overall_score);
```

### ExploitationAnalysis

Results of exploitation path analysis.

```rust
pub struct ExploitationAnalysis {
    pub attack_surface: AttackSurface,
    pub exploitation_complexity: ExploitationComplexity,
    pub privilege_escalation_chain: Vec<PrivilegeEscalationStep>,
    pub poc_template: Option<PoCTemplate>,
    pub skill_requirements: Vec<SkillRequirement>,
    pub time_estimate: TimeEstimate,
}
```

#### Fields

- **`attack_surface`**: Available attack surface information
- **`exploitation_complexity`**: Complexity scoring
- **`privilege_escalation_chain`**: Steps for privilege escalation
- **`poc_template`**: Generated proof-of-concept template
- **`skill_requirements`**: Required skills for exploitation
- **`time_estimate`**: Estimated time for exploitation

### AttackSurface

Information about available attack surfaces.

```rust
pub struct AttackSurface {
    pub entry_points: Vec<EntryPoint>,
    pub trust_boundaries: Vec<TrustBoundary>,
    pub data_flow_paths: Vec<DataFlowPath>,
}
```

#### Fields

- **`entry_points`**: Available entry points for attacks
- **`trust_boundaries`**: Security boundaries that can be crossed
- **`data_flow_paths`**: Paths for data flow exploitation

### PoCTemplate

Generated proof-of-concept template.

```rust
pub struct PoCTemplate {
    pub language: String,
    pub framework: String,
    pub template_code: String,
    pub exploitation_steps: Vec<String>,
    pub safety_notes: Vec<String>,
    pub target_environment: String,
}
```

#### Fields

- **`language`**: Programming language (Python, Bash, etc.)
- **`framework`**: Framework or library used
- **`template_code`**: Generated template code
- **`exploitation_steps`**: Step-by-step exploitation guide
- **`safety_notes`**: Important safety considerations
- **`target_environment`**: Target environment description

## Error Handling

### CVEError

Comprehensive error enumeration for all library operations.

```rust
pub enum CVEError {
    NetworkError(String),
    ParseError(String),
    NotFound,
    RateLimited,
    InvalidInput(String),
    ApiError(String),
}
```

#### Variants

- **`NetworkError`**: Network connectivity issues
- **`ParseError`**: JSON parsing or data format errors
- **`NotFound`**: Requested CVE not found
- **`RateLimited`**: API rate limit exceeded
- **`InvalidInput`**: Invalid input parameters
- **`ApiError`**: API-specific errors

#### Error Handling Example

```rust
use cve_explorer_pro::CVEError;

match fetcher.fetch_cve(cve_id).await {
    Ok(cve) => {
        // Process CVE successfully
    }
    Err(CVEError::NetworkError(msg)) => {
        eprintln!("Network error: {}", msg);
        // Implement retry logic
    }
    Err(CVEError::RateLimited) => {
        eprintln!("Rate limited. Consider using an API key.");
        // Wait and retry
    }
    Err(CVEError::NotFound) => {
        eprintln!("CVE {} not found", cve_id);
    }
    Err(e) => {
        eprintln!("Unexpected error: {}", e);
    }
}
```

## Display Functions

### Summary Display

```rust
pub fn display_summary(cve: &CVE, analysis: &RootCauseAnalysis)
```

Displays a concise summary of CVE analysis results.

**Parameters:**
- `cve`: CVE data structure
- `analysis`: Root cause analysis results

### Detailed Analysis Display

```rust
pub fn display_detailed_analysis(cve: &CVE, analysis: &RootCauseAnalysis)
```

Displays comprehensive analysis results in human-readable format.

**Parameters:**
- `cve`: CVE data structure
- `analysis`: Root cause analysis results

### Exploitation Analysis Display

```rust
pub fn display_exploitation_analysis(cve: &CVE, exploitation: &ExploitationAnalysis)
```

Displays exploitation path analysis results.

**Parameters:**
- `cve`: CVE data structure
- `exploitation`: Exploitation analysis results

### JSON Output

```rust
pub fn display_json_output(
    cve: &CVE,
    analysis: Option<&RootCauseAnalysis>,
    exploitation: Option<&ExploitationAnalysis>
) -> Result<(), Box<dyn std::error::Error>>
```

Outputs analysis results in JSON format.

**Parameters:**
- `cve`: CVE data structure
- `analysis`: Optional root cause analysis results
- `exploitation`: Optional exploitation analysis results

**Returns:** `Result<(), Box<dyn std::error::Error>>`

## CLI Interface

### Cli

Command-line interface structure.

```rust
pub struct Cli {
    pub cve: String,
    pub mode: String,
    pub format: String,
    pub api_key: Option<String>,
}
```

#### Fields

- **`cve`**: CVE identifier to analyze
- **`mode`**: Analysis mode ("basic", "exploitation", "full")
- **`format`**: Output format ("json", "detailed", "summary")
- **`api_key`**: Optional NVD API key

## Usage Patterns

### Basic Analysis Workflow

```rust
use cve_explorer_pro::{CVEFetcher, RootCauseAnalyzer, display_summary};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create fetcher
    let fetcher = CVEFetcher::new(None);
    
    // 2. Fetch CVE data
    let cve = fetcher.fetch_cve("CVE-2021-34527").await?;
    
    // 3. Analyze vulnerability
    let analyzer = RootCauseAnalyzer;
    let analysis = analyzer.analyze_vulnerability(&cve);
    
    // 4. Display results
    display_summary(&cve, &analysis);
    
    Ok(())
}
```

### Full Analysis Workflow

```rust
use cve_explorer_pro::{
    CVEFetcher, RootCauseAnalyzer, ExploitationPathAnalyzer,
    display_json_output
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fetcher = CVEFetcher::new(std::env::var("NVD_API_KEY").ok());
    let cve = fetcher.fetch_cve("CVE-2021-34527").await?;
    
    // Perform both analyses
    let analyzer = RootCauseAnalyzer;
    let analysis = analyzer.analyze_vulnerability(&cve);
    
    let exploit_analyzer = ExploitationPathAnalyzer;
    let exploitation = exploit_analyzer.analyze_exploitation_path(&cve);
    
    // Output comprehensive results
    display_json_output(&cve, Some(&analysis), Some(&exploitation))?;
    
    Ok(())
}
```

## Rate Limiting and Best Practices

### API Rate Limits

- **Without API Key**: 5 requests per 30 seconds
- **With API Key**: 50 requests per 30 seconds

### Recommended Practices

1. **Use API Keys**: Always use an API key for production applications
2. **Implement Backoff**: Use exponential backoff for rate limit errors
3. **Cache Results**: Cache CVE data to minimize API calls
4. **Error Handling**: Always handle potential network and parsing errors
5. **Async Processing**: Use async/await for non-blocking operations

### Example with Rate Limiting

```rust
use cve_explorer_pro::{CVEFetcher, CVEError};
use tokio::time::{sleep, Duration};

async fn fetch_with_retry(fetcher: &CVEFetcher, cve_id: &str, max_retries: u32) -> Result<CVE, CVEError> {
    let mut retries = 0;
    
    loop {
        match fetcher.fetch_cve(cve_id).await {
            Ok(cve) => return Ok(cve),
            Err(CVEError::RateLimited) if retries < max_retries => {
                let delay = Duration::from_secs(2_u64.pow(retries));
                sleep(delay).await;
                retries += 1;
            }
            Err(e) => return Err(e),
        }
    }
}
```

---

*CVE Explorer Pro v0.1.1 API Reference - Complete reference for security analysis automation*