# CVE Explorer Pro

🔍 **A comprehensive Rust library for deep CVE vulnerability analysis and exploitation path exploration**

[![Crates.io](https://img.shields.io/crates/v/cve_explorer_pro.svg)](https://crates.io/crates/cve_explorer_pro)
[![Documentation](https://docs.rs/cve_explorer_pro/badge.svg)](https://docs.rs/cve_explorer_pro)
[![Build Status](https://github.com/kayo09/cve_explorer_pro/workflows/CI/badge.svg)](https://github.com/kayo09/ForMistakeLearning/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🚀 Features

- **Deep CVE Analysis**: Comprehensive vulnerability analysis with root cause identification
- **Exploitation Path Mapping**: Detailed attack surface analysis and privilege escalation chains
- **Multiple Output Formats**: JSON, detailed reports, and summary views
- **NVD Integration**: Seamless integration with NIST's National Vulnerability Database
- **Proof of Concept Generation**: Automated PoC template creation for security research
- **Risk Assessment**: CVSS scoring with contextual severity analysis

## 📦 Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
cve_explorer_pro = "0.1.0"
```

Or install the CLI tool:

```bash
cargo install cve_explorer_pro
```

## 🔧 Usage

### As a Library

```rust
use cve_explorer_pro::{CVEFetcher, RootCauseAnalyzer, ExploitationPathAnalyzer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the fetcher
    let fetcher = CVEFetcher::new(Some("your_nvd_api_key".to_string()));
    
    // Fetch CVE data
    let cve = fetcher.fetch_cve("CVE-2021-34527").await?;
    
    // Perform root cause analysis
    let analyzer = RootCauseAnalyzer;
    let analysis = analyzer.analyze_vulnerability(&cve);
    
    // Analyze exploitation paths
    let exploit_analyzer = ExploitationPathAnalyzer;
    let exploitation = exploit_analyzer.analyze_exploitation_path(&cve);
    
    println!("Primary Cause: {:?}", analysis.primary_cause);
    println!("Exploitation Complexity: {:.1}", exploitation.exploitation_complexity.overall_score);
    
    Ok(())
}
```

### As a CLI Tool

```bash
# Basic analysis
cve_explorer_pro -c CVE-2021-34527 -m basic

# Full exploitation analysis
cve_explorer_pro -c CVE-2021-34527 -m exploitation -f detailed

# Complete analysis with JSON output
cve_explorer_pro -c CVE-2021-34527 -m full -f json --api-key YOUR_API_KEY
```

## 📚 Core Components

### CVE Fetcher
Retrieves vulnerability data from the National Vulnerability Database (NVD).

### Root Cause Analyzer
Identifies primary causes, contributing factors, and architectural flaws:
- Input validation failures
- Authentication bypasses
- Privilege escalation vectors
- Configuration errors

### Exploitation Path Analyzer
Maps attack surfaces and exploitation complexity:
- Entry point identification
- Trust boundary analysis
- Privilege escalation chains
- Impact propagation assessment

## 🎯 Analysis Types

### Basic Mode
- CVE metadata and description
- CVSS scoring and severity assessment
- Primary vulnerability cause identification
- Prevention recommendations

### Exploitation Mode
- Attack surface mapping
- Entry point analysis
- Privilege escalation paths
- Exploitation complexity scoring
- PoC template generation

### Full Mode
- Complete root cause analysis
- Comprehensive exploitation assessment
- Architectural flaw identification
- Development process recommendations

## 📊 Output Formats

### Detailed Report
Human-readable analysis with emojis and structured sections.

### JSON Output
Machine-readable format for integration with other tools:

```json
{
  "cve": {
    "id": "CVE-2021-34527",
    "description": "...",
    "cvss": {
      "base_score": 8.8,
      "severity": "High"
    }
  },
  "root_cause_analysis": {
    "primary_cause": "PrivilegeEscalation",
    "contributing_factors": ["PoorSecurityDesign"]
  },
  "exploitation_analysis": {
    "exploitation_complexity": {
      "overall_score": 2.5,
      "difficulty_level": "Intermediate"
    }
  }
}
```

### Summary View
Concise overview with key findings and recommendations.

## 🛡️ Security Considerations

This tool is designed for:
- ✅ Security research and education
- ✅ Vulnerability assessment and remediation
- ✅ Risk analysis and threat modeling
- ✅ Security awareness training

**⚠️ Important**: Use only in authorized environments. Always follow responsible disclosure practices.

## 🔑 API Key Setup

Get your free NVD API key from [NIST](https://nvd.nist.gov/developers/request-an-api-key):

```bash
export NVD_API_KEY="your-api-key-here"
cve_explorer_pro -c CVE-2021-34527 --api-key $NVD_API_KEY
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📋 Requirements

- Rust 1.70.0 or later
- Internet connection for NVD API access
- Optional: NVD API key for higher rate limits

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [NIST National Vulnerability Database](https://nvd.nist.gov/) for CVE data
- The Rust community for excellent crates and tools
- Security researchers who responsibly disclose vulnerabilities

## 📞 Contact

**Krutarth Parmar**
- GitHub: [@kayo09](https://github.com/kayo09)
- Email: thisiskay@kayparmar[dot]com

---

⭐ If you find this project helpful, please consider giving it a star!
