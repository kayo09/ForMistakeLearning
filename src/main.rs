use cve_explorer_pro::{
    Cli, CVEFetcher, RootCauseAnalyzer, ExploitationPathAnalyzer,
    display_summary, display_detailed_analysis, display_exploitation_analysis, display_full_analysis, display_json_output
};
use clap::Parser;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    println!("🔍 Analyzing CVE: {}", cli.cve);
    
    // Initialize fetcher
    let fetcher = CVEFetcher::new(cli.api_key.clone());
    
    // Fetch CVE data
    match fetcher.fetch_cve(&cli.cve).await {
        Ok(cve) => {
            println!("✅ Successfully fetched CVE data");
            
            match cli.mode.as_str() {
                "basic" => {
                    let analyzer = RootCauseAnalyzer;
                    let analysis = analyzer.analyze_vulnerability(&cve);
                    
                    match cli.format.as_str() {
                        "json" => display_json_output(&cve, Some(&analysis), None)?,
                        "summary" => display_summary(&cve, &analysis),
                        _ => display_detailed_analysis(&cve, &analysis),
                    }
                },
                "exploitation" => {
                    let exploitation_analyzer = ExploitationPathAnalyzer;
                    let exploitation_analysis = exploitation_analyzer.analyze_exploitation_path(&cve);
                    
                    match cli.format.as_str() {
                        "json" => display_json_output(&cve, None, Some(&exploitation_analysis))?,
                        _ => display_exploitation_analysis(&cve, &exploitation_analysis),
                    }
                },
                "full" => {
                    let analyzer = RootCauseAnalyzer;
                    let analysis = analyzer.analyze_vulnerability(&cve);
                    let exploitation_analyzer = ExploitationPathAnalyzer;
                    let exploitation_analysis = exploitation_analyzer.analyze_exploitation_path(&cve);
                    
                    match cli.format.as_str() {
                        "json" => display_json_output(&cve, Some(&analysis), Some(&exploitation_analysis))?,
                        _ => display_full_analysis(&cve, &analysis, &exploitation_analysis),
                    }
                },
                _ => {
                    eprintln!("❌ Invalid mode: {}. Use basic, exploitation, or full", cli.mode);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Error fetching CVE {}: {}", cli.cve, e);
            std::process::exit(1);
        }
    }
    
    Ok(())
}

