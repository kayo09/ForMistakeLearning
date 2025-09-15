use cve_explorer_pro::{CVEFetcher, RootCauseAnalyzer, ExploitationPathAnalyzer, display_json_output};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("📄 CVE Explorer Pro - JSON Output Example");
    
    // Initialize components
    let fetcher = CVEFetcher::new(None);
    
    // Fetch CVE data
    let cve_id = "CVE-2021-34527";
    println!("📡 Fetching {}", cve_id);
    
    match fetcher.fetch_cve(cve_id).await {
        Ok(cve) => {
            println!("✅ CVE data fetched");
            
            // Perform both types of analysis
            let analyzer = RootCauseAnalyzer;
            let analysis = analyzer.analyze_vulnerability(&cve);
            
            let exploit_analyzer = ExploitationPathAnalyzer;
            let exploitation = exploit_analyzer.analyze_exploitation_path(&cve);
            
            println!("\n📊 Complete analysis in JSON format:");
            println!("{}", "=".repeat(50));
            
            // Display as JSON
            display_json_output(&cve, Some(&analysis), Some(&exploitation))?;
            
            println!("{}", "=".repeat(50));
            println!("✅ JSON output complete");
            
            // Show some key statistics
            println!("\n📈 ANALYSIS SUMMARY:");
            println!("  Root Cause Factors: {}", analysis.contributing_factors.len());
            println!("  Prevention Recommendations: {}", analysis.prevention_recommendations.len());
            println!("  Exploitation Entry Points: {}", exploitation.attack_surface.entry_points.len());
            println!("  Complexity Score: {:.1}/10", exploitation.exploitation_complexity.overall_score);
            
        }
        Err(e) => {
            eprintln!("❌ Error: {}", e);
        }
    }
    
    Ok(())
}