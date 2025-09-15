use cve_explorer_pro::{CVEFetcher, RootCauseAnalyzer, display_summary};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 CVE Explorer Pro - Basic Analysis Example");
    
    // Initialize the fetcher (without API key for this example)
    let fetcher = CVEFetcher::new(None);
    
    // Fetch a well-known CVE
    let cve_id = "CVE-2021-34527"; // PrintNightmare
    println!("📡 Fetching CVE data for {}", cve_id);
    
    match fetcher.fetch_cve(cve_id).await {
        Ok(cve) => {
            println!("✅ Successfully fetched CVE data");
            
            // Perform root cause analysis
            let analyzer = RootCauseAnalyzer;
            let analysis = analyzer.analyze_vulnerability(&cve);
            
            // Display summary
            display_summary(&cve, &analysis);
            
            // Show detailed analysis results
            println!("\n🔬 DETAILED ANALYSIS:");
            println!("Primary Cause: {:?}", analysis.primary_cause);
            println!("Contributing Factors: {}", analysis.contributing_factors.len());
            println!("Architectural Flaws: {}", analysis.architectural_flaws.len());
            println!("Prevention Recommendations: {}", analysis.prevention_recommendations.len());
        }
        Err(e) => {
            eprintln!("❌ Error fetching CVE: {}", e);
            eprintln!("💡 Note: This example uses mock data when the NVD API is unavailable");
        }
    }
    
    Ok(())
}