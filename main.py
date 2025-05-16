import sys
import concurrent.futures
from typing import Dict, Any, Tuple, List, Optional
from modules.basic_scan.network_scan import scan_network
from modules.mitm_scan.arp_analyzer import arp_analysis
from modules.mitm_scan.dns_analyzer import analyze_dns_behavior
from modules.rogue_ap_scan.bssid_analyzer import analyze_bssids
from modules.rogue_ap_scan.ssid_analyzer import analyze_ssids

def run_with_error_check(analysis_func, analysis_name: str) -> Tuple[str, Dict[str, Any]]:

    try:
        result = analysis_func()
        if isinstance(result, dict) and "error" in result:
            return f"Error in {analysis_name}: {result['error']}", {}
        return "", result
    except Exception as e:
        return f"Exception in {analysis_name}: {str(e)}", {}

def format_section(title: str, data: Dict[str, Any]) -> str:

    output = [f"\n{title}:"]
    for key, value in data.items():
        # Format complex values for better readability
        if isinstance(value, dict) and len(str(value)) > 100:
            output.append(f"{key}: <complex data, length {len(str(value))} chars>")
        elif isinstance(value, list) and len(str(value)) > 100:
            output.append(f"{key}: <list with {len(value)} items>")
        else:
            output.append(f"{key}: {value}")
    return "\n".join(output)

def main() -> int:

    print("WiFi Sentry - Network Security Analysis")
    print("Running scans in parallel...\n")
    
    analyses = [
        (scan_network, "Network Scan"),
        (arp_analysis, "ARP Analysis"),
        (lambda: analyze_dns_behavior(type="detailed"), "DNS Analysis"),
        (analyze_ssids, "SSID Analysis"),
        (analyze_bssids, "BSSID Analysis")
    ]
    
    results = {}
    errors = []
    
    # Run analyses in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        # Submit all tasks
        future_to_analysis = {
            executor.submit(run_with_error_check, func, name): name 
            for func, name in analyses
        }
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_analysis):
            analysis_name = future_to_analysis[future]
            try:
                error, result = future.result()
                if error:
                    errors.append(error)
                else:
                    results[analysis_name] = result
                    print(f"✓ {analysis_name} completed")
            except Exception as e:
                errors.append(f"Exception processing {analysis_name} result: {str(e)}")
    
    # Check if any analyses failed
    if errors:
        for error in errors:
            print(error)
        return 1
    
    # Check if all required analyses completed successfully
    required_analyses = {"Network Scan", "ARP Analysis", "DNS Analysis", "SSID Analysis", "BSSID Analysis"}
    missing_analyses = required_analyses - set(results.keys())
    
    if missing_analyses:
        print(f"Error: Missing results for {', '.join(missing_analyses)}")
        return 1
    
    # Generate and display detailed report
    network_info = results["Network Scan"]
    arp_info = results["ARP Analysis"]
    dns_info = results["DNS Analysis"]
    ssid_info = results["SSID Analysis"]
    bssid_info = results["BSSID Analysis"]
    
    # Output network information
    print(format_section("Network Information", {
        "SSID": network_info['ssid'],
        "BSSID": network_info['bssid'],
        "Signal Strength": network_info['signal_strength'],
        "Authentication": network_info['authentication'],
        "Authentication Risk": network_info['authentication_risk'],
        "Cipher": network_info['cipher'],
        "Cipher Risk": network_info['cipher_risk']
    }))
    
    # Output ARP analysis results
    print(format_section("ARP Analysis", {
        "Status": arp_info['status'],
        "Details": arp_info['details'],
        "Risk Score": arp_info['score']
    }))
    
    # Output DNS analysis results
    print(format_section("DNS Analysis", {
        "Status": dns_info['status'],
        "Details": dns_info['details'],
        "Score": dns_info['score'],
        "Domains Analyzed": dns_info['domains_analyzed'],
        "Suspicious Domains": dns_info['suspicious_domains']
    }))
    
    # Output BSSID analysis results
    print(format_section("BSSID Analysis", {
        "Status": bssid_info['status'],
        "Message": bssid_info['message'],
        "Network Count": bssid_info['networks_count']
    }))
    
    # Output SSID analysis results
    print(format_section("SSID Analysis", {
        "Status": ssid_info['status'],
        "Message": ssid_info['message'],
        "Network Count": ssid_info['networks_count']
    }))
    
    # Summarize risks
    risk_levels = {
        "Network Security": network_info['authentication_risk'],
        "ARP Security": arp_info['status'],
        "DNS Security": dns_info['status'],
        "BSSID Security": bssid_info['status'],
        "SSID Security": ssid_info['status']
    }
    
    print("\nRisk Summary:")
    for area, level in risk_levels.items():
        print(f"{area}: {level}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())