import threading
import concurrent.futures
from typing import Dict, Any, List, Tuple, Optional

from modules.basic_scan.network_scan import scan_network
from modules.mitm_scan.arp_analyzer import arp_analysis
from modules.mitm_scan.dns_analyzer import analyze_dns_behavior
from modules.rogue_ap_scan.bssid_analyzer import analyze_bssids
from modules.rogue_ap_scan.ssid_analyzer import analyze_ssids


class ScanManager:
    def __init__(self):
        
        self.scan_results = {}
        self.errors = []
        self.scan_complete = False
        self.scan_thread = None
        
        # UI 
        self.dashboard = None
        self.details = None
    
    def set_ui_components(self, dashboard, details):
        
        self.dashboard = dashboard
        self.details = details
    
    def is_scanning(self):
        
        return self.scan_thread is not None and self.scan_thread.is_alive()
    
    def start_scan(self):
        
        if self.is_scanning():
            return
        
        # Clear previous results
        self.scan_results = {}
        self.errors = []
        self.scan_complete = False
        
        # Reset UI
        if self.dashboard:
            self.dashboard.update_progress(0, 0)
            self.dashboard.update_status("Scanning...")
            self.dashboard.enable_scan_button(False)
        
        if self.details:
            self.details.clear_all_tabs()
        
        # Start scan in a separate thread
        self.scan_thread = threading.Thread(target=self.run_scan)
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def run_with_error_check(self, analysis_func, analysis_name: str) -> Tuple[str, Dict[str, Any]]:
        
        try:
            result = analysis_func()
            if isinstance(result, dict) and "error" in result:
                return f"Error in {analysis_name}: {result['error']}", {}
            return "", result
        except Exception as e:
            return f"Exception in {analysis_name}: {str(e)}", {}
    
    def run_scan(self):
        
        analyses = [
            (scan_network, "Network Scan", "network"),
            (arp_analysis, "ARP Analysis", "arp"),
            (analyze_dns_behavior, "DNS Analysis", "dns"),
            (analyze_ssids, "SSID Analysis", "ssid"),
            (analyze_bssids, "BSSID Analysis", "bssid")
        ]
        
        completed = 0
        total = len(analyses)
        
        # Run analyses in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            # Submit all tasks
            future_to_analysis = {
                executor.submit(self.run_with_error_check, func, name): (name, tab_id)
                for func, name, tab_id in analyses
            }
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_analysis):
                analysis_name, tab_id = future_to_analysis[future]
                try:
                    error, result = future.result()
                    if error:
                        self.errors.append(error)
                        self.update_text_widget(tab_id, f"Error: {error}")
                    else:
                        self.scan_results[analysis_name] = result
                        self.update_scan_progress(analysis_name, tab_id, result)
                    
                    completed += 1
                    progress_value = completed / total
                    progress_percent = int(progress_value * 100)
                    
                    # Update progress on main thread
                    if self.dashboard:
                        self.dashboard.update_progress(progress_value, progress_percent)
                    
                except Exception as e:
                    self.errors.append(f"Exception processing {analysis_name} result: {str(e)}")
                    completed += 1
        
        self.finish_scan()
    
    def update_scan_progress(self, analysis_name, tab_id, result):
        
        if self.details:
            
            formatted_text = self.format_section(analysis_name, result)
            self.update_text_widget(tab_id, formatted_text)
    
    def update_text_widget(self, tab_id, text):
        
        if self.details:
            self.details.update_text(tab_id, text)
    
    def finish_scan(self):
        
        self.scan_complete = True
        
        # Update status
        if self.dashboard:
            self.dashboard.update_status("Scan Complete")
            self.dashboard.enable_scan_button(True)
        
        # Update risk indicators
        self.update_risk_indicators()
    
    def update_risk_indicators(self):
        
        if not self.dashboard:
            return
        
        # Update Network Security indicator
        if "Network Scan" in self.scan_results:
            network_info = self.scan_results["Network Scan"]
            self.dashboard.update_risk_indicator("Network Security", network_info.get('authentication_risk', 'Unknown'))
        
        # Update ARP Security indicator
        if "ARP Analysis" in self.scan_results:
            arp_info = self.scan_results["ARP Analysis"]
            self.dashboard.update_risk_indicator("ARP Security", arp_info.get('status', 'Unknown'))
        
        # Update DNS Security indicator
        if "DNS Analysis" in self.scan_results:
            dns_info = self.scan_results["DNS Analysis"]
            self.dashboard.update_risk_indicator("DNS Security", dns_info.get('status', 'Unknown'))
        
        # Update BSSID Security indicator
        if "BSSID Analysis" in self.scan_results:
            bssid_info = self.scan_results["BSSID Analysis"]
            self.dashboard.update_risk_indicator("BSSID Security", bssid_info.get('status', 'Unknown'))
        
        # Update SSID Security indicator
        if "SSID Analysis" in self.scan_results:
            ssid_info = self.scan_results["SSID Analysis"]
            self.dashboard.update_risk_indicator("SSID Security", ssid_info.get('status', 'Unknown'))
    
    def format_section(self, title: str, data: Dict[str, Any]) -> str:
        
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