import concurrent.futures
from typing import Dict, List, Any, Set, Union, Optional
from utils.network_utils import get_all_networks

# Constants for risk status levels
STATUS_SAFE = "SAFE"
STATUS_SUSPICIOUS = "SUSPICIOUS" 
STATUS_DANGEROUS = "DANGEROUS"

SUSPICIOUS_BSSID_COUNT = 2


def is_valid_network(network: Dict[str, Any]) -> bool:

    if not isinstance(network, dict):
        return False
        
    if "error" in network:
        return False
        
    if "ssid" not in network or "bssid_list" not in network:
        return False
        
    return True


def extract_oui(bssid: str) -> str:

    # Clean the BSSID and take first 6 characters (3 bytes)
    return bssid[:8].replace("-", "").replace(":", "")[:6].upper()


def analyze_network_bssids(network: Dict[str, Any]) -> Dict[str, Any]:

    if not is_valid_network(network):
        return {}
        
    result = {}
    bssid_list = network.get("bssid_list", [])
    
    # Skip networks with only one BSSID
    if len(bssid_list) <= 1:
        return {}
        
    # Analyze multiple BSSIDs
    result["multi_ap"] = {
        "ssid": network["ssid"],
        "bssid_count": len(bssid_list),
        "bssids": bssid_list,
        "suspicion_level": "SUSPICIOUS" if len(bssid_list) > SUSPICIOUS_BSSID_COUNT else "NORMAL"
    }
    
    # Extract and analyze OUIs
    ouis = [extract_oui(bssid) for bssid in bssid_list]
    unique_ouis = set(ouis)
    
    if len(unique_ouis) > 1:
        result["oui_anomaly"] = {
            "ssid": network["ssid"],
            "bssid_count": len(bssid_list),
            "unique_ouis": list(unique_ouis),
            "unique_oui_count": len(unique_ouis),
            "bssids": bssid_list
        }
        
    return result


def detect_multiple_bssids_same_ssid(networks: List[Dict[str, Any]], max_workers: int = 5) -> List[Dict[str, Any]]:

    multi_ap_networks = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit network analysis tasks
        future_to_network = {
            executor.submit(analyze_network_bssids, network): network 
            for network in networks if is_valid_network(network)
        }
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_network):
            try:
                result = future.result()
                if result and "multi_ap" in result:
                    multi_ap_networks.append(result["multi_ap"])
            except Exception as e:
                print(f"Error analyzing network BSSIDs: {e}")
    
    return multi_ap_networks


def detect_oui_anomalies(networks: List[Dict[str, Any]], max_workers: int = 5) -> List[Dict[str, Any]]:

    oui_anomalies = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit network analysis tasks
        future_to_network = {
            executor.submit(analyze_network_bssids, network): network 
            for network in networks if is_valid_network(network)
        }
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_network):
            try:
                result = future.result()
                if result and "oui_anomaly" in result:
                    oui_anomalies.append(result["oui_anomaly"])
            except Exception as e:
                print(f"Error analyzing network OUIs: {e}")
    
    return oui_anomalies


def analyze_bssids(max_workers: int = 5) -> Dict[str, Any]:

    # Constrain max_workers to a reasonable range
    max_workers = max(1, min(10, max_workers))
    
    # Get all available networks
    networks = get_all_networks()
    
    # Handle error cases
    if isinstance(networks, dict) and "error" in networks:
        return {
            "status": "ERROR",
            "message": networks["error"],
            "details": {},
            "networks_count": 0
        }
    
    if not networks:
        return {
            "status": "ERROR",
            "message": "No WiFi networks found or unable to scan networks",
            "details": {},
            "networks_count": 0
        }
    
    # Perform concurrent BSSID analysis checks
    multi_ap_networks = detect_multiple_bssids_same_ssid(networks, max_workers)
    oui_anomalies = detect_oui_anomalies(networks, max_workers)
    
    # Determine overall status
    status = STATUS_SAFE
    issues = []
    
    if oui_anomalies:
        status = STATUS_SUSPICIOUS
        issues.append(f"Found {len(oui_anomalies)} networks with inconsistent manufacturer identifiers")
    
    if len([net for net in multi_ap_networks if net["suspicion_level"] == "SUSPICIOUS"]) > 0:
        if status != STATUS_SUSPICIOUS:
            status = STATUS_SUSPICIOUS
        issues.append(f"Found networks with unusually high number of access points")
    
    # Build result dictionary
    result = {
        "status": status,
        "message": ", ".join(issues) if issues else "No suspicious BSSID patterns detected",
        "networks_count": len(networks),
        "details": {
            "multi_ap_networks": multi_ap_networks,
            "oui_anomalies": oui_anomalies
        },
        "all_networks": [
            {
                "ssid": net.get("ssid", "Unknown"),
                "bssid_count": len(net.get("bssid_list", []))
            }
            for net in networks if is_valid_network(net)
        ]
    }
    
    return result