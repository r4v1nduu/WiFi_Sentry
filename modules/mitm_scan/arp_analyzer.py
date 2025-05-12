import ipaddress
from collections import defaultdict
from typing import Dict, List, Set, Union, Any, Optional
import concurrent.futures
from utils.network_utils import get_arp_table, get_default_gateway, get_ip

MAX_RISK_SCORE = 20


def analyze_ip_entry(entry: Dict, subnet: Optional[str], subnet_macs: Set[str]):

    ip = entry.get("ip")
    mac = entry.get("mac", "").lower()
    
    # Skip invalid entries
    if not ip or not mac:
        return (ip, mac, False)
    
    is_local = False
    # Track if this MAC is in our subnet
    if subnet:
        try:
            if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(f"{subnet}/24"):
                is_local = True
        except ValueError:
            pass
            
    return (ip, mac, is_local)


def analyze_arp_table(arp_entries: List[Dict], gateway_ip: Optional[str], max_workers: int = 5) -> Dict[str, Any]:

    # Initialize counters and tracking data structures
    mac_to_ips = defaultdict(list)
    ip_to_macs = defaultdict(list)
    subnet_macs = set()
    issues = []
    risk_score = 0
    
    # Skip analysis if no entries provided
    if not arp_entries:
        return {
            "status": "error",
            "details": "No valid ARP data available",
            "score": 0,
            "issues": []
        }
    
    # Handle error dict case
    if isinstance(arp_entries, dict) and "error" in arp_entries:
        return {
            "status": "error",
            "details": arp_entries["error"],
            "score": 0,
            "issues": []
        }
    
    # Extract subnet information from the local IP
    subnet = None
    try:
        local_ip = get_ip()
        if local_ip:
            network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            subnet = str(network.network_address)
    except ValueError:
        pass  # Keep subnet as None if there's an issue
    
    # Process ARP entries concurrently
    entry_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_entry = {
            executor.submit(analyze_ip_entry, entry, subnet, subnet_macs): entry 
            for entry in arp_entries
        }
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_entry):
            try:
                ip, mac, is_local = future.result()
                
                # Skip invalid entries
                if not ip or not mac:
                    continue
                    
                # Track MAC to IP mapping
                if ip not in mac_to_ips[mac]:
                    mac_to_ips[mac].append(ip)
                
                # Track IP to MAC mapping
                if mac not in ip_to_macs[ip]:
                    ip_to_macs[ip].append(mac)
                
                # Track if this MAC is in our subnet
                if is_local:
                    subnet_macs.add(mac)
                    
                entry_results.append((ip, mac, is_local))
            except Exception as e:
                # Log error but continue with other entries
                print(f"Error analyzing ARP entry: {e}")
    
    # Function to check multiple IPs per MAC
    def check_multiple_ips_per_mac(mac, ips):
        if len(ips) > 1:
            return f"MAC {mac} is associated with {len(ips)} IP addresses: {', '.join(ips)}", min(len(ips), 5)
        return None, 0
    
    # Function to check gateway issues
    def check_gateway_issues(gateway_ip, ip_to_macs):
        if gateway_ip and isinstance(gateway_ip, str) and gateway_ip in ip_to_macs:
            gateway_macs = ip_to_macs[gateway_ip]
            if len(gateway_macs) > 1:
                return f"Multiple MAC addresses ({', '.join(gateway_macs)}) claim to be the gateway ({gateway_ip})", len(gateway_macs) * 3
        return None, 0
    
    # Function to check non-local MACs responding for local IPs
    def check_nonlocal_mac_for_local_ip(ip, macs, subnet, subnet_macs):
        try:
            if subnet and ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(f"{subnet}/24"):
                for mac in macs:
                    if mac not in subnet_macs:
                        return f"Non-local MAC {mac} is responding for local IP {ip}", 6
        except ValueError:
            pass
        return None, 0
    
    # Submit pattern analysis tasks
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Check multiple IPs per MAC
        multiple_ip_futures = {
            executor.submit(check_multiple_ips_per_mac, mac, ips): mac 
            for mac, ips in mac_to_ips.items()
        }
        
        # Check gateway issues
        gateway_future = executor.submit(check_gateway_issues, gateway_ip, ip_to_macs)
        
        # Check non-local MACs for local IPs
        nonlocal_mac_futures = {
            executor.submit(check_nonlocal_mac_for_local_ip, ip, macs, subnet, subnet_macs): ip 
            for ip, macs in ip_to_macs.items()
        }
        
        # Process results from multiple IP checks
        for future in concurrent.futures.as_completed(multiple_ip_futures):
            try:
                issue, score = future.result()
                if issue:
                    issues.append(issue)
                    risk_score += score
            except Exception as e:
                print(f"Error in multiple IP analysis: {e}")
        
        # Process result from gateway check
        try:
            issue, score = gateway_future.result()
            if issue:
                issues.append(issue)
                risk_score += score
        except Exception as e:
            print(f"Error in gateway analysis: {e}")
        
        # Process results from non-local MAC checks
        for future in concurrent.futures.as_completed(nonlocal_mac_futures):
            try:
                issue, score = future.result()
                if issue:
                    issues.append(issue)
                    risk_score += score
            except Exception as e:
                print(f"Error in non-local MAC analysis: {e}")
    
    # Determine status based on risk score
    if risk_score == 0:
        status = "None"
        details = "No ARP inconsistencies detected"
    elif risk_score < 5:
        status = "Low"
        details = "Minor ARP inconsistencies detected"
    elif risk_score < 10:
        status = "Medium"
        details = "ARP table shows potential spoofing"
    elif risk_score < MAX_RISK_SCORE:
        status = "High"
        details = "ARP table shows signs of ARP spoofing"
    else:
        status = "Critical"
        details = "Multiple signs of ARP spoofing detected"
    
    return {
        "status": status,
        "details": details,
        "score": risk_score,
        "issues": issues
    }


def arp_analysis(type: str = "simple", max_workers: int = 5) -> Dict[str, Any]:

    if type not in ["simple", "detailed"]:
        type = "simple"
    
    max_workers = max(1, min(10, max_workers))
    
    # Get ARP table and gateway information
    arp_entries = get_arp_table()
    gateway_ip = get_default_gateway()
    
    # Handle error case when gateway_ip is a dict with error
    if isinstance(gateway_ip, dict) and "error" in gateway_ip:
        gateway_ip = None
    
    result = analyze_arp_table(arp_entries, gateway_ip, max_workers)
    
    if type == "simple":
        return {
            "status": result["status"],
            "details": result["details"],
            "score": result["score"]
        }
    else:
        return {
            "status": result["status"],
            "details": result["details"],
            "score": result["score"],
            "issues": result.get("issues", [])
        }