import dns.resolver  # type: ignore
import concurrent.futures
import re
from typing import Dict, List, Any, Set, Optional, Union
from configs.trusted_domain import KNOWN_GOOD_IPS, DEFAULT_TRUSTED_DOMAINS
from utils.network_utils import IP_PATTERN, CIDR_PATTERN

MAX_RISK_SCORE = 20


def validate_ipv4(ip: str) -> bool:

    if not IP_PATTERN.match(ip):
        return False
        
    octets = ip.split('.')
    return all(0 <= int(octet) <= 255 for octet in octets)


def ip_to_int(ip: str) -> int:

    if not validate_ipv4(ip):
        raise ValueError(f"Invalid IP address format: {ip}")
        
    octets = ip.split('.')
    return (int(octets[0]) << 24) + (int(octets[1]) << 16) + (int(octets[2]) << 8) + int(octets[3])


def is_ip_in_cidr(ip: str, cidr: str) -> bool:

    # Handle direct IP comparison case
    if '/' not in cidr:
        return ip == cidr
    
    # Validate CIDR format
    if not CIDR_PATTERN.match(cidr):
        return False
        
    net_ip, bits = cidr.split('/')
    bits = int(bits)
    
    # Validate CIDR bits
    if not (0 <= bits <= 32):
        return False
    
    try:
        # Convert IP strings to integers
        ip_int = ip_to_int(ip)
        net_ip_int = ip_to_int(net_ip)
        
        # Create mask based on CIDR bits
        mask = (1 << (32 - bits)) - 1
        network = net_ip_int & ~mask
        
        return (ip_int & ~mask) == network
    except ValueError:
        return False


def check_ip_against_known_domain(domain: str, ip: str) -> bool:

    if domain not in KNOWN_GOOD_IPS:
        return False
        
    for cidr in KNOWN_GOOD_IPS.get(domain, []):
        if is_ip_in_cidr(ip, cidr):
            return True
            
    return False


def get_local_dns_result(domain: str) -> List[str]:

    try:
        answers = dns.resolver.resolve(domain, 'A')
        return [answer.address for answer in answers]
    except Exception:
        return []


def analyze_single_domain(domain: str) -> Dict[str, Any]:

    result = {
        "domain": domain,
        "local_ips": [],
        "is_suspicious": False,
        "confidence": 0,
        "details": []
    }
    
    # Get local DNS results
    local_ips = get_local_dns_result(domain)
    result["local_ips"] = local_ips
    
    # Check if resolution failed
    if not local_ips:
        result["is_suspicious"] = True
        result["confidence"] = 0.7
        result["details"].append("Failed to resolve domain using local DNS")
        return result
    
    # Check local IPs against known good ranges
    matches = [ip for ip in local_ips if check_ip_against_known_domain(domain, ip)]
    
    # Domain has known good IPs but none match
    if not matches and domain in KNOWN_GOOD_IPS:
        result["is_suspicious"] = True
        result["confidence"] = 0.9
        result["details"].append(f"Local DNS results don't match known IP ranges for {domain}")
    
    return result


def analyze_dns_behavior(type: str = "simple", max_workers: int = 5) -> Dict[str, Any]:

    if type not in ["simple", "detailed"]:
        type = "simple"
    
    max_workers = max(1, min(10, max_workers))
    
    domains_to_check = DEFAULT_TRUSTED_DOMAINS
    domains_analyzed = 0
    suspicious_domains = 0
    domain_results = []
    
    # Use ThreadPoolExecutor for parallel domain analysis
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_domain = {
            executor.submit(analyze_single_domain, domain): domain 
            for domain in domains_to_check
        }
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                domain_result = future.result()
                domains_analyzed += 1
                domain_results.append(domain_result)
                
                if domain_result["is_suspicious"]:
                    suspicious_domains += 1
            except Exception as e:
                # Log error but continue with other domains
                # Avoid print statements in production code, use logging instead
                print(f"Error analyzing {domain}: {e}")
    
    # Calculate risk score (0-20 scale)
    risk_score = 0
    if domains_analyzed > 0:
        # Base score on ratio of suspicious domains
        suspicious_ratio = suspicious_domains / domains_analyzed
        risk_score = min(MAX_RISK_SCORE, int(suspicious_ratio * MAX_RISK_SCORE))
        
        # Increase score based on confidence of suspicious results
        for result in domain_results:
            if result["is_suspicious"] and result["confidence"] > 0.8:
                risk_score += 1
        
        # Ensure we don't exceed maximum score
        risk_score = min(MAX_RISK_SCORE, risk_score)
    
    # Determine status based on risk score
    if risk_score == 0:
        status = "None"
        details = "No DNS manipulation detected"
    elif risk_score < 5:
        status = "Low"
        details = "Minor DNS anomalies detected"
    elif risk_score < 10:
        status = "Medium"
        details = "Suspicious DNS behavior detected"
    elif risk_score < MAX_RISK_SCORE:
        status = "High"
        details = "Suspicious DNS behavior detected"
    else:
        status = "Critical"
        details = "Multiple signs of DNS manipulation detected"
    
    # Add specific domain details if available
    suspicious_domains_list = [r["domain"] for r in domain_results if r["is_suspicious"]]
    if suspicious_domains_list and (status == "high" or status == "critical"):
        suspicious_str = ", ".join(suspicious_domains_list[:3])
        if len(suspicious_domains_list) > 3:
            suspicious_str += f" and {len(suspicious_domains_list)-3} more"
        details += f" (affected domains: {suspicious_str})"
    
    if type == "simple":
        return {
            "status": status,
            "details": details,
            "score": risk_score
        }
    else:
        return {
            "status": status,
            "details": details,
            "score": risk_score,
            "domains_analyzed": domains_analyzed,
            "suspicious_domains": suspicious_domains,
            "domain_results": domain_results
        }