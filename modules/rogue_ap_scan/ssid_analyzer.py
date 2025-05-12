import difflib
import concurrent.futures
from typing import Dict, List, Set, Any, Tuple, Optional
from utils.network_utils import get_all_networks
from utils.string_utils import calculate_levenshtein
from configs.homoglyph import HOMOGLYPHS, INVISIBLE_PATTERN

# Constants for risk status levels
STATUS_SAFE = "SAFE"
STATUS_SUSPICIOUS = "SUSPICIOUS"
STATUS_DANGEROUS = "DANGEROUS"

# Similarity thresholds
SIMILARITY_THRESHOLD_MIN = 0.7
SIMILARITY_THRESHOLD_MAX = 0.99
DANGEROUS_SIMILAR_COUNT = 3


def is_valid_network(network: Dict[str, Any]) -> bool:

    if not isinstance(network, dict):
        return False
        
    if "error" in network:
        return False
        
    if "ssid" not in network or not network["ssid"]:
        return False
        
    return True


def calculate_similarity(ssid1: str, ssid2: str) -> float:

    # Convert to lowercase for comparison
    ssid1_lower = ssid1.lower()
    ssid2_lower = ssid2.lower()
    
    # Calculate sequence matcher similarity
    sequence_similarity = difflib.SequenceMatcher(None, ssid1_lower, ssid2_lower).ratio()
    
    # Calculate Levenshtein distance (normalize by max length)
    levenshtein = calculate_levenshtein(ssid1_lower, ssid2_lower)
    max_length = max(len(ssid1), len(ssid2))
    levenshtein_similarity = 1 - (levenshtein / max_length if max_length > 0 else 0)
    
    # Calculate weighted similarity score (combining both metrics)
    weighted_score = (sequence_similarity * 0.7) + (levenshtein_similarity * 0.3)
    
    return weighted_score


def find_similar_ssids_worker(ssid_pairs: List[Tuple[int, str, int, str]]) -> List[Dict[str, Any]]:

    similar_pairs = []
    
    for idx1, ssid1, idx2, ssid2 in ssid_pairs:
        # Skip identical SSIDs
        if ssid1 == ssid2:
            continue
            
        # Calculate similarity
        weighted_score = calculate_similarity(ssid1, ssid2)
        
        # If similar but not identical
        if SIMILARITY_THRESHOLD_MIN <= weighted_score < SIMILARITY_THRESHOLD_MAX:
            similar_pairs.append({
                "ssid1": ssid1,
                "ssid2": ssid2,
                "score": weighted_score,
                "idx1": idx1,
                "idx2": idx2
            })
    
    return similar_pairs


def find_similar_ssids(networks: List[Dict[str, Any]], max_workers: int = 5) -> List[Dict[str, Any]]:

    # Extract valid SSIDs from networks
    valid_networks = [(i, network["ssid"]) for i, network in enumerate(networks) if is_valid_network(network)]
    if not valid_networks:
        return []
        
    # Create all possible pairs for comparison (excluding identical indices)
    ssid_pairs = []
    for i, (idx1, ssid1) in enumerate(valid_networks):
        for j, (idx2, ssid2) in enumerate(valid_networks[i+1:], i+1):
            ssid_pairs.append((idx1, ssid1, idx2, ssid2))
    
    # Split work into chunks for concurrent processing
    chunk_size = max(1, len(ssid_pairs) // max_workers)
    chunks = [ssid_pairs[i:i+chunk_size] for i in range(0, len(ssid_pairs), chunk_size)]
    
    # Process chunks concurrently
    all_similar_pairs = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(find_similar_ssids_worker, chunk) for chunk in chunks]
        for future in concurrent.futures.as_completed(futures):
            try:
                similar_pairs = future.result()
                all_similar_pairs.extend(similar_pairs)
            except Exception as e:
                print(f"Error finding similar SSIDs: {e}")
    
    # Group similar SSIDs together
    ssid_groups = {}
    processed_indices = set()
    
    for pair in sorted(all_similar_pairs, key=lambda x: x["score"], reverse=True):
        ssid1, ssid2 = pair["ssid1"], pair["ssid2"]
        idx1, idx2 = pair["idx1"], pair["idx2"]
        
        # Skip if both SSIDs are already processed
        if idx1 in processed_indices and idx2 in processed_indices:
            continue
            
        # Find existing group or create new
        group_key = None
        for key in ssid_groups:
            if ssid1 in ssid_groups[key]["all_ssids"] or ssid2 in ssid_groups[key]["all_ssids"]:
                group_key = key
                break
                
        if group_key is None:
            group_key = len(ssid_groups)
            ssid_groups[group_key] = {
                "base_ssid": ssid1,
                "similar_ssids": [],
                "all_ssids": {ssid1},
                "similarity_scores": {}
            }
            processed_indices.add(idx1)
            
        # Add new SSID to group
        if ssid2 not in ssid_groups[group_key]["all_ssids"]:
            ssid_groups[group_key]["similar_ssids"].append(ssid2)
            ssid_groups[group_key]["all_ssids"].add(ssid2)
            ssid_groups[group_key]["similarity_scores"][ssid2] = f"{pair['score']:.2f}"
            processed_indices.add(idx2)
    
    # Convert to list and add counts
    result = []
    for group in ssid_groups.values():
        if group["similar_ssids"]:  # Only include groups with at least one similar SSID
            group["count"] = len(group["all_ssids"])
            del group["all_ssids"]  # Remove temporary tracking set
            result.append(group)
    
    return result


def check_character_issues(ssid: str) -> Dict[str, Any]:

    issues = {
        "unusual_chars": [],
        "homoglyphs": []
    }
    
    # Check for invisible characters
    invisible_matches = INVISIBLE_PATTERN.findall(ssid)
    if invisible_matches:
        issues["unusual_chars"].extend([f"U+{ord(c):04X}" for c in invisible_matches])
    
    # Check for homoglyphs and unusual Unicode
    for char in ssid:
        # Check for homoglyphs
        for latin_char, homoglyph_chars in HOMOGLYPHS.items():
            if char in homoglyph_chars:
                issues["homoglyphs"].append(f"'{char}' (U+{ord(char):04X}) looks like '{latin_char}'")
                break
        
        # Check for non-ASCII character codes that could be misleading
        if ord(char) > 127 and not char.isalpha() and f"U+{ord(char):04X}" not in issues["unusual_chars"]:
            issues["unusual_chars"].append(f"U+{ord(char):04X}")
    
    return issues


def check_unusual_characters(networks: List[Dict[str, Any]], max_workers: int = 5) -> List[Dict[str, Any]]:

    suspicious_networks = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Create mapping of futures to networks
        future_to_network = {}
        for network in networks:
            if is_valid_network(network):
                future = executor.submit(check_character_issues, network["ssid"])
                future_to_network[future] = network
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_network):
            try:
                network = future_to_network[future]
                issues = future.result()
                
                # Only add networks with actual issues
                if issues["unusual_chars"] or issues["homoglyphs"]:
                    suspicious_networks.append({
                        "ssid": network["ssid"],
                        "unusual_chars": issues["unusual_chars"],
                        "homoglyphs": issues["homoglyphs"]
                    })
            except Exception as e:
                print(f"Error checking unusual characters: {e}")
    
    return suspicious_networks


def analyze_ssids(max_workers: int = 5) -> Dict[str, Any]:

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
    
    # Perform concurrent SSID analysis checks
    similar_ssids = find_similar_ssids(networks, max_workers)
    unusual_ssid_chars = check_unusual_characters(networks, max_workers)
    
    # Determine overall status
    status = STATUS_SAFE
    issues = []
    
    if similar_ssids:
        status = STATUS_SUSPICIOUS
        issues.append(f"Found {len(similar_ssids)} groups of suspiciously similar SSIDs")
    
    if unusual_ssid_chars:
        status = STATUS_SUSPICIOUS
        issues.append(f"Found {len(unusual_ssid_chars)} SSIDs with unusual or invisible characters")
    
    # Check if there are any groups with many similar SSIDs (likely attack)
    for group in similar_ssids:
        if group["count"] >= DANGEROUS_SIMILAR_COUNT:  # If 3 or more similar SSIDs, consider it dangerous
            status = STATUS_DANGEROUS
            issues.append(f"Found large cluster of similar SSIDs: {group['base_ssid']} and {len(group['similar_ssids'])} variants")
    
    # Build result dictionary
    result = {
        "status": status,
        "message": ", ".join(issues) if issues else "No suspicious WiFi networks detected",
        "networks_count": len(networks),
        "details": {
            "similar_ssids": similar_ssids,
            "unusual_characters": unusual_ssid_chars
        },
        "all_networks": [
            {
                "ssid": net.get("ssid", "Unknown"),
                "authentication": net.get("authentication", "Unknown"),
                "cipher": net.get("cipher", "Unknown"),
                "signal": net.get("signal", "Unknown")
            }
            for net in networks if is_valid_network(net)
        ]
    }
    
    return result