from utils.network_utils import get_connected_network
from configs.secuirty_risks import AUTHENTICATION_RISK, CIPHER_RISK

def scan_network():

    network_info = get_connected_network()
    
    if "error" in network_info:
        return {"error": network_info["error"]}
    
    result = {
        "ssid": network_info.get("ssid", "Unknown"),
        "bssid": network_info.get("bssid", "Unknown"),
        "signal_strength": network_info.get("signal", "Unknown"),
        "authentication": network_info.get("authentication", "Unknown"),
        "cipher": network_info.get("cipher", "Unknown"),
        "authentication_risk": "Unknown",
        "cipher_risk": "Unknown"
    }
    
    auth = result["authentication"]
    if auth != "Unknown":
        auth_lower = auth.lower()
        for known_auth, risk_level in AUTHENTICATION_RISK.items():
            if known_auth.lower() in auth_lower:
                result["authentication_risk"] = risk_level
                break

    cipher = result["cipher"]
    if cipher != "Unknown":
        cipher_lower = cipher.lower()
        for known_cipher, risk_level in CIPHER_RISK.items():
            if known_cipher.lower() in cipher_lower:
                result["cipher_risk"] = risk_level
                break
    
    return result