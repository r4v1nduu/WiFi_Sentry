AUTHENTICATION_RISK = {
    "Open": "High",
    "WEP": "Critical",
    "WPA-Personal": "Medium",
    "WPA2-Personal": "Low",
    "WPA3-Personal": "Very Low",
    "WPA-Enterprise": "Low",
    "WPA2-Enterprise": "Very Low",
    "WPA3-Enterprise": "Minimal",
    "WPS": "High",
}

CIPHER_RISK = {
    "None": "Critical",
    "WEP": "Critical",
    "TKIP": "High",  # Deprecated
    "AES": "Low",
    "CCMP": "Low",
    "GCMP": "Very Low",
}
