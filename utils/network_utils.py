import re
from functools import wraps
from .windows_utils import run_windows_command

# Regex patterns
IPV4_PATTERN = re.compile(r"IPv4 Address[^:]*:\s*([^\s]+)")
SUBNET_PATTERN = re.compile(r"Subnet Mask[^:]*:\s*([^\s]+)")
GATEWAY_PATTERN = re.compile(r"Default Gateway[^:]*:\s*([^\s]+)")
MAC_PATTERN = re.compile(r"Physical Address[^:]*:\s*([0-9A-Fa-f-]+)")
DNS_PATTERN = re.compile(r"DNS Servers[^:]*:\s*([^\r\n]+)")
EXTRA_DNS_PATTERN = re.compile(r"^\s+([^\s]+)$")
SSID_PATTERN = re.compile(r"SSID\s*:\s*(.*?)(?:\r?\n)")
BSSID_PATTERN = re.compile(r"BSSID\s*:\s*([0-9A-Fa-f:-]+)")
SIGNAL_PATTERN = re.compile(r"Signal\s*:\s*(\d+)%")
ROUTE_PATTERN = re.compile(r"\s*0\.0\.0\.0\s+0\.0\.0\.0\s+([0-9.]+)\s")
ARP_PATTERN = re.compile(r"\s*([0-9.]+)\s+([0-9a-f-]+)\s+(\w+)")
AUTHENTICATION_PATTERN = re.compile(r"Authentication\s*:\s*([^\r\n]+)")
CIPHER_PATTERN = re.compile(r"Cipher\s*:\s*([^\r\n]+)")

IP_PATTERN = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
CIDR_PATTERN = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$')

# cache implementation
class NetworkCache:
    def __init__(self):
        self._cache = {}

    def get(self, key):
        # Get a value from the cache if it exists
        return self._cache.get(key)

    def set(self, key, value):
        # Store a value in the cache
        self._cache[key] = value

    def clear(self, key=None):
        # Clear the entire cache or a specific key
        if key is None:
            self._cache.clear()
        elif key in self._cache:
            del self._cache[key]

    def has_key(self, key):
        # Check if a key exists in the cache
        return key in self._cache

# Create a global cache instance
_network_cache = NetworkCache()

# Decorator for caching function results
def cached():
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Create a unique cache key from the function name and arguments
            key = f"{func.__name__}:{str(args)}:{str(kwargs)}"
            
            # Check if result is in cache
            if _network_cache.has_key(key):
                return _network_cache.get(key)
            
            # Call the original function
            result = func(*args, **kwargs)
            
            # Cache the result
            _network_cache.set(key, result)
            
            return result
        return wrapper
    return decorator

def clear_network_cache():
    
    _network_cache.clear()

@cached()
def get_connected_network():
    network_info = {}

    output = run_windows_command("netsh wlan show interfaces")
    if not output or "error" in output:
        return {"error": "Failed to execute command"}
    
    # Check if connected
    if "State" not in output or "connected" not in output:
        return {"error": "Not connected to any Wi-Fi network"}
    
    # Extract SSID
    ssid_match = SSID_PATTERN.search(output)
    if ssid_match:
        network_info["ssid"] = ssid_match.group(1).strip()
    
    # Extract BSSID
    bssid_match = BSSID_PATTERN.search(output)
    if bssid_match:
        network_info["bssid"] = bssid_match.group(1).strip()
    
    # Extract signal strength
    signal_match = SIGNAL_PATTERN.search(output)
    if signal_match:
        network_info["signal"] = f"{signal_match.group(1)}%"
    
    # Extract authentication
    auth_match = AUTHENTICATION_PATTERN.search(output)
    if auth_match:
        network_info["authentication"] = auth_match.group(1).strip()
    
    # Extract cipher
    cipher_match = CIPHER_PATTERN.search(output)
    if cipher_match:
        network_info["cipher"] = cipher_match.group(1).strip()
    
    return network_info

@cached()
def get_all_networks():
    # Only extracts SSID and BSSID
    networks = []
    current_network = {}

    output = run_windows_command("netsh wlan show networks mode=Bssid")
    if not output or isinstance(output, dict) and "error" in output:
        return {"error": "Failed to execute command"}
    
    for line in output.split('\n'):
        line = line.strip()
        if "SSID" in line and "BSSID" not in line:
            if current_network and "ssid" in current_network:
                networks.append(current_network)
            current_network = {}
            ssid_parts = line.split(" : ", 1)
            if len(ssid_parts) > 1:
                current_network["ssid"] = ssid_parts[1].strip()
                current_network["bssid_list"] = []
        
        elif "BSSID" in line:
            bssid_parts = line.split(" : ", 1)
            if len(bssid_parts) > 1:
                bssid_mac = bssid_parts[1].strip().lower()
                current_network["bssid_list"].append(bssid_mac)
    
    # Add the last network
    if current_network and "ssid" in current_network:
        networks.append(current_network)
    
    return networks

@cached()
def get_arp_table():
    arp_entries = []
    in_interface_section = False

    output = run_windows_command("arp -a")
    if not output or "error" in output:
        return {"error": "Failed to execute command"}
    
    for line in output.splitlines():
        # Check for interface header
        if "Interface:" in line:
            in_interface_section = True
            continue
        
        if not in_interface_section:
            continue
            
        # Skip table headers
        if "Internet Address" in line or "---" in line:
            continue
            
        # Parse actual ARP entries
        match = re.search(r"\s*([0-9.]+)\s+([0-9a-f-]+)\s+(\w+)\s*", line, re.IGNORECASE)
        if match:
            ip = match.group(1)
            mac = match.group(2).lower()
            entry_type = match.group(3)
            
            # Skip invalid entries
            if mac in ["ff-ff-ff-ff-ff-ff", "00-00-00-00-00-00"]:
                continue
                
            # Skip multicast entries
            if mac.startswith("01-00-5e"):
                continue
                
            # Skip multicast IP addresses
            try:
                first_octet = int(ip.split('.')[0])
                if 224 <= first_octet <= 239:
                    continue
            except (ValueError, IndexError):
                continue
                
            arp_entries.append({
                "ip": ip,
                "mac": mac,
                "type": entry_type
            })
            
    return arp_entries

@cached()
def get_ip():
    # First check if connected to WiFi at all
    wifi_info = get_connected_network()
    if isinstance(wifi_info, dict) and "error" in wifi_info:
        return None
    
    # Get the SSID of the connected network
    ssid = wifi_info.get("ssid")
    if not ssid:
        return None
    
    # Get full network config for all interfaces
    output = run_windows_command("ipconfig /all")
    if isinstance(output, dict) and "error" in output:
        return None
    
    # Split the output by interfaces
    interfaces = re.split(r"\r?\n\r?\n", output)
    
    # Look for a wireless interface that is connected
    wifi_ip = None
    for interface in interfaces:
        # Check if this looks like a WiFi interface
        if "Wireless" in interface or "Wi-Fi" in interface or "Wifi" in interface:
            # Extract the IP address if available
            ip_match = IPV4_PATTERN.search(interface)
            if ip_match:
                wifi_ip = ip_match.group(1).strip()
                break
    
    return wifi_ip

@cached()
def get_default_gateway():

    try:
        # Run the route print command to get routing table
        route_output = run_windows_command("route print 0.0.0.0")
        
        # Check if the command returned an error
        if isinstance(route_output, dict) and "error" in route_output:
            raise RuntimeError(f"Error running route print: {route_output['error']}")
        
        # Check if output is a string
        if not isinstance(route_output, str):
            raise RuntimeError(f"Unexpected output type from route print: {type(route_output)}")
        
        # Look for the gateway in the routing table (0.0.0.0 route)
        gateway = None
        for line in route_output.splitlines():
            if "0.0.0.0" in line:
                parts = line.split()
                if len(parts) >= 3:
                    potential_ip = parts[2]
                    # Verify it's a valid IPv4 address
                    if re.match(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", potential_ip):
                        gateway = potential_ip
                        break
        
        # If no gateway found, raise an error
        if not gateway:
            raise RuntimeError("No default gateway found in routing table")
        
        return gateway
        
    except Exception as e:
        # Re-raise any exceptions with a clear message
        raise RuntimeError(f"Failed to get default gateway: {str(e)}")

# Force refresh specific network information
def refresh_network_info(function_name=None):

    if function_name is None:
        clear_network_cache()
        return
        
    # Find all keys that start with the function name and clear them
    keys_to_clear = [k for k in _network_cache._cache.keys() if k.startswith(f"{function_name}:")]
    for key in keys_to_clear:
        _network_cache.clear(key)


def scan_port(port):

    output = run_windows_command("netstat -an | findstr :{port}")
    
    # Check for active connections or listening states on this port
    if output and (f":{port}" in output) and ("LISTENING" in output or "ESTABLISHED" in output):
        return True
    else:
        return False