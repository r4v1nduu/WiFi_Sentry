DEFAULT_TRUSTED_DOMAINS = [
    "cloudflare.com",
    "dns.google",
    "resolver1.opendns.com",
    "dns.quad9.net"
]

KNOWN_GOOD_IPS = {
    "cloudflare.com": [
        "1.1.1.1/32",
        "1.0.0.1/32"
    ],
    "dns.google": [
        "8.8.8.8/32",
        "8.8.4.4/32"
    ],
    "resolver1.opendns.com": [
        "208.67.222.222/32",
        "208.67.220.220/32"
    ],
    "dns.quad9.net": [
        "9.9.9.9/32",
        "149.112.112.112/32"
    ]
}
