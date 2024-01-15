import json
from urllib.parse import urlparse, parse_qs

def generate_json(input_link):
    parsed_url = urlparse(input_link)
    query_params = parse_qs(parsed_url.query)

# Extract relevant information from the link
    password_and_server = parsed_url.netloc.split('@')
    password = password_and_server[0]
    server_with_port = password_and_server[1]

    # Check if port is specified in the netloc
    server_parts = server_with_port.split(':')
    server_ip = server_parts[0]
    server_port = int(server_parts[1]) if len(server_parts) > 1 else 443

    
    # Extract the value after the '#' symbol as the output filename
    output_filename = parsed_url.fragment + ".json"
    sni = query_params.get('sni', [output_filename])[0]
    insecure = bool(int(query_params.get('insecure', [0])[0]))

    # Construct the JSON structure
    output_json = {
        "dns": {
            "independent_cache": True,
            "rules": [
                {
                    "disable_cache": True,
                    "geosite": ["category-ads-all"],
                    "server": "dns-block"
                }
            ],
            "servers": [
                {
                    "address": "tcp://94.140.14.14",
                    "address_resolver": "dns-direct",
                    "strategy": "ipv4_only",
                    "tag": "dns-remote"
                },
                {
                    "address": "https://cloudflare-dns.com/dns-query",
                    "address_resolver": "dns-local",
                    "detour": "direct",
                    "strategy": "ipv4_only",
                    "tag": "dns-direct"
                },
                {
                    "address": "local",
                    "detour": "direct",
                    "tag": "dns-local"
                },
                {
                    "address": "rcode://success",
                    "tag": "dns-block"
                }
            ]
        },
        "inbounds": [
            {
                "auto_route": True,
                "endpoint_independent_nat": True,
                "inet4_address": "172.19.0.1/28",
                "interface_name": "ipv4-tun",
                "mtu": 1500,
                "sniff": True,
                "stack": "gvisor",
                "strict_route": True,
                "type": "tun"
            }
        ],
        "log": {
            "level": "warn"
        },
        "outbounds": [
            {
                "down_mbps": 100,
                "password": password,
                "server": server_ip,
                "server_port": 443,
                "tag": "proxy",
                "tls": {
                    "alpn": ["h3"],
                    "enabled": True,
                "insecure": True,
                    "server_name": sni
                },
                "type": "hysteria2",
                "up_mbps": 50
            },
            {
                "tag": "direct",
                "type": "direct"
            },
            {
                "tag": "bypass",
                "type": "direct"
            },
            {
                "tag": "block",
                "type": "block"
            },
            {
                "tag": "dns-out",
                "type": "dns"
            }
        ],
        "route": {
            "geoip": {
                "download_url": "https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db",
                "download_detour": "proxy"
            },
            "geosite": {
                "download_url": "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db",
                "download_detour": "proxy"
            },
            "auto_detect_interface": True,
            "rules": [
                {
                    "outbound": "dns-out",
                    "port": [53]
                },
                {
                    "inbound": ["dns-in"],
                    "outbound": "dns-out"
                },
                 {
                  "domain_suffix": ".ir",
                  "geoip": [
                     "ir",
                     "cn",
                     "private"
                  ],
                  "outbound": "bypass"
                  },
                {
                    "ip_cidr": ["224.0.0.0/3", "ff00::/8"],
                    "outbound": "block",
                    "source_ip_cidr": ["224.0.0.0/3", "ff00::/8"]
                }
            ]
        }
    }

    # Write the JSON to a file
    with open(output_filename, 'w') as output_file:
        json.dump(output_json, output_file, indent=3)

    print(f"Output JSON file '{output_filename}' created successfully.")

# for usage please put your link down here
input_link = "hy2://pass@ip:port?insecure=1&sni=www.sni.com#name"
generate_json(input_link)
