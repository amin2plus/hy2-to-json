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
       "outbounds": [
           {
               "type": "selector",
               "tag": "Select",
               "outbounds": [
                   "Auto",
                   "hy2"
               ],
               "default": "Auto"
           },
           {
               "type": "urltest",
               "tag": "Auto",
               "outbounds": [
                   "hy2"
               ],
               "url": "https://www.gstatic.com/generate_204",
               "interval": "10m",
               "tolerance": 200
           },
           {
               "tag": "direct",
               "type": "direct"
           },
           {
               "tag": "block",
               "type": "block"
           },
           {
               "tag": "dns-out",
               "type": "dns"
           },
           {
               "tag": "hy2",
               "type": "hysteria2",
               "server": server_ip,
               "password": password,
               "server_port": 443,
               "tls": {
                   "alpn": [
                      "h3"
                   ],
                   "enabled": True,
                   "insecure": True,
                   "server_name": "www.google.com"
                },
               "down_mbps": 60,
               "up_mbps": 30
            }
       ],
       "route": {
           "auto_detect_interface": True,
           "override_android_vpn": True,
           "final": "Select",
           "geoip": {
               "download_url": "https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db",
               "download_detour": "Select"
            },
            "geosite": {
               "download_url": "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db",
               "download_detour": "Select"
            },
            "rules": [
               {
                  "outbound": "dns-out",
                  "port": [
                     53
                  ]
               },
               {
                  "inbound": [
                     "dns-in"
                  ],
                  "outbound": "dns-out"
               },
               {
                  "geoip": [
                     "ir"
                  ],
                  "process_name": [
                   "WeChat"
                 ],
                  "outbound": "direct"
               },
               {
                  "ip_cidr": [
                     "224.0.0.0/3",
                     "ff00::/8"
                  ],
                  "outbound": "block",
                  "source_ip_cidr": [
                     "224.0.0.0/3",
                     "ff00::/8"
                  ]
               }
            ]
         },
       "experimental": {
           "cache_file": {
               "enabled": True,
               "path": "cache.db",
               "cache_id": "hy2",
               "store_fakeip": True
           }
       },
       "dns": {
           "servers": [
               {
                   "address": "tcp://94.140.14.14",
                   "address_resolver": "dns-local",
                   "strategy": "prefer_ipv4",
                   "tag": "dns-remote",
                   "detour": "Select"
               },
               {
                   "address": "94.140.14.14",
                   "detour": "direct",
                   "tag": "dns-local"
               },
               {
                   "address": "rcode://success",
                   "tag": "dns-block"
               }
           ],
           "rules": [
               {
                   "domain": [
                      "9.9.9.9",
                      "frankfurt.amin2plus.store",
                      "estonia.amin2plus.store"
                   ],
                   "server": "dns-local"
               },
               {
                   "outbound": "direct",
                   "server": "dns-local"
               }
           ],
           "final": "dns-remote",
           "reverse_mapping": True,
           "strategy": "prefer_ipv4",
           "independent_cache": True
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
       }
    }

    # Write the JSON to a file
    with open(output_filename, 'w') as output_file:
        json.dump(output_json, output_file, indent=3)

    print(f"Output JSON file '{output_filename}' created successfully.")

# for usage please put your link down here
input_link = "hy2://2b6010bb11e6571f@85.215.50.93:443?insecure=1&sni=www.google.com#hosein-fk"
generate_json(input_link)
