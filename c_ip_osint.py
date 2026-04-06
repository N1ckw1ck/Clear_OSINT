#!/usr/bin/env python3

'''
(Clear Web) IP Address OSINT Tool
For authorized research and investigative purposes only.
You can get in trouble for scanning IPs you don't own / aren't authorized to scan.
Assume the owner of any IP you scan has logging in place and will know that you scanned it.
Please don't break any laws.
'''

import sys
import json
import socket
import ipaddress
import requests
import concurrent.futures
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any

# AbuseIPDB has a free API tier for checking IP reputation and abuse reports.
# Sign up at: https://www.abuseipdb.com/register
ABUSEIPDB_API_KEY: str = '' # Paste the key here.
# If left blank the scan will still work, but abuse report data won't be available.

# Shodan offers a paid API tier for checking open ports and service banners.
# There is a free tier but it won't allow API access to this endpoint.
# Sign up at: https://account.shodan.io/register
# Paste your key below.
SHODAN_API_KEY: str = ''
# If left blank the tool will fall back to a direct TCP port probe instead.
# It is not the end of the world to leave this blank

# ANSI styling
R  = '\033[91m'
G  = '\033[92m'
Y  = '\033[93m'
B  = '\033[94m'
M  = '\033[95m'
C  = '\033[96m'
W  = '\033[97m'
DIM  = '\033[2m'
BOLD = '\033[1m'
RESET = '\033[0m'

BANNER = f'''
{B}{BOLD}
 ██╗██████╗      ██████╗ ███████╗██╗███╗   ██╗████████╗
 ██║██╔══██╗    ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
 ██║██████╔╝    ██║   ██║███████╗██║██╔██╗ ██║   ██║
 ██║██╔═══╝     ██║   ██║╚════██║██║██║╚██╗██║   ██║
 ██║██║         ╚██████╔╝███████║██║██║ ╚████║   ██║
 ╚═╝╚═╝          ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝
{RESET}{DIM}IP Address OSINT Tool | Authorized research use only{RESET}
'''

DIVIDER = f'{DIM}{"─" * 62}{RESET}'

# Common ports to probe with their service names
COMMON_PORTS: dict[int, str] = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    465: 'SMTPS',
    587: 'SMTP (Submission)',
    993: 'IMAPS',
    995: 'POP3S',
    1433: 'MSSQL',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
    9200: 'Elasticsearch',
    27017: 'MongoDB',
}

PORT_TIMEOUT = 1.5 # seconds per port probe
PORT_WORKERS = 50 # concurrent (sort of) threads for port scanning

# Known datacenter/hosting ASN name fragments
DATACENTER_ASN_KEYWORDS: set[str] = {
    # Cloud providers
    'amazon', 'aws', 'google', 'microsoft', 'azure', 'googlecloud',
    # Hosting / VPS
    'digitalocean', 'linode', 'akamai', 'vultr', 'hetzner', 'ovh',
    'leaseweb', 'rackspace', 'softlayer', 'choopa', 'as-choopa',
    'frantech', 'quadranet', 'psychz', 'singlehop', 'nocix',
    'colocation', 'colo', 'hosting', 'datacenter', 'data center',
    'server', 'cloud', 'vps', 'dedicated',
    # CDN
    'cloudflare', 'fastly', 'incapsula', 'cdn',
    # VPN providers (ASN-registered ones)
    'mullvad', 'nordvpn', 'expressvpn', 'privateinternetaccess',
    'pia ', 'ipvanish', 'purevpn', 'hidemyass',
    # Tor-adjacent
    'torservers', 'emerald onion',
}

RESIDENTIAL_ASN_KEYWORDS: set[str] = {
    'comcast', 'xfinity', 'at&t', 'verizon', 'spectrum', 'cox',
    'charter', 'centurylink', 'lumen', 'frontier', 'optimum',
    'cablevision', 'mediacom', 'windstream', 'consolidated',
    'british telecom', 'bt ', 'sky ', 'virgin media', 'talk talk',
    'deutsche telekom', 'vodafone', 'orange', 'sfr', 'bouygues',
    'telecom italia', 'telefonica', 'swisscom', 'proximus',
    'bell canada', 'rogers', 'telus', 'shaw',
    'isp', 'broadband', 'cable', 'dsl', 'fiber', 'fibre',
    'residential', 'dynamic',
}

# Display helpers
def print_section(title: str) -> None:
    print(f'\n{B}{BOLD}[ {title} ]{RESET}')
    print(DIVIDER)

def print_field(label: str, value: str, color: str = W) -> None:
    print(f'  {DIM}{label:<30}{RESET}{color}{value}{RESET}')

# Dataclasses
@dataclass
class LocalInfo:
    '''Network interface data for private/loopback IPs.'''
    interfaces: list[dict[str, str]] # Like [{name, ip, mac}]
    hostname: str

@dataclass
class GeoInfo:
    ip: str
    city: str
    region: str
    country: str
    country_code: str
    latitude: str
    longitude: str
    timezone: str
    org: str
    asn: str
    asn_name: str

@dataclass
class RipeStatInfo:
    prefix: str
    announced: bool
    rir: str
    allocation_status: str
    asn: str
    asn_name: str
    asn_country: str
    asn_description: str
    abuse_contacts: list[str]
    bgp_peers: list[str]

@dataclass
class AsnDetail:
    routing_history: list[str] # prefixes seen advertised historically returns list
    first_seen: str
    last_seen: str
    upstream_peers: list[str]
    downstream_peers: list[str]
    neighbour_count_left: int
    neighbour_count_right: int

@dataclass
class HostingClassification:
    category: str # 'Datacenter / Cloud', 'Residential ISP', 'Mobile', 'Unknown'
    confidence: str # 'High', 'Medium', 'Low'
    signals: list[str]

@dataclass
class PassiveDnsEntry:
    rrtype: str
    rrname: str
    rdata: str
    last_seen: str

@dataclass
class DnsChainResult:
    resource: str
    forward_nodes: dict[str, list[str]]
    reverse_nodes: dict[str, list[str]]
    authoritative_nameservers: list[str]
    nameservers: list[str]

@dataclass
class DomainDiscovery:
    domains: list[str]
    source_map: dict[str, list[str]]
    probed: list[dict[str, str]] 

@dataclass
class PortResult:
    port: int
    service: str
    open: bool
    banner: str

@dataclass
class ShodanInfo:
    open_ports: list[int]
    port_details: list[dict[str, str]]
    isp: str
    org: str
    hostnames: list[str]
    domains: list[str]
    os: str
    tags: list[str]
    last_update: str

@dataclass
class AbuseInfo:
    is_public: bool
    abuse_confidence_score: int
    country_code: str
    isp: str
    domain: str
    usage_type: str
    total_reports: int
    num_distinct_users: int
    last_reported_at: str
    is_whitelisted: bool

@dataclass
class PingResult:
    packets_sent: int
    packets_received: int
    packet_loss_pct: float
    rtt_min_ms: float
    rtt_avg_ms: float
    rtt_max_ms: float
    rtt_mdev_ms: float # Jitter
    raw_output: str
    error: str

@dataclass
class IpReport:
    target: str
    scan_time: str
    ip_version: int
    is_private: bool
    is_loopback: bool
    rdns: str
    geo: GeoInfo | None
    ripe: RipeStatInfo | None
    asn_detail: AsnDetail | None
    passive_dns: list[PassiveDnsEntry]
    dns_chain: DnsChainResult | None
    domain_discovery: DomainDiscovery | None
    ports: list[PortResult]
    hosting_class: HostingClassification | None
    is_tor: bool
    shodan: ShodanInfo | None
    abuse: AbuseInfo | None
    ping: PingResult | None


# IP classification and input
def classify_ip(ip_str: str) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, bool, bool]:
    '''Parse and classify an IP. Returns (addr_obj, is_private, is_loopback).'''
    addr = ipaddress.ip_address(ip_str)
    return addr, addr.is_private, addr.is_loopback

def get_ip_input() -> str:
    '''Prompt the user for an IP address.'''
    print(f'\n{Y}Enter target IP address:{RESET}')
    raw = input(f'{C}> IP Address (IPv4 or IPv6): {RESET}').strip()
    return raw

def reverse_dns(ip: str) -> str:
    '''Attempt reverse DNS lookup. Returns hostname or "N/A".'''
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return 'N/A'

# Local interface info (for private IPs)
def get_local_info() -> LocalInfo:
    '''
    Collect local network interface information without external dependencies.
    Uses /proc/net/if_inet6 and /proc/net/fib_trie on Linux;
    fall back to socket.getaddrinfo on other platforms.
    '''
    hostname = socket.gethostname()
    interfaces: list[dict[str, str]] = []

    # Try to use the netifaces library for best coverage
    try:
        import netifaces  # type: ignore
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            ipv4_list = addrs.get(netifaces.AF_INET, [])
            mac_list = addrs.get(netifaces.AF_LINK, [])
            mac = mac_list[0].get('addr', 'N/A') if mac_list else 'N/A'
            if ipv4_list:
                for entry in ipv4_list:
                    interfaces.append({
                        'name': iface,
                        'ip': entry.get('addr', 'N/A'),
                        'mask': entry.get('netmask', 'N/A'),
                        'mac': mac,
                    })
            else:
                interfaces.append({'name': iface, 'ip': 'N/A', 'mask': 'N/A', 'mac': mac})
        return LocalInfo(interfaces=interfaces, hostname=hostname)
    except ImportError:
        pass

    # Fallback use socket to get at least the primary outbound IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        primary_ip = s.getsockname()[0]
        s.close()
    except Exception:
        primary_ip = '127.0.0.1'

    interfaces.append({
        'name': 'primary',
        'ip':   primary_ip,
        'mask': 'N/A',
        'mac':  'N/A (install netifaces for full detail)',
    })
    return LocalInfo(interfaces=interfaces, hostname=hostname)

# Geo (ipapi.co no key required)
def fetch_geo(ip: str) -> GeoInfo | None:
    '''
    Fetch geolocation and ASN data from ipapi.co.
    Free tier: 1000 req/day, no key required.
    Docs: https://ipapi.co/api/
    '''
    url = f'https://ipapi.co/{ip}/json/'
    try:
        response = requests.get(url, timeout=8, headers={'User-Agent': 'ip-osint-tool/1.0'})
        response.raise_for_status()
        d = response.json()
    except Exception as e:
        print(f'\n  {R}ipapi.co request failed: {e}{RESET}')
        return None

    if d.get('error'):
        print(f'\n  {R}ipapi.co error: {d.get("reason", "Unknown")}{RESET}')
        return None

    def s(key: str) -> str:
        val = d.get(key)
        return str(val) if val is not None else 'N/A'

    return GeoInfo(
        ip=s('ip'),
        city=s('city'),
        region=s('region'),
        country=s('country_name'),
        country_code=s('country_code'),
        latitude=s('latitude'),
        longitude=s('longitude'),
        timezone=s('timezone'),
        org=s('org'),
        asn=s('asn'),
        asn_name=s('org'),
    )

# RIPEstat no key whoop
# Docs: https://stat.ripe.net/docs/02.data-api/
def _ripe_get(endpoint: str, params: dict[str, str]) -> dict[str, Any] | None: # Any Any Any 
    '''Helper: GET a RIPEstat data endpoint, return parsed JSON or None.'''
    url = f'https://stat.ripe.net/data/{endpoint}/data.json'
    try:
        r = requests.get(url, params=params, timeout=10,
                         headers={'User-Agent': 'ip-osint-tool/1.0'})
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f'\n  {R}RIPEstat [{endpoint}] failed: {e}{RESET}')
        return None

def fetch_ripestat(ip: str) -> RipeStatInfo | None:
    '''
    Query RIPEstat for prefix, ASN, abuse contact, and routing data.
    Combines: prefix-overview, whois, abuse-contact-finder, routing-history.
    Keyless.
    '''
    result = RipeStatInfo(
        prefix='N/A',
        announced=False,
        rir='N/A',
        allocation_status='N/A',
        asn='N/A',
        asn_name='N/A',
        asn_country='N/A',
        asn_description='N/A',
        abuse_contacts=[],
        bgp_peers=[],
    )

    # Prefix overview — gets BGP prefix + announcement status
    data = _ripe_get('prefix-overview', {'resource': ip})
    if data and data.get('status') == 'ok':
        d = data.get('data', {})
        result.announced = d.get('announced', False)
        result.prefix = d.get('resource', 'N/A')
        asns = d.get('asns', []) # type ?????
        if asns:
            result.asn = str(asns[0].get('asn', 'N/A'))
            result.asn_name = asns[0].get('holder', 'N/A')
        block = d.get('block', {})
        result.rir = block.get('registry', 'N/A').upper()
        result.allocation_status = block.get('name', 'N/A')

    # Abuse contact finder
    data = _ripe_get('abuse-contact-finder', {'resource': ip})
    if data and data.get('status') == 'ok':
        contacts = data.get('data', {}).get('abuse_contacts', [])
        result.abuse_contacts = [str(c) for c in contacts if c]

    # Network-info for extra ASN / country context
    data = _ripe_get('network-info', {'resource': ip})
    if data and data.get('status') == 'ok':
        d = data.get('data', {})
        if result.prefix == 'N/A':
            result.prefix = d.get('prefix', 'N/A')
        asns = d.get('asns', [])
        if asns and result.asn == 'N/A':
            result.asn = str(asns[0])

    # BGP peers (routing neighbours) via bgp-state
    data = _ripe_get('bgp-state', {'resource': result.prefix if result.prefix != 'N/A' else ip})
    if data and data.get('status') == 'ok':
        routes = data.get('data', {}).get('bgp_state', [])
        peers: list[str] = []
        for route in routes[:10]: # cap at 10
            path = route.get('path', []) # This could be increased
            if path:
                peers.append(f"AS{path[-1]} (via path: {' → '.join(str(a) for a in path[-3:])})")
        result.bgp_peers = peers

    return result

def fetch_asn_detail(asn: str) -> AsnDetail | None:
    '''
    Query RIPEstat for ASN routing history and BGP neighbours.
    Requires a valid ASN string (digits only, no AS prefix).
    '''
    if not asn or asn == 'N/A':
        return None

    resource = f'AS{asn}'

    routing_history: list[str] = []
    first_seen = 'N/A'
    last_seen = 'N/A'

    data = _ripe_get('routing-history', {'resource': resource})
    if data and data.get('status') == 'ok':
        routes = data.get('data', {}).get('by_origin', [])
        for origin in routes:
            prefixes = origin.get('prefixes', [])
            for p in prefixes[:20]: # cap per origin
                prefix_str = p.get('prefix', '')
                timelines = p.get('timelines', [])
                if timelines:
                    t_start = timelines[0].get('starttime', '')
                    t_end = timelines[-1].get('endtime', '')
                    if t_start and first_seen == 'N/A':
                        first_seen = t_start
                    if t_end:
                        last_seen = t_end
                    routing_history.append(f'{prefix_str} (active: {t_start[:10]} → {t_end[:10]})')
                else:
                    routing_history.append(prefix_str)

    upstream_peers: list[str] = []
    downstream_peers: list[str] = []
    neighbour_count_left = 0
    neighbour_count_right = 0

    data = _ripe_get('asn-neighbours', {'resource': resource})
    if data and data.get('status') == 'ok':
        d = data.get('data', {})
        counts = d.get('neighbour_counts', {})
        neighbour_count_left = int(counts.get('left', 0))
        neighbour_count_right = int(counts.get('right', 0))
        neighbours = d.get('neighbours', [])
        for n in neighbours[:15]:
            direction = n.get('type', '')
            entry = (
                f"AS{n.get('asn')} "
                f"(power: {n.get('power')}, "
                f"v4 peers: {n.get('v4_peers')}, "
                f"v6 peers: {n.get('v6_peers')})"
            )
            if direction == 'left':
                upstream_peers.append(entry)
            else:
                downstream_peers.append(entry)

    return AsnDetail(
        routing_history=routing_history[:30],
        first_seen=first_seen,
        last_seen=last_seen,
        upstream_peers=upstream_peers,
        downstream_peers=downstream_peers,
        neighbour_count_left=neighbour_count_left,
        neighbour_count_right=neighbour_count_right,
    )

# Passive DNS (RIPEstat)
# Returns records as a string not dict
def fetch_passive_dns(ip: str) -> list[PassiveDnsEntry]:
    data = _ripe_get('reverse-dns-ip', {'resource': ip})
    entries: list[PassiveDnsEntry] = []

    if not data or data.get('status') != 'ok':
        return entries

    records: list[str] = data.get('data', {}).get('result') or [] # lies its a list of strings
    for hostname in records:
        entries.append(PassiveDnsEntry(
            rrtype='PTR',
            rrname=hostname,
            rdata=ip,
            last_seen='N/A',
        ))

    return entries[:30]

# If IP recursive chain is much less wide
def fetch_dns_chain(hostname: str) -> DnsChainResult | None:
    '''
    Fetch recursive DNS forward/reverse chain from RIPEstat.
    Input should be a hostname, not an IP.
    '''
    if not hostname or hostname == 'N/A':
        return None

    data = _ripe_get('dns-chain', {'resource': hostname})
    if not data or data.get('status') != 'ok':
        return None

    d = data.get('data', {})
    return DnsChainResult(
        resource=d.get('resource', hostname),
        forward_nodes=d.get('forward_nodes', {}),
        reverse_nodes=d.get('reverse_nodes', {}),
        authoritative_nameservers=d.get('authoritative_nameservers', []),
        nameservers=d.get('nameservers', []),
    )

def check_tor_exit(ip: str) -> bool:
    '''Check if IP is a known Tor exit node via torproject.org bulk exit list.'''
    url = 'https://check.torproject.org/torbulkexitlist'
    try:
        r = requests.get(url, timeout=8, headers={'User-Agent': 'ip-osint-tool/1.0'})
        r.raise_for_status()
        exit_nodes = {line.strip() for line in r.text.splitlines() if line.strip()}
        return ip in exit_nodes
    except Exception as e:
        print(f'\n  {R}Tor exit check failed: {e}{RESET}')
        return False
    
def classify_hosting(asn_name: str, org: str, prefix: str) -> HostingClassification:
    '''
    Classify IP as datacenter/cloud/VPN vs residential based on ASN name,
    org string, and prefix size. No other calls required.
    '''
    signals: list[str] = []
    dc_score = 0
    res_score = 0

    combined = f'{asn_name} {org}'.lower()

    for keyword in DATACENTER_ASN_KEYWORDS:
        if keyword in combined:
            dc_score += 1
            signals.append(f'ASN/org matches datacenter keyword: "{keyword}"')
            break  # one match is enough to flag it

    for keyword in RESIDENTIAL_ASN_KEYWORDS:
        if keyword in combined:
            res_score += 1
            signals.append(f'ASN/org matches residential ISP keyword: "{keyword}"')
            break

    # Mobile detection
    mobile_keywords = {'mobile', 'cellular', 'wireless', 't-mobile', 'sprint', 'ee ', 'three ', 'o2 '}
    if any(k in combined for k in mobile_keywords):
        signals.append('ASN/org suggests mobile carrier')
        return HostingClassification(category='Mobile Carrier', confidence='Medium', signals=signals)

    # Prefix size signal — /24 or smaller = likely datacenter allocation
    # Residential blocks tend to be larger (/8 to /16 at ISP level)
    if prefix and prefix != 'N/A':
        try:
            net = ipaddress.ip_network(prefix, strict=False)
            prefix_len = net.prefixlen
            if prefix_len >= 24:
                dc_score += 1
                signals.append(f'Prefix /{prefix_len} is a small block, typical of datacenter allocation')
            elif prefix_len <= 16:
                res_score += 1
                signals.append(f'Prefix /{prefix_len} is a large block, typical of ISP allocation')
        except ValueError:
            pass

    if dc_score > res_score:
        confidence = 'High' if dc_score >= 2 else 'Medium'
        return HostingClassification(category='Datacenter / Cloud / Hosting', confidence=confidence, signals=signals)
    elif res_score > dc_score:
        confidence = 'High' if res_score >= 2 else 'Medium'
        return HostingClassification(category='Residential ISP', confidence=confidence, signals=signals)
    else:
        return HostingClassification(category='Unknown', confidence='Low', signals=signals or ['No matching signals found'])

# Hackertarget reverse ip
#  Docs: https://hackertarget.com/reverse-ip-lookup/
def fetch_hackertarget_reverseip(ip: str) -> list[str]:
    '''
    Free reverse-IP lookup via HackerTarget.
    No API key needed. ~100 req/day free tier.
    Return a list of domain names hosted on the IP.
    '''
    url = f'https://api.hackertarget.com/reverseiplookup/?q={ip}'
    try:
        r = requests.get(url, timeout=10, headers={'User-Agent': 'ip-osint-tool/1.0'})
        r.raise_for_status()
        text = r.text.strip()
    except Exception as e:
        print(f'\n  {R}HackerTarget request failed: {e}{RESET}')
        return []

    # API returns "No records found" or "error" on failure
    if 'no records' in text.lower() or 'error' in text.lower() or not text:
        return []

    return [line.strip() for line in text.splitlines() if line.strip()]

# TLS certificate SAN extraction
def fetch_tls_san_domains(ip: str, port: int = 443, timeout: float = 5.0) -> list[str]:
    '''
    Connect to the IP on port 443, retrieve TLS certificate,
    and extract all Subject Alternative Names (SANs).
    Uses stdlib ssl only.
    Returns a list of domain names from the cert's SAN field.
    '''
    import ssl
    import socket as _socket

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE # Just want the cert data, not to verify it

    domains: list[str] = []
    try:
        with _socket.create_connection((ip, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=ip) as tls_sock:
                cert: dict[str, Any] | None = tls_sock.getpeercert()
                if cert is None:
                    return []
                # subjectAltName is a tuple of (type, value) pairs like ('DNS', 'example.com')
                sans: list[tuple[str, str]] = list(cert.get('subjectAltName', []))
                for kind, value in sans:
                    kind_str: str = str(kind)
                    value_str: str = str(value)
                    if kind_str == 'DNS':
                        # removeprefix only strips the literal '*.' prefix unlike lstrip
                        # which would strip any leading '*' or '.' characters individually
                        clean: str = value_str.removeprefix('*.').strip()
                        if clean:
                            domains.append(clean)
    except Exception as e:
        print(f'  {DIM}TLS SAN extraction skipped: {e}{RESET}')

    return list(dict.fromkeys(domains)) # Preserve order, dedupe

# HTTP/HTTPS probe per domain
def _probe_domain_http(ip: str, domain: str, timeout: float = 6.0) -> dict[str, str]:
    '''
    Send an HTTP/HTTPS request to the IP with the given Host header.
    Extracts status code, page title, and final URL after redirects.
    Returns a dict with keys: domain, url, status, title, redirect.
    '''
    import re as _re

    result: dict[str, str] = {
        'domain': domain,
        'url': f'https://{domain}',
        'status': 'N/A',
        'title': 'N/A',
        'redirect': '',
        'error': '',
    }

    for scheme in ('https', 'http'):
        target_url = f'{scheme}://{ip}'
        headers = {
            'Host': domain,
            'User-Agent': 'Mozilla/5.0 (compatible; ip-osint-tool/1.0)', # Iffy
            'Accept': 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
        }
        try:
            resp = requests.get(
                target_url,
                headers=headers,
                timeout=timeout,
                allow_redirects=True,
                verify=False, # Cert likely won't match IP that's okay we just want content
            )
            result['status'] = str(resp.status_code)
            result['url'] = f'{scheme}://{domain}'

            # Check if it followed a redirect to a different domain
            if resp.url and domain not in resp.url:
                result['redirect'] = resp.url[:120]

            # Extract <title> from response body
            html = resp.text[:8192]  # Only need the <head>
            title_match = _re.search(r'<title[^>]*>([^<]{1,200})</title>', html, _re.IGNORECASE)
            if title_match:
                result['title'] = title_match.group(1).strip()[:120]

            return result # Got a response so don't try http fallback

        except requests.exceptions.SSLError:
            continue # Try http
        except Exception as e:
            result['error'] = str(e)[:80]
            return result

    return result

def probe_domains_http(ip: str, domains: list[str], max_workers: int = 10) -> list[dict[str, str]]:
    '''
    Concurrently probe each domain in the list via HTTP/HTTPS Host-header injection.
    Returns only domains that returned a real response (status != N/A).
    '''
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # Expected (didn't verify)

    results: list[dict[str, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_probe_domain_http, ip, d): d for d in domains}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res['status'] != 'N/A':
                results.append(res)

    return sorted(results, key=lambda r: r['domain'])

# Orchestrator discovers and probes all domains
def discover_domains(
    ip: str,
    rdns: str,
    passive_dns: list[PassiveDnsEntry],
    shodan: 'ShodanInfo | None',
) -> DomainDiscovery:
    '''
    Aggregate domain names from all available sources, deduplicate,
    then HTTP probe each to confirm live services.
    '''
    source_map: dict[str, list[str]] = {
        'hackertarget': [],
        'tls_san': [],
        'shodan': [],
        'passive_dns': [],
        'rdns': [],
    }

    print(f'{DIM}  → HackerTarget reverse IP...{RESET}')
    source_map['hackertarget'] = fetch_hackertarget_reverseip(ip)

    print(f'{DIM}  → TLS certificate SAN extraction (port 443)...{RESET}')
    source_map['tls_san'] = fetch_tls_san_domains(ip)

    if shodan:
        source_map['shodan'] = list(shodan.hostnames) + list(shodan.domains)

    source_map['passive_dns'] = [e.rrname for e in passive_dns if e.rrname]

    if rdns and rdns != 'N/A':
        source_map['rdns'] = [rdns]

    # Union + deduplicate, preserving rough priority order
    seen: set[str] = set()
    all_domains: list[str] = []
    for source_domains in source_map.values():
        for d in source_domains:
            d_clean = d.strip().rstrip('.').lower()
            if d_clean and d_clean not in seen:
                seen.add(d_clean)
                all_domains.append(d_clean)

    print(f'{DIM}  → HTTP probing {len(all_domains)} unique domains...{RESET}')
    probed = probe_domains_http(ip, all_domains) if all_domains else []

    return DomainDiscovery(
        domains=all_domains,
        source_map=source_map,
        probed=probed,
    )

# Port probe (TCP connect, if not Shodan)
def _probe_port(ip: str, port: int, service: str) -> PortResult:
    '''Attempt a TCP connect to one port. Grab a banner if possible.'''
    try:
        with socket.create_connection((ip, port), timeout=PORT_TIMEOUT) as s:
            banner = ''
            try:
                s.settimeout(1)
                # Only attempt banner grab on text likely ports
                if port in (21, 22, 25, 110, 143, 587, 993, 995):
                    raw = s.recv(256)
                    banner = raw.decode('utf-8', errors='replace').strip()[:80]
            except Exception:
                pass
            return PortResult(port=port, service=service, open=True, banner=banner)
    except Exception:
        return PortResult(port=port, service=service, open=False, banner='')

def probe_common_ports(ip: str) -> list[PortResult]:
    '''Probe COMMON_PORTS concurrently. Return only open ports.'''
    results: list[PortResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=PORT_WORKERS) as ex:
        futures = {
            ex.submit(_probe_port, ip, port, svc): port
            for port, svc in COMMON_PORTS.items()
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result.open:
                results.append(result)
    return sorted(results, key=lambda r: r.port)

# Shodan (optional with paid API key)
# Docs: https://developer.shodan.io/api
def fetch_shodan(ip: str, api_key: str) -> ShodanInfo | None:
    '''
    Query the Shodan host endpoint for open ports, banners, and metadata.
    Requires a paid Shodan account / API key.
    PAID.
    '''
    url = f'https://api.shodan.io/shodan/host/{ip}'
    try:
        r = requests.get(url, params={'key': api_key.strip()}, timeout=10)
        if r.status_code == 404:
            print(f'\n  {DIM}Shodan: no data for this IP.{RESET}')
            return None
        r.raise_for_status()
        d = r.json()
    except Exception as e:
        print(f'\n  {R}Shodan request failed: {e}{RESET}')
        return None

    port_details: list[dict[str, str]] = []
    for item in d.get('data', []):
        port_details.append({
            'port': str(item.get('port', 'N/A')),
            'transport': item.get('transport', 'tcp'),
            'product': item.get('product', ''),
            'version': item.get('version', ''),
            'banner': str(item.get('data', ''))[:100].strip(),
        })

    return ShodanInfo(
        open_ports=sorted(d.get('ports', [])),
        port_details=port_details,
        isp=d.get('isp', 'N/A'),
        org=d.get('org', 'N/A'),
        hostnames=d.get('hostnames', []),
        domains=d.get('domains', []),
        os=str(d.get('os') or 'N/A'),
        tags=d.get('tags', []),
        last_update=d.get('last_update', 'N/A'),
    )


# AbuseIPDB (optional with free API key)
# Docs: https://www.abuseipdb.com/api
def fetch_abuseipdb(ip: str, api_key: str) -> AbuseInfo | None:
    '''
    Query AbuseIPDB for abuse reports and confidence score.
    Requires a free AbuseIPDB account / API key.
    maxAgeInDays=90 covers the last 3 months.
    '''
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Key': api_key.strip(),
        'Accept': 'application/json',
    }
    params = {'ipAddress': ip, 'maxAgeInDays': '90', 'verbose': ''}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=8)
        r.raise_for_status()
        d = r.json().get('data', {})
    except Exception as e:
        print(f'\n  {R}AbuseIPDB request failed: {e}{RESET}')
        return None

    def s(key: str) -> str:
        val = d.get(key)
        return str(val) if val is not None else 'N/A'

    return AbuseInfo(
        is_public=bool(d.get('isPublic', True)),
        abuse_confidence_score=int(d.get('abuseConfidenceScore', 0)),
        country_code=s('countryCode'),
        isp=s('isp'),
        domain=s('domain'),
        usage_type=s('usageType'),
        total_reports=int(d.get('totalReports', 0)),
        num_distinct_users=int(d.get('numDistinctUsers', 0)),
        last_reported_at=s('lastReportedAt'),
        is_whitelisted=bool(d.get('isWhitelisted', False)),
    )

# Why subprocess over a Python ICMP library:
#  - Raw ICMP sockets require root on most systems
#  - The system ping binary has the setuid bit set and makes it easy
#  - No extra dependencies!
def run_ping(ip: str, count: int = 10) -> PingResult:
    '''
    Send count ICMP echo requests via the system ping binary.
    Parses RTT statistics from the summary line,
    should work on Linux and macOS.
    Falls back semi gracefully if ping is not available or the host blocks ICMP.
    '''
    import subprocess
    import re as _re
    import sys as _sys

    empty = PingResult(
        packets_sent=count,
        packets_received=0,
        packet_loss_pct=100.0,
        rtt_min_ms=0.0,
        rtt_avg_ms=0.0,
        rtt_max_ms=0.0,
        rtt_mdev_ms=0.0,
        raw_output='',
        error='',
    )

    # Build the command — macOS uses -c for count same as linux
    # -W / -w: per-packet timeout. macOS uses -W (ms), Linux uses -W (s)
    # There is likely a better way to handle this
    if _sys.platform == 'darwin':
        cmd = ['ping', '-c', str(count), '-W', '1000', ip]
    else:
        cmd = ['ping', '-c', str(count), '-W', '1', ip]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=count * 3, # Should be generous enough
        )
        output = proc.stdout + proc.stderr
        empty.raw_output = output.strip()
    except FileNotFoundError:
        empty.error = 'ping binary not found'
        return empty
    except subprocess.TimeoutExpired:
        empty.error = 'ping timed out'
        return empty
    except Exception as e:
        empty.error = str(e)
        return empty

    # Parse packet loss
    # Linux: "10 packets transmitted, 8 received, 20% packet loss"
    # macOS: "10 packets transmitted, 8 packets received, 20.0% packet loss"
    loss_match = _re.search(
        r'(\d+) packets transmitted,\s*(\d+) (?:packets )?received,\s*([\d.]+)%',
        output,
    )
    received = 0
    loss_pct = 100.0
    if loss_match:
        sent_parsed = int(loss_match.group(1))
        received = int(loss_match.group(2))
        loss_pct = float(loss_match.group(3))
    else:
        sent_parsed = count

    # Parse RTT statistics
    # Linux: "rtt min/avg/max/mdev = 12.3/15.1/18.4/1.2 ms"
    # macOS: "round-trip min/avg/max/stddev = 12.3/15.1/18.4/1.2 ms"
    rtt_min = rtt_avg = rtt_max = rtt_mdev = 0.0
    rtt_match = _re.search(
        r'(?:rtt|round-trip)\s+min/avg/max/(?:mdev|stddev)\s*=\s*'
        r'([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)',
        output,
    )
    if rtt_match:
        rtt_min   = float(rtt_match.group(1))
        rtt_avg   = float(rtt_match.group(2))
        rtt_max   = float(rtt_match.group(3))
        rtt_mdev  = float(rtt_match.group(4))

    return PingResult(
        packets_sent=sent_parsed,
        packets_received=received,
        packet_loss_pct=loss_pct,
        rtt_min_ms=rtt_min,
        rtt_avg_ms=rtt_avg,
        rtt_max_ms=rtt_max,
        rtt_mdev_ms=rtt_mdev,
        raw_output=output.strip(),
        error='',
    )


# Print sections
def print_local_section(local: LocalInfo) -> None:
    print_section('LOCAL MACHINE INFO')
    print_field('Hostname:', local.hostname)
    if not local.interfaces:
        print(f'  {DIM}No interface data available.{RESET}')
        return
    for iface in local.interfaces:
        print(f'\n  {BOLD}{C}{iface["name"]}{RESET}')
        print_field('  IP Address:', iface.get('ip', 'N/A'))
        print_field('  Subnet Mask:', iface.get('mask', 'N/A'))
        print_field('  MAC Address:', iface.get('mac', 'N/A'), DIM + W)

def print_classification_section(report: IpReport) -> None:
    print_section('IP CLASSIFICATION')
    print_field('Target IP:', report.target)
    print_field('IP Version:', f'IPv{report.ip_version}')
    print_field('Reverse DNS:', report.rdns)
    private_color = Y if report.is_private else G
    print_field('Private / RFC1918:', 'Yes' if report.is_private else 'No', private_color)
    print_field('Loopback:', 'Yes' if report.is_loopback else 'No')

def print_geo_section(geo: GeoInfo) -> None:
    print_section('GEOLOCATION')
    print_field('Country:', f'{geo.country} ({geo.country_code})')
    print_field('Region:', geo.region)
    print_field('City:', geo.city)
    print_field('Latitude:', geo.latitude)
    print_field('Longitude:', geo.longitude)
    print_field('Timezone:', geo.timezone)
    print_field('Organisation:', geo.org)
    print_field('ASN:', geo.asn)

def print_ripe_section(ripe: RipeStatInfo) -> None:
    print_section('ASN & ROUTING')
    announced_color = G if ripe.announced else R
    print_field('Announced:', 'Yes' if ripe.announced else 'No', announced_color)
    print_field('BGP Prefix:', ripe.prefix)
    print_field('RIR:', ripe.rir)
    print_field('Allocation:', ripe.allocation_status)
    print_field('ASN:', f'AS{ripe.asn}' if ripe.asn != 'N/A' else 'N/A')
    print_field('ASN Holder:', ripe.asn_name)

    if ripe.abuse_contacts:
        print(f'\n  {DIM}{"─" * 20} Abuse Contacts {"─" * 15}{RESET}')
        for contact in ripe.abuse_contacts:
            print(f'    {Y}{contact}{RESET}')
    else:
        print_field('Abuse Contacts:', 'None found')

    if ripe.bgp_peers:
        print(f'\n  {DIM}{"─" * 20} BGP Routing Peers {"─" * 12}{RESET}')
        for peer in ripe.bgp_peers:
            print(f'    {DIM}{peer}{RESET}')

def print_asn_detail_section(asn_detail: AsnDetail, asn: str) -> None:
    print_section(f'ASN DETAIL  (AS{asn})')

    print_field('First Seen Routing:', asn_detail.first_seen[:10] if asn_detail.first_seen != 'N/A' else 'N/A')
    print_field('Last Seen Routing:', asn_detail.last_seen[:10] if asn_detail.last_seen != 'N/A' else 'N/A')
    print_field('Upstream Neighbours:', str(asn_detail.neighbour_count_left))
    print_field('Downstream Neighbours:', str(asn_detail.neighbour_count_right))

    if asn_detail.upstream_peers:
        print(f'\n  {DIM}{"─" * 20} Upstream Peers {"─" * 15}{RESET}')
        for peer in asn_detail.upstream_peers:
            print(f'    {C}{peer}{RESET}')

    if asn_detail.downstream_peers:
        print(f'\n  {DIM}{"─" * 20} Downstream Peers {"─" * 13}{RESET}')
        for peer in asn_detail.downstream_peers:
            print(f'    {DIM}{peer}{RESET}')

    if asn_detail.routing_history:
        print(f'\n  {DIM}{"─" * 20} Routing History {"─" * 14}{RESET}')
        for entry in asn_detail.routing_history:
            print(f'    {DIM}{entry}{RESET}')

def print_passive_dns_section(entries: list[PassiveDnsEntry]) -> None:
    print_section('PASSIVE DNS')
    if not entries:
        print(f'  {DIM}No passive DNS records found.{RESET}')
        return
    print_field('Records found:', str(len(entries)))
    print()
    for entry in entries:
        print(f'  {C}{entry.rrname:<40}{RESET} {DIM}{entry.rrtype:<8}{RESET} {W}{entry.rdata}{RESET}')
        if entry.last_seen and entry.last_seen != 'N/A':
            print(f'  {DIM}  Last seen: {entry.last_seen}{RESET}')

def print_dns_chain_section(chain: DnsChainResult) -> None:
    print_section(f'DNS CHAIN  ({chain.resource})')

    if chain.forward_nodes:
        print(f'  {DIM}{"─" * 20} Forward Resolution {"─" * 11}{RESET}')
        for node, targets in chain.forward_nodes.items():
            if targets:
                for target in targets:
                    print(f'    {C}{node:<45}{RESET} {DIM}→{RESET} {W}{target}{RESET}')
            else:
                print(f'    {C}{node}{RESET} {DIM}→ (no further resolution){RESET}')

    if chain.reverse_nodes:
        print(f'\n  {DIM}{"─" * 20} Reverse Resolution {"─" * 11}{RESET}')
        for ip, hostnames in chain.reverse_nodes.items():
            for h in hostnames:
                print(f'    {Y}{ip:<45}{RESET} {DIM}→{RESET} {W}{h}{RESET}')

    if chain.nameservers:
        print(f'\n  {DIM}{"─" * 20} Nameservers {"─" * 18}{RESET}')
        for ns in chain.nameservers:
            print(f'    {DIM}{ns}{RESET}')

    if chain.authoritative_nameservers:
        print(f'\n  {DIM}{"─" * 20} Authoritative NSes {"─" * 11}{RESET}')
        for ns in chain.authoritative_nameservers[:10]: # cap — can be very long - can be changed if needed just bump the int
            print(f'    {DIM}{ns}{RESET}')
        if len(chain.authoritative_nameservers) > 10:
            print(f'    {DIM}... and {len(chain.authoritative_nameservers) - 10} more{RESET}')

def print_domain_discovery_section(discovery: DomainDiscovery) -> None:
    print_section('REVERSE IP → DOMAIN DISCOVERY')

    # Break it down now
    for source, domains in discovery.source_map.items():
        if domains:
            label = {
                'hackertarget': 'HackerTarget',
                'tls_san': 'TLS cert SAN',
                'shodan': 'Shodan',
                'passive_dns': 'Passive DNS',
                'rdns': 'Reverse DNS',
            }.get(source, source)
            print_field(f'{label}:', f'{len(domains)} domain(s)', DIM + W)

    print_field('Total unique domains:', str(len(discovery.domains)))

    if not discovery.probed:
        print(f'\n  {DIM}No live HTTP responses from discovered domains.{RESET}')
        return

    print(f'\n  {DIM}{"─" * 20} Live services {"─" * 16}{RESET}')
    print(f'  {DIM}{"Domain":<40} {"Status":<8} {"Title":<40} URL{RESET}')
    print(f'  {DIM}{"─" * 100}{RESET}')

    for entry in discovery.probed:
        status = entry.get('status', 'N/A')
        status_color = G if status.startswith('2') else Y if status.startswith('3') else R
        domain = entry.get('domain', '')[:38]
        title  = entry.get('title', 'N/A')[:38]
        url = entry.get('url', '')

        print(
            f'  {C}{domain:<40}{RESET}'
            f'{status_color}{status:<8}{RESET}'
            f'{W}{title:<40}{RESET}'
            f'{DIM}{url}{RESET}'
        )
        if entry.get('redirect'):
            print(f'  {DIM}    ↳ redirects to: {entry["redirect"]}{RESET}')

    # Handy clickable links summary
    print(f'\n  {DIM}{"─" * 20} URLs {"─" * 25}{RESET}')
    for entry in discovery.probed:
        if entry.get('status', '').startswith('2'):
            print(f'  {G}↳ {entry["url"]}{RESET}')
        elif entry.get('status') not in ('N/A', ''):
            print(f'  {Y}↳ {entry["url"]}  ({entry["status"]}){RESET}')

def print_port_section(ports: list[PortResult]) -> None:
    print_section('COMMON PORT PROBE  (direct TCP)')
    if not ports:
        print(f'  {G}No common ports found open.{RESET}')
        return
    print_field('Open ports found:', str(len(ports)))
    print()
    for p in ports:
        banner_str = f'  {DIM}↳ {p.banner}{RESET}' if p.banner else ''
        print(f'  {R}{p.port:<7}{RESET}{W}{p.service}{RESET}')
        if banner_str:
            print(f'  {banner_str}')

def print_hosting_section(hc: HostingClassification, is_tor: bool) -> None:
    print_section('HOST CLASSIFICATION')

    cat_color = R if 'Datacenter' in hc.category else G if 'Residential' in hc.category else Y
    conf_color = G if hc.confidence == 'High' else Y if hc.confidence == 'Medium' else DIM + W

    print_field('Category:', hc.category, cat_color)
    print_field('Confidence:', hc.confidence, conf_color)

    tor_color = R if is_tor else G
    print_field('Tor Exit Node:', 'YES' if is_tor else 'No', tor_color)

    if hc.signals:
        print(f'\n  {DIM}{"─" * 20} Signals {"─" * 22}{RESET}')
        for signal in hc.signals:
            print(f'    {DIM}⟶  {signal}{RESET}')

def print_shodan_section(shodan: ShodanInfo) -> None:
    print_section('SHODAN HOST DATA')
    print_field('Organisation:', shodan.org)
    print_field('ISP:', shodan.isp)
    print_field('OS:', shodan.os)
    print_field('Last Updated:', shodan.last_update)

    if shodan.hostnames:
        print(f'\n  {DIM}{"─" * 20} Hostnames {"─" * 20}{RESET}')
        for h in shodan.hostnames:
            print(f'    {C}{h}{RESET}')

    if shodan.domains:
        print(f'\n  {DIM}{"─" * 20} Domains {"─" * 22}{RESET}')
        for d in shodan.domains:
            print(f'    {C}{d}{RESET}')

    if shodan.tags:
        print(f'\n  {DIM}{"─" * 20} Tags {"─" * 25}{RESET}')
        for tag in shodan.tags:
            print(f'    {Y}{tag}{RESET}')

    if shodan.port_details:
        print(f'\n  {DIM}{"─" * 20} Open Ports & Services {"─" * 8}{RESET}')
        for detail in shodan.port_details:
            product = detail.get('product', '')
            version = detail.get('version', '')
            svc_str = f'{product} {version}'.strip() or 'N/A'
            print(f'    {R}{detail["port"]}/{detail["transport"]:<8}{RESET}{W}{svc_str}{RESET}')
            banner = detail.get('banner', '')
            if banner:
                print(f'      {DIM}↳ {banner}{RESET}')
    elif shodan.open_ports:
        print(f'\n  {DIM}{"─" * 20} Open Ports {"─" * 19}{RESET}')
        print(f'    {R}{", ".join(str(p) for p in shodan.open_ports)}{RESET}')

def print_abuse_section(abuse: AbuseInfo) -> None:
    print_section('ABUSE / REPUTATION')

    score = abuse.abuse_confidence_score
    score_color = R if score >= 50 else Y if score >= 15 else G
    print_field('Confidence Score (0-100):', str(score), score_color)
    print_field('Total Reports (90 days):', str(abuse.total_reports))
    print_field('Distinct Reporters:', str(abuse.num_distinct_users))
    print_field('Last Reported:', abuse.last_reported_at)
    print_field('Whitelisted:', 'Yes' if abuse.is_whitelisted else 'No',
                G if abuse.is_whitelisted else DIM + W)
    print_field('ISP:', abuse.isp)
    print_field('Domain:', abuse.domain)
    print_field('Usage Type:', abuse.usage_type)
    print_field('Country:', abuse.country_code)

def print_ping_section(ping: PingResult) -> None:
    print_section('ICMP PING  (RTT & Packet Loss)')

    if ping.error:
        print(f'  {R}Ping failed: {ping.error}{RESET}')
        return

    loss = ping.packet_loss_pct
    loss_color = G if loss == 0 else Y if loss < 30 else R
    recv_color = G if ping.packets_received == ping.packets_sent else Y if ping.packets_received > 0 else R

    print_field('Packets sent:', str(ping.packets_sent))
    print_field('Packets received:', str(ping.packets_received), recv_color)
    print_field('Packet loss:', f'{loss:.1f}%', loss_color)

    if ping.packets_received == 0:
        print(f'\n  {Y}Host did not respond to ICMP — may be filtered by firewall.{RESET}')
        return

    # RTT coloring: green <50ms, yellow <150ms, red >=150ms
    def rtt_color(ms: float) -> str:
        return G if ms < 50 else Y if ms < 150 else R

    print()
    print_field('RTT min:', f'{ping.rtt_min_ms:.2f} ms', rtt_color(ping.rtt_min_ms))
    print_field('RTT avg:', f'{ping.rtt_avg_ms:.2f} ms', rtt_color(ping.rtt_avg_ms))
    print_field('RTT max:', f'{ping.rtt_max_ms:.2f} ms', rtt_color(ping.rtt_max_ms))
    print_field('Jitter (mdev):', f'{ping.rtt_mdev_ms:.2f} ms',
                G if ping.rtt_mdev_ms < 5 else Y if ping.rtt_mdev_ms < 20 else R)

# Save
def save_report(report: IpReport) -> None:
    '''Save full report to JSON.'''
    data: dict[str, object] = {
        'scan_time': report.scan_time,
        'target': report.target,
        'ip_version': report.ip_version,
        'is_private': report.is_private,
        'is_loopback': report.is_loopback,
        'rdns': report.rdns,
        'geo': asdict(report.geo) if report.geo else None,
        'ripe': asdict(report.ripe) if report.ripe else None,
        'asn_detail': asdict(report.asn_detail) if report.asn_detail else None,
        'passive_dns': [asdict(e) for e in report.passive_dns],
        'dns_chain': asdict(report.dns_chain) if report.dns_chain else None,
        'domain_discovery': asdict(report.domain_discovery) if report.domain_discovery else None,
        'ports': [asdict(p) for p in report.ports],
        'hosting_class': asdict(report.hosting_class) if report.hosting_class else None,
        'is_tor': report.is_tor,
        'shodan': asdict(report.shodan) if report.shodan else None,
        'abuse': asdict(report.abuse) if report.abuse else None,
        'ping': asdict(report.ping) if report.ping else None,
    }
    safe_ip = report.target.replace(':', '_').replace('.', '_') # :.
    filename = f'ip_osint_{safe_ip}.json'
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    print(f'{G}  Report saved → {filename}{RESET}\n')

# Main
def main() -> None:
    save = '--save' in sys.argv

    print(BANNER)

    raw = get_ip_input()

    # Validate
    try:
        addr, is_private, is_loopback = classify_ip(raw)
    except ValueError:
        print(f'\n{R}  Invalid IP address: {raw!r}{RESET}')
        sys.exit(1)

    ip_str  = str(addr)
    ip_version = addr.version
    is_tor: bool = False

    # Private / loopback show local info and exit
    if is_private or is_loopback:
        kind = 'loopback' if is_loopback else 'private (RFC1918)'
        print(f'\n{Y}  {ip_str} is a {kind} address — running local interface scan.{RESET}')
        print(f'{DIM}  OSINT modules skipped (no routable target).{RESET}\n')
        print(f'{DIM} Scan time : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{RESET}')
        print(f'{DIM} Target    : {ip_str}{RESET}')

        local = get_local_info()
        print_local_section(local)

        rdns = reverse_dns(ip_str)
        print_section('IP CLASSIFICATION')
        print_field('Target IP:', ip_str)
        print_field('IP Version:', f'IPv{ip_version}')
        print_field('Type:', kind.title(), Y)
        print_field('Reverse DNS:', rdns)
        print(f'\n{DIVIDER}\n')
        return

    # Public IP
    print(f'\n{DIM} Scan time : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{RESET}')
    print(f'{DIM} Target    : {ip_str}{RESET}')

    print(f'\n{DIM}Reverse DNS lookup...{RESET}')
    rdns = reverse_dns(ip_str)

    print(f'{DIM}Fetching geolocation...{RESET}')
    geo = fetch_geo(ip_str)

    print(f'{DIM}Querying RIPEstat (prefix, ASN, abuse contacts)...{RESET}')
    ripe = fetch_ripestat(ip_str)

    asn_detail: AsnDetail | None = None
    if ripe and ripe.asn != 'N/A':
        print(f'{DIM}Fetching ASN routing history and neighbours...{RESET}')
        asn_detail = fetch_asn_detail(ripe.asn)

    print(f'{DIM}Fetching passive DNS...{RESET}')
    passive_dns = fetch_passive_dns(ip_str)

    dns_chain: DnsChainResult | None = None
    dns_chain_target = rdns if rdns != 'N/A' else ( # Use rdns hostname if available, elsefall back to first passive DNS entry
        passive_dns[0].rrname if passive_dns else None
    )
    if dns_chain_target:
        print(f'{DIM}Fetching DNS chain for {dns_chain_target}...{RESET}')
        dns_chain = fetch_dns_chain(dns_chain_target)

    # Optional: Shodan
    shodan: ShodanInfo | None = None
    if SHODAN_API_KEY.strip():
        print(f'{DIM}Querying Shodan...{RESET}')
        shodan = fetch_shodan(ip_str, SHODAN_API_KEY)

    # Optional: AbuseIPDB
    abuse: AbuseInfo | None = None
    if ABUSEIPDB_API_KEY.strip():
        print(f'{DIM}Querying AbuseIPDB...{RESET}')
        abuse = fetch_abuseipdb(ip_str, ABUSEIPDB_API_KEY)

    print(f'{DIM}Discovering hosted domains (reverse IP)...{RESET}')
    domain_discovery = discover_domains(ip_str, rdns, passive_dns, shodan)

    print(f'{DIM}Checking Tor exit node list...{RESET}')
    is_tor: bool = check_tor_exit(ip_str)

    print(f'{DIM}Classifying host type...{RESET}')
    asn_name: str = ripe.asn_name if ripe else ''
    org: str = geo.org if geo else ''
    prefix: str = ripe.prefix if ripe else 'N/A'
    hosting_class: HostingClassification = classify_hosting(asn_name, org, prefix)

    # Assemble report (no ports yet - prompt next)
    report = IpReport(
        target=ip_str,
        scan_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        ip_version=ip_version,
        is_private=is_private,
        is_loopback=is_loopback,
        rdns=rdns,
        geo=geo,
        ripe=ripe,
        asn_detail=asn_detail,
        passive_dns=passive_dns,
        dns_chain=dns_chain,
        domain_discovery=domain_discovery,
        ports=[],
        hosting_class=hosting_class,
        is_tor=is_tor,
        shodan=shodan,
        abuse=abuse,
        ping=None,
    )

    # Print core report
    print_classification_section(report)
    if report.hosting_class:
        print_hosting_section(report.hosting_class, report.is_tor)
    if geo:
        print_geo_section(geo)
    else:
        print(f'\n  {Y}Geolocation unavailable.{RESET}')
    if ripe:
        print_ripe_section(ripe)
        if report.asn_detail and ripe:
            print_asn_detail_section(report.asn_detail, ripe.asn)
    else:
        print(f'\n  {Y}RIPEstat data unavailable.{RESET}')

    print_passive_dns_section(passive_dns)
    if report.dns_chain:
        print_dns_chain_section(report.dns_chain)

    if report.domain_discovery:
        print_domain_discovery_section(report.domain_discovery)

    if shodan:
        print_shodan_section(shodan)
    elif not SHODAN_API_KEY.strip():
        print(f'\n  {DIM}Shodan enrichment skipped (no API key set).{RESET}')

    if abuse:
        print_abuse_section(abuse)
    elif not ABUSEIPDB_API_KEY.strip():
        print(f'\n  {DIM}AbuseIPDB enrichment skipped (no API key set).{RESET}')

    # Ping
    print(f'\n{Y}Run ICMP ping? Sends {10} packets to measure RTT and packet loss.{RESET}')
    ping_choice = input(f'{C}> Ping target? [y/N]: {RESET}').strip().lower()
    if ping_choice == 'y':
        print(f'\n{DIM}Pinging {ip_str}...{RESET}')
        report.ping = run_ping(ip_str, count=10)
        print_ping_section(report.ping)

    # Optional port probe
    print(f'\n{Y}Run common port probe? Checks {len(COMMON_PORTS)} ports via direct TCP connect.{RESET}')
    # Skip port prompt if Shodan already has port data
    if shodan and shodan.open_ports:
        print(f'{DIM}  (Shodan already provided port data — probe still available if wanted){RESET}')
    port_choice = input(f'{C}> Probe common ports? [y/N]: {RESET}').strip().lower()
    if port_choice == 'y':
        print(f'\n{DIM}Probing {len(COMMON_PORTS)} common ports (concurrent, {PORT_TIMEOUT}s timeout)...{RESET}')
        report.ports = probe_common_ports(ip_str)
        print_port_section(report.ports)

    print(f'\n{DIVIDER}\n')

    # Save prompt
    if not save:
        save_choice = input(f'{C}> Save report to current directory? [y/N]: {RESET}').strip().lower()
        if save_choice == 'y':
            save = True

    if save:
        save_report(report)


if __name__ == '__main__':
    main()