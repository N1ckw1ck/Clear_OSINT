#!/usr/bin/env python3

'''
(Clear Web) Domain (URL) OSINT Tool
For authorized research and investigative purposes only.
Be a little careful with this one.
Scraping may or may not be illegal.
Please don't break any laws.
'''

import sys
import json
import ssl
import socket
import time
import re
import dns.resolver
import whois # type: ignore
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, urldefrag
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from collections import deque

# Crawling through links can be exhausting
DEFAULT_MAX_PAGES: int = 20 # Default to 20 maximum pages visited
MAX_PAGES_LIMIT: int = 50 # This could be changed

# ANSI styling
R = '\033[91m'
G = '\033[92m'
Y = '\033[93m'
B = '\033[94m'
M = '\033[95m'
C = '\033[96m'
W = '\033[97m'
DIM = '\033[2m'
BOLD = '\033[1m'
RESET = '\033[0m'

BANNER = f'''
{M}{BOLD}
 ██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗ ██████╗ ██╗███╗   ██╗████████╗
 ██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║██╔════╝ ██║████╗  ██║╚══██╔══╝
 ██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║╚█████╗  ██║██╔██╗ ██║   ██║
 ██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║ ╚═══██╗ ██║██║╚██╗██║   ██║
 ██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║██████╔╝ ██║██║ ╚████║   ██║
 ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝  ╚═╝╚═╝  ╚═══╝   ╚═╝
{RESET}{DIM}  Domain OSINT Tool | Authorized research use only{RESET}
'''

DIVIDER = f'{DIM}{"─" * 62}{RESET}'

# Headers - attempt to blend in as a real browser
REQUEST_HEADERS: dict[str, str] = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                  '(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,'
              'image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
}

# Security headers worth checking for
SECURITY_HEADERS: list[str] = [
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Referrer-Policy',
    'Permissions-Policy',
    'X-XSS-Protection',
]

EMAIL_REGEX = re.compile(
    r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', # This could be better
    re.IGNORECASE
)

SERVER_VERSION_REGEX = re.compile(r'[\w\-]+/(\d+\.\d+[\.\d]*)', re.IGNORECASE) # Version extraction from strings like "Apache/2.4.51"

# Common ports to scan
COMMON_PORTS: list[tuple[int, str]] = [
    (21, 'FTP'),
    (22, 'SSH'),
    (23, 'Telnet'),
    (25, 'SMTP'),
    (80, 'HTTP'),
    (443, 'HTTPS'),
    (445, 'SMB'),
    (3306, 'MySQL'),
    (3389, 'RDP'),
    (5432, 'PostgreSQL'),
    (6379, 'Redis'),
    (8080, 'HTTP-Alt'),
    (8443, 'HTTPS-Alt'),
    (27017, 'MongoDB'),
]

# Sensitive paths to probe
SENSITIVE_PATHS: list[tuple[str, str]] = [
    ('/.git/HEAD', 'Git repository exposure'),
    ('/.env', '.env file exposure'),
    ('/phpinfo.php', 'PHP info page'),
    ('/.htaccess', '.htaccess exposure'),
    ('/.DS_Store', '.DS_Store exposure'),
    ('/config.php', 'Config file exposure'),
    ('/backup.zip', 'Backup archive exposure'),
    ('/wp-login.php', 'WordPress login page'),
    ('/wp-admin/', 'WordPress admin panel'),
    ('/xmlrpc.php', 'WordPress XML-RPC'),
    ('/wp-json/wp/v2/users', 'WordPress user enumeration'),
    ('/readme.html', 'WordPress readme'),
    ('/robots.txt', 'Robots.txt (informational)'),
    ('/sitemap.xml', 'Sitemap (informational)'),
    ('/.well-known/security.txt', 'Security.txt policy'),
]

# Known WordPress versions with known critical vulnerabilities (version: CVE summary)
# Covers major milestones not exhaustive 
# Should fix / enhance
WORDPRESS_VULN_MAP: dict[str, str] = {
    '6.4':  'CVE-2023-5561 (6.4.0-6.4.2): RCE via PHP object injection',
    '6.3':  'CVE-2023-39999 (6.3.x): Exposure of user emails',
    '6.2':  'CVE-2023-2745 (6.2.0): Path traversal via translation strings',
    '6.1':  'CVE-2023-22622 (6.1.x): Authenticated SQLi via WP_Date_Query',
    '6.0':  'CVE-2022-21663 (6.0.x): Stored XSS via crafted post',
    '5.9':  'CVE-2022-3590 (5.9.x): Unauthenticated blind SSRF',
    '5.8':  'CVE-2021-44223 (5.8.x): Prototype pollution via Lodash',
    '5.7':  'CVE-2021-29447 (5.7.x): XXE via media upload',
    '5.6':  'CVE-2021-29450 (5.6.x): Authenticated RFI',
    '5.5':  'Multiple XSS and auth bypass issues (legacy)',
}

# Helpers
def print_section(title: str) -> None:
    print(f'\n{M}{BOLD}[ {title} ]{RESET}')
    print(DIVIDER)

def print_field(label: str, value: str, color: str = W) -> None:
    print(f'  {DIM}{label:<28}{RESET}{color}{value}{RESET}')

def print_flag(label: str, present: bool, good_when_present: bool = True) -> None:
    if present:
        color = G if good_when_present else R
        status = 'Present'
    else:
        color = R if good_when_present else G
        status = 'Missing'
    print_field(label, status, color)

# Dataclasses
@dataclass
class DnsInfo:
    a_records: list[str]
    ptr_records: list[str]
    mx_records: list[str]
    ns_records: list[str]
    txt_records: list[str]

@dataclass
class WhoisInfo:
    registrar: str
    creation_date: str
    expiration_date: str
    updated_date: str
    name_servers: list[str]
    registrant_country: str
    dnssec: str
    raw_available: bool

@dataclass
class SslInfo:
    issued_to: str
    issued_by: str
    valid_from: str
    valid_until: str
    days_remaining: int
    subject_alt_names: list[str]
    version: str
    serial_number: str

@dataclass
class HttpInfo:
    status_code: int
    redirect_chain: list[str]
    server: str
    powered_by: str
    content_type: str
    security_headers_present: list[str]
    security_headers_missing: list[str]
    all_headers: dict[str, str]

@dataclass
class TechFingerprint:
    web_server: str
    programming_language: str
    cdn_provider: str
    hosting_provider: str
    cms: str
    framework: str
    other: list[str]

@dataclass
class RiskScore:
    score: int
    level: str
    flags: list[str]

@dataclass
class IpqsUrlScan:
    safe: str
    suspicious: str
    malware: str
    phishing: str
    risk_score: str
    parked: str
    spamming: str
    scrape_success: bool

@dataclass
class CrawlResult:
    pages_crawled: int
    pages_attempted: int
    truncated: bool
    internal_links: list[str]
    external_domains: list[str]
    emails: list[str]
    domain_link_map: dict[str, list[str]]

@dataclass
class ExposedPath:
    path: str
    description: str
    status_code: int
    exposed: bool # True = potentially sensitive (200/401/403)
    note: str

@dataclass
class SensitivePathResult:
    paths_checked: int
    exposed: list[ExposedPath]
    informational: list[ExposedPath]
    robots_disallowed: list[str] # Disallow entries from robots.txt
    sitemap_urls_found: int

@dataclass
class WordPressInfo:
    detected: bool
    version: str # 'Unknown' if not found
    version_source: str
    vuln_note: str
    xmlrpc_enabled: bool
    user_enum_exposed: bool # /wp-json/wp/v2/users returned user data
    login_exposed: bool
    admin_exposed: bool
    readme_exposed: bool
    exposed_usernames: list[str]

@dataclass
class EmailSecurityInfo:
    spf_record: str
    spf_policy: str # 'pass', 'softfail', 'fail', 'neutral', 'none'
    spf_issue: str
    dmarc_record: str
    dmarc_policy: str # 'none', 'quarantine', 'reject', 'missing'
    dmarc_issue: str
    dkim_selectors_found: list[str]
    dkim_selectors_checked: list[str]

@dataclass
class PortScanResult:
    ports_scanned: list[int]
    open_ports: list[tuple[int, str]]
    closed_ports: list[int]
    timeout_seconds: float

@dataclass
class HttpMethodResult:
    allowed_methods: list[str]
    risky_methods: list[str] # put, delete, trace, connect found open
    options_status: int

@dataclass
class CspQuality:
    header_present: bool
    raw_value: str
    issues: list[str]
    grade: str # 'Good', 'Weak', 'Missing'

@dataclass
class ServerVersionInfo:
    server_header: str
    version_detected: str
    powered_by: str
    version_risks: list[str]

@dataclass
class DomainReport:
    target: str
    scan_time: str
    ip_address: str
    dns: DnsInfo
    whois: WhoisInfo
    ssl: SslInfo | None
    http: HttpInfo | None
    tech: TechFingerprint | None
    risk: RiskScore | None
    ipqs_scan: IpqsUrlScan | None
    crawl: CrawlResult | None
    sensitive_paths: SensitivePathResult | None
    wordpress: WordPressInfo | None
    email_security: EmailSecurityInfo | None
    port_scan: PortScanResult | None
    http_methods: HttpMethodResult | None
    csp_quality: CspQuality | None
    server_version: ServerVersionInfo | None


# Input
def get_domain_input() -> tuple[str, int]:
    '''Prompt for target domain and crawl page limit.'''
    print(f'\n{Y}Enter target domain:{RESET}')
    raw = input(f'{C}> Domain (e.g. example.com): {RESET}').strip()

    if not raw.startswith('http://') and not raw.startswith('https://'):
        raw = 'https://' + raw

    parsed = urlparse(raw)
    domain = parsed.netloc or parsed.path

    print(f'\n{Y}Max pages to crawl (1-{MAX_PAGES_LIMIT}, default {DEFAULT_MAX_PAGES}):{RESET}')
    raw_limit = input(f'{C}> Max pages: {RESET}').strip()

    if not raw_limit:
        limit = DEFAULT_MAX_PAGES
    else:
        try:
            limit = int(raw_limit)
            limit = max(1, min(MAX_PAGES_LIMIT, limit))
        except ValueError:
            print(f'{Y}Invalid input, using default of {DEFAULT_MAX_PAGES}.{RESET}')
            limit = DEFAULT_MAX_PAGES

    return domain, limit

# DNS resolution
def resolve_dns(domain: str) -> tuple[str, DnsInfo]:
    '''Resolve all DNS records for the domain. Returns primary IP and DnsInfo.'''
    resolver = dns.resolver.Resolver()

    def query(qtype: str) -> list[str]:
        try:
            answers = resolver.resolve(domain, qtype)
            return [r.to_text() for r in answers]
        except Exception:
            return []

    a_records = query('A')
    ip_address = a_records[0].strip('"') if a_records else 'Unknown'

    ptr_records: list[str] = []
    for ip in a_records:
        try:
            ptr = socket.gethostbyaddr(ip)
            ptr_records.append(ptr[0])
        except Exception:
            pass

    mx_records = query('MX')
    ns_records = query('NS')
    txt_records = query('TXT')

    return ip_address, DnsInfo(
        a_records=a_records,
        ptr_records=ptr_records,
        mx_records=mx_records,
        ns_records=ns_records,
        txt_records=txt_records,
    )

# whois
def fetch_whois(domain: str) -> WhoisInfo:
    '''Fetch WHOIS registration data for the domain.'''
    def fmt_date(val: object) -> str:
        if val is None:
            return 'N/A'
        if isinstance(val, list):
            val = val[0] # type: ignore
        if isinstance(val, datetime):
            return val.strftime('%Y-%m-%d')
        return str(val) # type: ignore

    try:
        w = whois.whois(domain)
        ns = w.name_servers or [] # type: ignore
        if isinstance(ns, str):
            ns = [ns]
        ns_clean: list[str] = [str(n).lower() for n in ns] # type: ignore

        return WhoisInfo(
            registrar=str(w.registrar or 'N/A'), # type: ignore
            creation_date=fmt_date(w.creation_date), # type: ignore
            expiration_date=fmt_date(w.expiration_date), # type: ignore
            updated_date=fmt_date(w.updated_date), # type: ignore
            name_servers=ns_clean,
            registrant_country=str(w.country or 'N/A'), # type: ignore
            dnssec=str(w.dnssec or 'N/A'), # type: ignore
            raw_available=True,
        )
    except Exception:
        return WhoisInfo(
            registrar='N/A',
            creation_date='N/A',
            expiration_date='N/A',
            updated_date='N/A',
            name_servers=[],
            registrant_country='N/A',
            dnssec='N/A',
            raw_available=False,
        )

# SSL / TLS
def fetch_ssl(domain: str) -> SslInfo | None:
    '''Fetch SSL certificate details for the domain.'''
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=domain,
        )
        conn.settimeout(8)
        conn.connect((domain, 443))
        cert: dict[str, object] = conn.getpeercert() # type: ignore
        conn.close()

        def parse_date(val: object) -> str:
            if isinstance(val, str):
                try:
                    return datetime.strptime(val, '%b %d %H:%M:%S %Y %Z').strftime('%Y-%m-%d')
                except Exception:
                    return str(val)
            return 'N/A'

        not_before = parse_date(cert.get('notBefore'))
        not_after_raw = cert.get('notAfter')
        not_after = parse_date(not_after_raw)

        days_remaining = 0
        if isinstance(not_after_raw, str):
            try:
                expiry = datetime.strptime(not_after_raw, '%b %d %H:%M:%S %Y %Z')
                days_remaining = (expiry - datetime.now(timezone.utc).replace(tzinfo=None)).days
            except Exception:
                pass

        subject: dict[str, str] = dict(x[0] for x in cert.get('subject', [])) # type: ignore
        issuer: dict[str, str] = dict(x[0] for x in cert.get('issuer', [])) # type: ignore

        sans: list[str] = []
        for entry in cert.get('subjectAltName', []): # type: ignore
            if isinstance(entry, tuple) and entry[0] == 'DNS':
                sans.append(str(entry[1])) # type: ignore

        return SslInfo(
            issued_to=str(subject.get('commonName', 'N/A')),
            issued_by=str(issuer.get('organizationName', 'N/A')),
            valid_from=not_before,
            valid_until=not_after,
            days_remaining=days_remaining,
            subject_alt_names=sans,
            version=str(cert.get('version', 'N/A')), # type: ignore
            serial_number=str(cert.get('serialNumber', 'N/A')), # type: ignore
        )
    except Exception:
        return None

# HTTP headers
def fetch_http_info(domain: str) -> HttpInfo | None:
    '''Fetch HTTP response headers and check for security headers.'''
    url = f'https://{domain}'
    try:
        session = requests.Session()
        response = session.get(
            url,
            headers=REQUEST_HEADERS,
            timeout=10,
            allow_redirects=True,
        )

        redirect_chain: list[str] = [r.url for r in response.history]
        all_headers: dict[str, str] = dict(response.headers)

        present: list[str] = []
        missing: list[str] = []
        for h in SECURITY_HEADERS:
            if h.lower() in {k.lower() for k in all_headers}:
                present.append(h)
            else:
                missing.append(h)

        return HttpInfo(
            status_code=response.status_code,
            redirect_chain=redirect_chain,
            server=all_headers.get('Server', all_headers.get('server', 'N/A')),
            powered_by=all_headers.get('X-Powered-By', all_headers.get('x-powered-by', 'N/A')),
            content_type=all_headers.get('Content-Type', all_headers.get('content-type', 'N/A')),
            security_headers_present=present,
            security_headers_missing=missing,
            all_headers=all_headers,
        )
    except Exception:
        return None

# Technology fingerprint
def fingerprint_tech(headers: dict[str, str], soup: BeautifulSoup | None) -> TechFingerprint:
    '''Fingerprint web technologies from response headers and HTML content.'''
    headers_lower = {k.lower(): v for k, v in headers.items()}
    other: list[str] = []

    web_server = headers_lower.get('server', 'Unknown')

    language = 'Unknown'
    powered_by = headers_lower.get('x-powered-by', '')
    if powered_by:
        language = powered_by
    elif 'php' in headers_lower.get('x-pingback', '').lower():
        language = 'PHP'

    cdn = 'Unknown'
    if 'cf-ray' in headers_lower:
        cdn = 'Cloudflare'
    elif 'x-amz-cf-id' in headers_lower or 'x-amz-request-id' in headers_lower:
        cdn = 'AWS CloudFront'
    elif 'x-azure-ref' in headers_lower:
        cdn = 'Microsoft Azure CDN'
    elif 'x-vercel-id' in headers_lower:
        cdn = 'Vercel'
    elif 'x-fastly-request-id' in headers_lower:
        cdn = 'Fastly'
    elif 'x-cache' in headers_lower and 'cloudfront' in headers_lower.get('x-cache', '').lower():
        cdn = 'AWS CloudFront'
    elif 'x-served-by' in headers_lower and 'akamai' in headers_lower.get('x-served-by', '').lower():
        cdn = 'Akamai'

    hosting = 'Unknown'
    if 'x-vercel-id' in headers_lower:
        hosting = 'Vercel'
    elif 'x-amz-request-id' in headers_lower:
        hosting = 'AWS'
    elif 'x-azure-ref' in headers_lower:
        hosting = 'Microsoft Azure'
    elif 'x-wix-request-id' in headers_lower:
        hosting = 'Wix'
    elif 'x-squarespace-served' in headers_lower:
        hosting = 'Squarespace'
    elif 'x-shopify-stage' in headers_lower:
        hosting = 'Shopify'

    cms = 'Unknown'
    if 'x-wordpress-cache' in headers_lower or 'x-wp-cf-super-cache' in headers_lower:
        cms = 'WordPress'
    elif 'x-drupal-cache' in headers_lower or 'x-drupal-dynamic-cache' in headers_lower:
        cms = 'Drupal'
    elif 'x-joomla-version' in headers_lower:
        cms = 'Joomla'
    elif 'x-shopify-stage' in headers_lower:
        cms = 'Shopify'
    elif 'x-wix-request-id' in headers_lower:
        cms = 'Wix'
    elif 'x-squarespace-served' in headers_lower:
        cms = 'Squarespace'

    if soup is not None and cms == 'Unknown':
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator:
            content = str(generator.get('content', '')).lower() # type: ignore
            if 'wordpress' in content:
                cms = f'WordPress ({generator.get("content", "")})' # type: ignore
            elif 'drupal' in content:
                cms = f'Drupal ({generator.get("content", "")})' # type: ignore
            elif 'joomla' in content:
                cms = f'Joomla ({generator.get("content", "")})' # type: ignore
            elif 'wix' in content:
                cms = 'Wix'
            elif content:
                cms = str(generator.get('content', 'Unknown')) # type: ignore

    if soup is not None and cms == 'Unknown':
        page_text = str(soup)
        if '/wp-content/' in page_text or '/wp-includes/' in page_text:
            cms = 'WordPress'
        elif '/sites/default/files/' in page_text:
            cms = 'Drupal'
        elif 'Shopify.theme' in page_text:
            cms = 'Shopify'

    framework = 'Unknown'
    if soup is not None:
        page_text = str(soup)
        if '__NEXT_DATA__' in page_text:
            framework = 'Next.js'
        elif '__nuxt' in page_text or 'data-n-head' in page_text:
            framework = 'Nuxt.js'
        elif 'data-reactroot' in page_text or 'react' in page_text.lower():
            framework = 'React'
        elif 'ng-version' in page_text or 'ng-app' in page_text:
            framework = 'Angular'
        elif '__gatsby' in page_text:
            framework = 'Gatsby'
        elif 'data-vue-app' in page_text or 'vue.js' in page_text.lower():
            framework = 'Vue.js'
        elif 'svelte' in page_text.lower():
            framework = 'Svelte'

    interesting = [
        'x-generator', 'x-frame-options', 'x-runtime',
        'x-aspnet-version', 'x-aspnetmvc-version',
    ]
    for h in interesting:
        if h in headers_lower and headers_lower[h] not in ('', 'N/A'):
            other.append(f'{h}: {headers_lower[h]}')

    if 'via' in headers_lower:
        other.append(f'Via: {headers_lower["via"]}')

    return TechFingerprint(
        web_server=web_server,
        programming_language=language,
        cdn_provider=cdn,
        hosting_provider=hosting,
        cms=cms,
        framework=framework,
        other=other,
    )

# Risk score
def calculate_risk_score(report_data: dict[str, object]) -> RiskScore:
    '''
    Calculate a low-resource risk score from already-collected data.
    No additional calls or requests required. Not extremely accurate.
    '''
    score = 0
    flags: list[str] = []

    http = report_data.get('http')
    ssl = report_data.get('ssl')
    whois_data = report_data.get('whois')

    if isinstance(http, HttpInfo):
        if http.status_code and http.redirect_chain and not any(
            r.startswith('https://') for r in http.redirect_chain
        ):
            score += 20
            flags.append('Not using HTTPS')

    if ssl is None:
        score += 20
        flags.append('No SSL certificate found')
    elif isinstance(ssl, SslInfo):
        if ssl.days_remaining <= 0:
            score += 20
            flags.append('SSL certificate has expired')
        elif ssl.days_remaining <= 7:
            score += 15
            flags.append(f'SSL certificate expires in {ssl.days_remaining} days')
        elif ssl.days_remaining <= 30:
            score += 5
            flags.append(f'SSL certificate expires in {ssl.days_remaining} days')

    if isinstance(http, HttpInfo):
        missing_count = len(http.security_headers_missing)
        if missing_count >= 5:
            score += 15
            flags.append(f'{missing_count} security headers missing')
        elif missing_count >= 3:
            score += 8
            flags.append(f'{missing_count} security headers missing')

        if http.powered_by != 'N/A':
            score += 5
            flags.append(f'Server software disclosed via X-Powered-By: {http.powered_by}')

        if len(http.redirect_chain) > 2:
            score += 5
            flags.append(f'Long redirect chain ({len(http.redirect_chain)} hops)')

    if isinstance(whois_data, WhoisInfo):
        if whois_data.creation_date not in ('N/A', ''):
            try:
                created = datetime.strptime(whois_data.creation_date, '%Y-%m-%d')
                age_days = (datetime.now() - created).days
                if age_days < 30:
                    score += 20
                    flags.append(f'Domain registered only {age_days} days ago')
                elif age_days < 90:
                    score += 10
                    flags.append(f'Domain registered only {age_days} days ago')
            except ValueError:
                pass

    score = min(score, 100)

    if score >= 60:
        level = 'High Risk'
    elif score >= 30:
        level = 'Medium Risk'
    else:
        level = 'Low Risk'

    return RiskScore(score=score, level=level, flags=flags)

# IPQS scrape
def scrape_ipqs_url_scan(domain: str) -> IpqsUrlScan:
    '''
    Scrape IPQS malicious URL scanner page for domain threat data.
    No API key, scrapes the public results page.
    '''
    url = f'https://www.ipqualityscore.com/threat-feeds/malicious-url-scanner/{domain}'

    defaults = dict(
        safe='Unavailable',
        suspicious='Unavailable',
        malware='Unavailable',
        phishing='Unavailable',
        risk_score='Unavailable',
        parked='Unavailable',
        spamming='Unavailable',
        scrape_success=False,
    )

    try:
        response = requests.get(url, headers=REQUEST_HEADERS, timeout=12)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f'\n  {R}IPQS URL scan request failed: {e}{RESET}')
        return IpqsUrlScan(**defaults) # type: ignore

    try:
        soup = BeautifulSoup(response.text, 'html.parser')
        table = soup.find('table')
        if not table:
            print(f'\n  {Y}IPQS URL scan: could not locate results table.{RESET}')
            return IpqsUrlScan(**defaults) # type: ignore

        rows = table.find_all('tr') # type: ignore

        def get_row_text(index: int) -> str:
            try:
                row = rows[index]
                result_td = row.find('td', class_='right')
                if result_td:
                    span = result_td.find('span')
                    if span:
                        return span.get_text(strip=True)
                    return result_td.get_text(strip=True)
                return 'Unavailable'
            except (IndexError, AttributeError):
                return 'Unavailable'

        return IpqsUrlScan(
            safe=get_row_text(0),
            suspicious=get_row_text(1),
            malware=get_row_text(4),
            phishing=get_row_text(5),
            risk_score=get_row_text(6),
            parked=get_row_text(7),
            spamming=get_row_text(8),
            scrape_success=True,
        )

    except Exception as e:
        print(f'\n  {Y}IPQS URL scan parse error: {e}{RESET}')
        return IpqsUrlScan(**defaults) # type: ignore


# Sensitive path probing
def probe_sensitive_paths(domain: str) -> SensitivePathResult:
    '''
    Probe a list of known-sensitive paths via HEAD (or GET where needed).
    Parses robots.txt and sitemap.xml if found.
    '''
    base = f'https://{domain}'
    session = requests.Session()
    exposed: list[ExposedPath] = []
    informational: list[ExposedPath] = []
    robots_disallowed: list[str] = []
    sitemap_urls_found = 0

    # Paths that need GET to extract content
    get_paths = {'/robots.txt', '/sitemap.xml', '/.git/HEAD', '/wp-json/wp/v2/users', '/xmlrpc.php'}

    for path, description in SENSITIVE_PATHS:
        url = base + path
        try:
            method = 'GET' if path in get_paths else 'HEAD'
            response = session.request(
                method,
                url,
                headers=REQUEST_HEADERS,
                timeout=8,
                allow_redirects=True,
            )
            code = response.status_code
            note = ''
            is_exposed = False

            # Special handling per path
            if path == '/robots.txt' and code == 200:
                for line in response.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith('disallow:'):
                        val = line.split(':', 1)[-1].strip()
                        if val:
                            robots_disallowed.append(val)
                note = f'{len(robots_disallowed)} Disallow entries found'

            elif path == '/sitemap.xml' and code == 200:
                sitemap_urls_found = response.text.count('<loc>')
                note = f'{sitemap_urls_found} <loc> entries found'

            elif path == '/.git/HEAD' and code == 200:
                first_line = response.text.strip().splitlines()[0] if response.text.strip() else ''
                note = f'HEAD content: {first_line[:60]}' if first_line else 'Content readable'
                is_exposed = True

            elif path == '/xmlrpc.php' and code == 200:
                # If POST to xmlrpc and it responds, it's active
                try:
                    xml_payload = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
                    post_resp = session.post(
                        url,
                        data=xml_payload,
                        headers={**REQUEST_HEADERS, 'Content-Type': 'text/xml'},
                        timeout=8,
                    )
                    if post_resp.status_code == 200 and 'methodResponse' in post_resp.text:
                        note = 'XML-RPC is active and responding to POST requests'
                        is_exposed = True
                    else:
                        note = 'Reachable but POST not accepted'
                except Exception:
                    note = 'GET accessible'
                    is_exposed = True

            elif path == '/wp-json/wp/v2/users' and code == 200:
                try:
                    users_data: list[object] = response.json()
                    if len(users_data) > 0:
                        note = f'{len(users_data)} user(s) exposed via REST API'
                        is_exposed = True
                    else:
                        note = 'Endpoint reachable, no user data returned'
                except Exception:
                    note = 'Endpoint reachable'
                    is_exposed = code == 200

            elif code in (200, 401, 403):
                # 401/403 still confirms the path exists
                is_exposed = True
                if code == 401:
                    note = 'Auth required (path confirmed)'
                elif code == 403:
                    note = 'Forbidden (path confirmed)'

            ep = ExposedPath(
                path=path,
                description=description,
                status_code=code,
                exposed=is_exposed or (code in (200, 401, 403) and path not in ('/robots.txt', '/sitemap.xml', '/.well-known/security.txt')),
                note=note,
            )

            # Bucket into exposed vs informational
            info_paths = {'/robots.txt', '/sitemap.xml', '/.well-known/security.txt'}
            if path in info_paths:
                if code == 200:
                    informational.append(ep)
            elif ep.exposed:
                exposed.append(ep)

        except Exception:
            pass  # Silently skip connection errors per path

    return SensitivePathResult(
        paths_checked=len(SENSITIVE_PATHS),
        exposed=exposed,
        informational=informational,
        robots_disallowed=robots_disallowed,
        sitemap_urls_found=sitemap_urls_found,
    )


# WordPress deep scan
def scan_wordpress(domain: str, soup: BeautifulSoup | None, sensitive: SensitivePathResult | None) -> WordPressInfo | None:
    '''
    Deep WordPress scan. Extracts version, checks for exposed endpoints,
    and maps known CVEs. Only runs if WordPress is detected.
    Returns None if WordPress is not detected.
    '''
    base = f'https://{domain}'
    session = requests.Session()

    # Detection signals
    is_wp = False
    if soup is not None:
        page_text = str(soup)
        if '/wp-content/' in page_text or '/wp-includes/' in page_text:
            is_wp = True

    # Also check if sensitive path scan already found WP endpoints
    if sensitive is not None:
        wp_paths = {'/wp-login.php', '/wp-admin/', '/xmlrpc.php', '/wp-json/wp/v2/users', '/readme.html'}
        for ep in sensitive.exposed:
            if ep.path in wp_paths:
                is_wp = True
                break

    if not is_wp:
        return None

    # Version extraction — multiple sources
    version = 'Unknown'
    version_source = 'Not found'

    # <meta name="generator">
    if soup is not None and version == 'Unknown':
        gen = soup.find('meta', attrs={'name': 'generator'})
        if gen:
            content = str(gen.get('content', ''))
            match = re.search(r'WordPress\s+([\d.]+)', content, re.IGNORECASE)
            if match:
                version = match.group(1)
                version_source = 'meta generator tag'

    # ?ver= params on scripts/styles (most common)
    if soup is not None and version == 'Unknown':
        ver_pattern = re.compile(r'\?ver=([\d.]+)')
        for tag in soup.find_all(['script', 'link'], src=True): # type: ignore
            src = str(tag.get('src', '') or tag.get('href', ''))
            if 'wp-' in src:
                match = ver_pattern.search(src)
                if match:
                    version = match.group(1)
                    version_source = '?ver= asset parameter'
                    break
        if version == 'Unknown':
            for tag in soup.find_all('link', href=True): # type: ignore
                href = str(tag.get('href', ''))
                if 'wp-' in href:
                    match = ver_pattern.search(href)
                    if match:
                        version = match.group(1)
                        version_source = '?ver= asset parameter'
                        break

    # /readme.html
    if version == 'Unknown':
        try:
            r = session.get(f'{base}/readme.html', headers=REQUEST_HEADERS, timeout=8)
            if r.status_code == 200:
                match = re.search(r'Version\s+([\d.]+)', r.text, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    version_source = '/readme.html'
        except Exception:
            pass

    # /feed/ (RSS exposes version in generator tag)
    if version == 'Unknown':
        try:
            r = session.get(f'{base}/feed/', headers=REQUEST_HEADERS, timeout=8)
            if r.status_code == 200:
                match = re.search(r'<generator>.*?v=([\d.]+)</generator>', r.text, re.IGNORECASE)
                if not match:
                    match = re.search(r'WordPress ([\d.]+)', r.text, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    version_source = 'RSS /feed/ generator tag'
        except Exception:
            pass

    # Map version to known CVEs
    vuln_note = 'No known CVEs mapped for this version'
    if version != 'Unknown':
        major_minor = '.'.join(version.split('.')[:2])
        vuln_note = WORDPRESS_VULN_MAP.get(major_minor, f'No CVEs mapped for {version} — verify manually')

    # Check xmlrpc
    xmlrpc_enabled = False
    if sensitive is not None:
        for ep in sensitive.exposed:
            if ep.path == '/xmlrpc.php' and 'responding to POST' in ep.note:
                xmlrpc_enabled = True

    # Check user enum exposure
    user_enum_exposed = False
    exposed_usernames: list[str] = []
    try:
        r = session.get(f'{base}/wp-json/wp/v2/users', headers=REQUEST_HEADERS, timeout=8)
        if r.status_code == 200:
            try:
                users: list[dict[str, object]] = r.json()
                for u in users:
                    if 'slug' in u:
                        exposed_usernames.append(str(u['slug']))
                user_enum_exposed = len(exposed_usernames) > 0
            except Exception:
                user_enum_exposed = True
    except Exception:
        pass

    # Presence checks from sensitive paths
    def path_exposed(target_path: str) -> bool:
        if sensitive is None:
            return False
        return any(ep.path == target_path and ep.exposed for ep in sensitive.exposed)

    return WordPressInfo(
        detected=True,
        version=version,
        version_source=version_source,
        vuln_note=vuln_note,
        xmlrpc_enabled=xmlrpc_enabled,
        user_enum_exposed=user_enum_exposed,
        login_exposed=path_exposed('/wp-login.php'),
        admin_exposed=path_exposed('/wp-admin/'),
        readme_exposed=path_exposed('/readme.html'),
        exposed_usernames=exposed_usernames,
    )


# Email security (SPF / DMARC / DKIM)
def check_email_security(domain: str) -> EmailSecurityInfo:
    '''
    Check SPF, DMARC, and common DKIM selectors via DNS TXT lookups.
    Pure DNS — no HTTP requests.
    '''
    resolver = dns.resolver.Resolver()

    def txt_lookup(host: str) -> list[str]:
        try:
            answers = resolver.resolve(host, 'TXT')
            return [r.to_text().strip('"') for r in answers]
        except Exception:
            return []

    # SPF — look in root TXT records
    spf_record = 'Not found'
    spf_policy = 'none'
    spf_issue = ''
    for record in txt_lookup(domain):
        if record.lower().startswith('v=spf1'):
            spf_record = record
            if '+all' in record:
                spf_policy = 'fail'
                spf_issue = '"+all" allows any server to send mail — effectively no restriction'
            elif '~all' in record:
                spf_policy = 'softfail'
                spf_issue = '"~all" is a soft fail — non-conforming mail delivered but marked'
            elif '-all' in record:
                spf_policy = 'pass'
                spf_issue = ''
            elif '?all' in record:
                spf_policy = 'neutral'
                spf_issue = '"?all" is neutral — no enforcement'
            else:
                spf_policy = 'unknown'
                spf_issue = 'No "all" mechanism found — policy unclear'
            break

    if spf_record == 'Not found':
        spf_policy = 'none'
        spf_issue = 'No SPF record — domain is spoofable'

    # DMARC — _dmarc.<domain>
    dmarc_record = 'Not found'
    dmarc_policy = 'missing'
    dmarc_issue = ''
    dmarc_records = txt_lookup(f'_dmarc.{domain}')
    for record in dmarc_records:
        if record.lower().startswith('v=dmarc1'):
            dmarc_record = record
            # Extract p= policy
            match = re.search(r'p=(\w+)', record, re.IGNORECASE)
            if match:
                p = match.group(1).lower()
                dmarc_policy = p
                if p == 'none':
                    dmarc_issue = 'Policy is "none" — monitoring only, no enforcement'
                elif p == 'quarantine':
                    dmarc_issue = 'Policy is "quarantine" — suspicious mail goes to spam'
                elif p == 'reject':
                    dmarc_issue = '' # idk
            else:
                dmarc_issue = 'p= not found in record'
            break

    if dmarc_record == 'Not found':
        dmarc_issue = 'No DMARC record — phishing/spoofing not mitigated'

    # DKIM — probe common selectors
    dkim_selectors_to_check = [
        'default', 'google', 'mail', 'dkim', 'k1', 'k2',
        'selector1', 'selector2', 'smtp', 'email', 'amazonses',
    ]
    dkim_found: list[str] = []
    for selector in dkim_selectors_to_check:
        host = f'{selector}._domainkey.{domain}'
        records = txt_lookup(host)
        for r in records:
            if 'v=dkim1' in r.lower() or 'p=' in r.lower():
                dkim_found.append(selector)
                break

    return EmailSecurityInfo(
        spf_record=spf_record[:120] if len(spf_record) > 120 else spf_record,
        spf_policy=spf_policy,
        spf_issue=spf_issue,
        dmarc_record=dmarc_record[:120] if len(dmarc_record) > 120 else dmarc_record,
        dmarc_policy=dmarc_policy,
        dmarc_issue=dmarc_issue,
        dkim_selectors_found=dkim_found,
        dkim_selectors_checked=dkim_selectors_to_check,
    )

# Port scan
def port_scan(ip: str, timeout: float = 1.5) -> PortScanResult:
    '''
    Scan common ports using stdlib socket only. No external dependencies.
    '''
    open_ports: list[tuple[int, str]] = []
    closed_ports: list[int] = []
    ports_scanned = [p for p, _ in COMMON_PORTS]

    for port, service in COMMON_PORTS:
        print(f'  {DIM}Scanning port {port} ({service})...{RESET}', end='\r')
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            open_ports.append((port, service))
        else:
            closed_ports.append(port)

    print(' ' * 50, end='\r') # Clear the progress line
    return PortScanResult(
        ports_scanned=ports_scanned,
        open_ports=open_ports,
        closed_ports=closed_ports,
        timeout_seconds=timeout,
    )

# HTTP method enumeration
def check_http_methods(domain: str) -> HttpMethodResult:
    '''Send OPTIONS request and parse the Allow header for risky methods.'''
    url = f'https://{domain}'
    risky = {'PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH'}
    allowed: list[str] = []
    risky_found: list[str] = []
    status = 0

    try:
        response = requests.options(url, headers=REQUEST_HEADERS, timeout=8)
        status = response.status_code
        allow_header = response.headers.get('Allow', response.headers.get('allow', ''))
        if allow_header:
            allowed = [m.strip().upper() for m in allow_header.split(',')]
            risky_found = [m for m in allowed if m in risky]
    except Exception:
        pass

    return HttpMethodResult(
        allowed_methods=allowed,
        risky_methods=risky_found,
        options_status=status,
    )

# CSP quality grader
def grade_csp(http: HttpInfo | None) -> CspQuality:
    '''
    Evaluate the Content-Security-Policy header quality.
    Checks for common misconfigurations even when the header is present.
    '''
    if http is None:
        return CspQuality(
            header_present=False,
            raw_value='',
            issues=['No HTTP info available'],
            grade='Missing',
        )

    headers_lower = {k.lower(): v for k, v in http.all_headers.items()}
    csp_value = headers_lower.get('content-security-policy', '')

    if not csp_value:
        return CspQuality(
            header_present=False,
            raw_value='',
            issues=['CSP header is absent'],
            grade='Missing',
        )

    issues: list[str] = []
    csp_lower = csp_value.lower()

    if 'unsafe-inline' in csp_lower:
        issues.append("'unsafe-inline' allows inline scripts/styles — defeats XSS protection")
    if 'unsafe-eval' in csp_lower:
        issues.append("'unsafe-eval' allows eval() — significant XSS risk")
    if "script-src *" in csp_lower or "default-src *" in csp_lower:
        issues.append('Wildcard (*) source in script/default-src — any origin allowed')
    if 'http:' in csp_lower:
        issues.append("'http:' scheme allowed — mixed content and MITM risk")
    if 'data:' in csp_lower and 'script-src' in csp_lower:
        issues.append("'data:' URI in script-src — can be exploited for XSS")

    # Check for missing critical directives
    for directive in ['default-src', 'script-src']:
        if directive not in csp_lower:
            issues.append(f"'{directive}' directive missing")

    grade = 'Good' if not issues else ('Weak' if len(issues) <= 2 else 'Poor')

    return CspQuality(
        header_present=True,
        raw_value=csp_value[:600], # 600 chars, might need to be longer
        issues=issues,
        grade=grade,
    )

# Server version analysis
def analyze_server_version(http: HttpInfo | None) -> ServerVersionInfo:
    '''
    Parse server/powered-by headers for version disclosure and flag concerns.
    '''
    if http is None:
        return ServerVersionInfo(
            server_header='Unknown',
            version_detected='Unknown',
            powered_by='N/A',
            version_risks=[],
        )

    server = http.server
    powered_by = http.powered_by
    version_detected = 'Unknown'
    risks: list[str] = []

    # Try to extract version from Server header
    match = SERVER_VERSION_REGEX.search(server)
    if match:
        version_detected = match.group(1)
        risks.append(f'Server version disclosed in header: {server}')

    # PHP version disclosure is particularly risky
    if powered_by != 'N/A':
        php_match = re.search(r'PHP/([\d.]+)', powered_by, re.IGNORECASE)
        if php_match:
            php_ver = php_match.group(1)
            risks.append(f'PHP version disclosed via X-Powered-By: PHP/{php_ver}')
            # PHP versions before 8.1 are EOL
            try:
                major, minor = int(php_ver.split('.')[0]), int(php_ver.split('.')[1])
                if major < 8 or (major == 8 and minor < 1):
                    risks.append(f'PHP {php_ver} is end-of-life and no longer receives security patches')
            except Exception:
                pass

        asp_match = re.search(r'ASP\.NET\s*([\d.]+)?', powered_by, re.IGNORECASE)
        if asp_match:
            risks.append(f'ASP.NET version disclosed via X-Powered-By: {powered_by}')

    if not risks and server not in ('N/A', 'Unknown', ''):
        risks.append(f'Server header present ({server})')

    return ServerVersionInfo(
        server_header=server,
        version_detected=version_detected,
        powered_by=powered_by,
        version_risks=risks,
    )

# Crawling
def extract_emails(text: str) -> set[str]:
    '''Extract email addresses from a block of text.'''
    return set(EMAIL_REGEX.findall(text))

def extract_links(soup: BeautifulSoup, base_url: str, target_domain: str) -> tuple[set[str], set[str]]:
    '''
    Extract internal and external links from a parsed page.
    Returns (internal_urls, external_domains).
    '''
    internal: set[str] = set()
    external: set[str] = set()

    for tag in soup.find_all('a', href=True):
        href = str(tag['href']).strip()
        if not href or href.startswith('#') or href.startswith('javascript:'):
            continue

        absolute = urljoin(base_url, href)
        absolute, _ = urldefrag(absolute)

        parsed = urlparse(absolute)
        if not parsed.scheme or not parsed.netloc:
            continue

        link_domain = parsed.netloc.lower().lstrip('www.')
        base_domain = target_domain.lower().lstrip('www.')

        if link_domain == base_domain or link_domain.endswith('.' + base_domain):
            internal.add(absolute)
        elif parsed.scheme in ('http', 'https'):
            external.add(parsed.netloc.lower())

    return internal, external


def crawl(domain: str, max_pages: int) -> CrawlResult:
    '''
    Crawl the target domain up to max_pages pages.
    Collects internal links, external domains, emails, and link map.
    '''
    start_url = f'https://{domain}'
    visited: set[str] = set()
    queue: deque[str] = deque([start_url])
    all_internal: set[str] = set()
    all_external: set[str] = set()
    all_emails: set[str] = set()
    domain_link_map: dict[str, list[str]] = {}
    pages_crawled = 0
    pages_attempted = 0

    session = requests.Session()

    while queue and pages_crawled < max_pages:
        url = queue.popleft()

        if url in visited:
            continue
        visited.add(url)
        pages_attempted += 1

        print(f'  {DIM}[{pages_crawled + 1}/{max_pages}] Crawling: {url[:70]}{RESET}')

        try:
            response = session.get(
                url,
                headers=REQUEST_HEADERS,
                timeout=10,
                allow_redirects=True,
            )
            content_type = response.headers.get('Content-Type', '')
            if not content_type or 'text' not in content_type:
                continue

            soup = BeautifulSoup(response.text, 'html.parser')
            pages_crawled += 1

            emails = extract_emails(response.text)
            all_emails.update(emails)

            internal, external = extract_links(soup, response.url, domain)
            all_internal.update(internal)
            all_external.update(external)

            page_path = urlparse(url).path or '/'
            linked_paths: list[str] = [urlparse(link).path or '/' for link in internal]
            domain_link_map[page_path] = linked_paths

            for link in internal:
                if link not in visited:
                    queue.append(link)

        except Exception as e:
            print(f'  {R}Failed: {url[:60]} — {e}{RESET}')

        time.sleep(1)

    truncated = len(queue) > 0 and pages_crawled >= max_pages

    return CrawlResult(
        pages_crawled=pages_crawled,
        pages_attempted=pages_attempted,
        truncated=truncated,
        internal_links=sorted(all_internal),
        external_domains=sorted(all_external),
        emails=sorted(all_emails),
        domain_link_map=domain_link_map,
    )

# Print sections
def print_dns_section(dns_info: DnsInfo, ip: str) -> None:
    print_section('IP & DNS')
    print_field('Primary IP:', ip)

    for record in dns_info.a_records:
        print_field('A Record:', record)
    for record in dns_info.ptr_records:
        print_field('PTR (Reverse DNS):', record)
    for record in dns_info.mx_records:
        print_field('MX Record:', record)
    for record in dns_info.ns_records:
        print_field('NS Record:', record)
    if dns_info.txt_records:
        print(f'\n  {DIM}TXT Records:{RESET}')
        for record in dns_info.txt_records:
            print(f'    {W}{record[:80]}{RESET}')

def print_whois_section(w: WhoisInfo) -> None:
    print_section('WHOIS')
    print_field('Registrar:', w.registrar)
    print_field('Created:', w.creation_date)
    print_field('Expires:', w.expiration_date)
    print_field('Updated:', w.updated_date)
    print_field('Registrant Country:', w.registrant_country)
    print_field('DNSSEC:', w.dnssec)
    for ns in w.name_servers:
        print_field('Name Server:', ns)
    if not w.raw_available:
        print(f'  {Y}WHOIS data unavailable or rate limited.{RESET}')

def print_ssl_section(ssl_info: SslInfo | None) -> None:
    print_section('SSL / TLS CERTIFICATE')
    if ssl_info is None:
        print(f'  {R}Could not retrieve SSL certificate.{RESET}')
        return

    days_color = G if ssl_info.days_remaining > 30 else Y if ssl_info.days_remaining > 7 else R
    print_field('Issued To:', ssl_info.issued_to)
    print_field('Issued By:', ssl_info.issued_by)
    print_field('Valid From:', ssl_info.valid_from)
    print_field('Valid Until:', ssl_info.valid_until)
    print_field('Days Remaining:', str(ssl_info.days_remaining), days_color)
    print_field('Version:', ssl_info.version)
    print_field('Serial Number:', ssl_info.serial_number)
    if ssl_info.subject_alt_names:
        print(f'\n  {DIM}Subject Alternative Names:{RESET}')
        for san in ssl_info.subject_alt_names:
            print(f'    {W}{san}{RESET}')

def print_http_section(http: HttpInfo | None) -> None:
    print_section('HTTP HEADERS & SECURITY')
    if http is None:
        print(f'  {R}Could not retrieve HTTP headers.{RESET}')
        return

    status_color = G if http.status_code < 400 else R
    print_field('Status Code:', str(http.status_code), status_color)
    print_field('Server:', http.server)
    print_field('Powered By:', http.powered_by)
    print_field('Content Type:', http.content_type)

    if http.redirect_chain:
        print(f'\n  {DIM}Redirect Chain:{RESET}')
        for r in http.redirect_chain:
            print(f'    {DIM}→ {W}{r}{RESET}')

    print(f'\n  {DIM}{"─" * 20} Security Headers {"─" * 12}{RESET}')
    for h in http.security_headers_present:
        print_flag(f'{h}:', True)
    for h in http.security_headers_missing:
        print_flag(f'{h}:', False)

def print_tech_section(tech: TechFingerprint) -> None:
    print_section('TECHNOLOGY FINGERPRINT')
    print_field('Web Server:', tech.web_server)
    print_field('Language / Runtime:', tech.programming_language)
    print_field('CDN Provider:', tech.cdn_provider)
    print_field('Hosting Provider:', tech.hosting_provider)
    print_field('CMS:', tech.cms)
    print_field('JS Framework:', tech.framework)
    if tech.other:
        print(f'\n  {DIM}{"─" * 20} Additional Headers {"─" * 11}{RESET}')
        for item in tech.other:
            print(f'    {DIM}{item}{RESET}')

def print_risk_section(risk: RiskScore) -> None:
    print_section('CALCULATED RISK SCORE')
    score_color = R if risk.score >= 60 else Y if risk.score >= 30 else G
    print_field('Score (0-100):', str(risk.score), score_color)
    print_field('Level:', risk.level, score_color)

    if risk.flags:
        print(f'\n  {DIM}{"─" * 20} Risk Factors {"─" * 17}{RESET}')
        for flag in risk.flags:
            print(f'    {Y}⚑ {flag}{RESET}')
    else:
        print(f'\n    {G}No risk factors detected.{RESET}')

def print_ipqs_scan_section(scan: IpqsUrlScan) -> None:
    print_section('URL THREAT SCAN (scraped)')

    if not scan.scrape_success:
        print(f'  {Y}IPQS scan data unavailable — page structure may have changed.{RESET}')
        return

    def threat_color(val: str) -> str:
        lower = val.lower()
        if any(w in lower for w in ['safe', 'no issues', 'no malware', 'no phishing',
                                     'no spam', 'not parked', 'low risk']):
            return G
        if any(w in lower for w in ['high', 'critical', 'malware', 'phishing', 'spam']):
            return R
        return Y

    for label, value in [
        ('Safe:', scan.safe),
        ('Suspicious:', scan.suspicious),
        ('Malware:', scan.malware),
        ('Phishing:', scan.phishing),
        ('Risk Score:', scan.risk_score),
        ('Parked Domain:', scan.parked),
        ('Spamming Domain:', scan.spamming),
    ]:
        print_field(label, value, threat_color(value))

def print_sensitive_paths_section(result: SensitivePathResult) -> None:
    print_section('SENSITIVE PATH PROBE')
    print_field('Paths Checked:', str(result.paths_checked))

    # Exposed paths
    if result.exposed:
        print(f'\n  {DIM}{"─" * 20} Exposed / Accessible {"─" * 9}{RESET}')
        for ep in result.exposed:
            code_color = R if ep.status_code == 200 else Y
            status_str = f'[{ep.status_code}]'
            print(f'  {code_color}{BOLD}{status_str:<7}{RESET}{R}{ep.path:<35}{RESET}  {DIM}{ep.description}{RESET}')
            if ep.note:
                print(f'  {" " * 7}{Y}↳ {ep.note}{RESET}')
    else:
        print(f'\n    {G}No sensitive paths exposed.{RESET}')

    # Informational paths
    if result.informational:
        print(f'\n  {DIM}{"─" * 20} Informational {"─" * 16}{RESET}')
        for ep in result.informational:
            print(f'  {C}[{ep.status_code}]{RESET}   {W}{ep.path:<35}{RESET}  {DIM}{ep.description}{RESET}')
            if ep.note:
                print(f'         {DIM}↳ {ep.note}{RESET}')

    # Robots.txt disallow entries
    if result.robots_disallowed:
        print(f'\n  {DIM}{"─" * 20} robots.txt Disallowed Paths {"─" * 3}{RESET}')
        for path in result.robots_disallowed[:20]:
            print(f'    {Y}{path}{RESET}')
        if '/' in result.robots_disallowed and len(result.robots_disallowed) == 1:
            print(f'    {Y}↳ Disallow: / — crawlers instructed to index nothing{RESET}')
        if len(result.robots_disallowed) > 20:
            print(f'    {DIM}... and {len(result.robots_disallowed) - 20} more{RESET}')

def print_wordpress_section(wp: WordPressInfo) -> None:
    print_section('WORDPRESS ANALYSIS')

    if not wp.detected:
        print(f'  {DIM}WordPress not detected.{RESET}')
        return

    version_color = W if wp.version == 'Unknown' else Y
    print_field('Detected:', 'Yes', G)
    print_field('Version:', wp.version, version_color)
    print_field('Version Source:', wp.version_source, DIM)

    # CVE mapping
    vuln_color = R if 'CVE' in wp.vuln_note else G if 'No CVEs mapped' not in wp.vuln_note else DIM
    print(f'\n  {DIM}{"─" * 20} Known Vulnerabilities {"─" * 8}{RESET}')
    print(f'    {vuln_color}{wp.vuln_note}{RESET}')

    # Endpoint exposure
    print(f'\n  {DIM}{"─" * 20} Endpoint Exposure {"─" * 12}{RESET}')
    print_flag('XML-RPC enabled:',       wp.xmlrpc_enabled,      good_when_present=False)
    print_flag('User enum via REST API:',wp.user_enum_exposed,   good_when_present=False)
    print_flag('Login page exposed:',    wp.login_exposed,       good_when_present=False)
    print_flag('Admin panel exposed:',   wp.admin_exposed,       good_when_present=False)
    print_flag('readme.html exposed:',   wp.readme_exposed,      good_when_present=False)

    if wp.exposed_usernames:
        print(f'\n  {DIM}{"─" * 20} Enumerated Usernames {"─" * 9}{RESET}')
        for user in wp.exposed_usernames:
            print(f'    {R}{user}{RESET}')

def print_email_security_section(es: EmailSecurityInfo) -> None:
    print_section('EMAIL SECURITY (SPF / DMARC / DKIM)')

    # SPF
    print(f'\n  {DIM}{"─" * 24} SPF {"─" * 23}{RESET}')
    spf_color = G if es.spf_policy in ('pass',) else R if es.spf_policy in ('fail', 'none') else Y
    print_field('SPF Record:', es.spf_record if es.spf_record != 'Not found' else 'None found', spf_color)
    print_field('Enforcement:', es.spf_policy.upper(), spf_color)
    if es.spf_issue:
        print(f'    {Y}⚑ {es.spf_issue}{RESET}')

    # DMARC
    print(f'\n  {DIM}{"─" * 23} DMARC {"─" * 22}{RESET}')
    dmarc_color = G if es.dmarc_policy == 'reject' else R if es.dmarc_policy in ('missing',) else Y
    print_field('DMARC Record:', es.dmarc_record if es.dmarc_record != 'Not found' else 'None found', dmarc_color)
    print_field('Policy:', es.dmarc_policy.upper(), dmarc_color)
    if es.dmarc_issue:
        print(f'    {Y}⚑ {es.dmarc_issue}{RESET}')

    # DKIM
    print(f'\n  {DIM}{"─" * 23} DKIM {"─" * 23}{RESET}')
    if es.dkim_selectors_found:
        print_field('Selectors Found:', ', '.join(es.dkim_selectors_found), G)
    else:
        print_field('Selectors Found:', f'None of {len(es.dkim_selectors_checked)} checked', Y)
        print(f'    {DIM}(Checked: {", ".join(es.dkim_selectors_checked)}){RESET}')

def print_port_scan_section(result: PortScanResult) -> None:
    print_section('PORT SCAN')
    print_field('Ports Scanned:', str(len(result.ports_scanned)))
    print_field('Timeout per Port:', f'{result.timeout_seconds}s')

    print(f'\n  {DIM}{"─" * 20} Results {"─" * 22}{RESET}')
    if result.open_ports:
        for port, service in result.open_ports:
            risky_services = {'FTP', 'Telnet', 'SMTP', 'SMB', 'RDP', 'Redis', 'MongoDB', 'MySQL', 'PostgreSQL'}
            color = R if service in risky_services else Y if service in ('HTTP',) else G
            flag = f'{Y} ⚑ Unencrypted/exposed service{RESET}' if service in risky_services else ''
            print(f'  {color}{BOLD}OPEN{RESET}  {W}{port:<8}{RESET}{C}{service:<16}{RESET}{flag}')
    else:
        print(f'    {G}No open ports found on scanned list.{RESET}')

    if result.closed_ports:
        closed_str = ', '.join(str(p) for p in result.closed_ports)
        print(f'\n  {DIM}Closed: {closed_str}{RESET}')

def print_http_methods_section(result: HttpMethodResult) -> None:
    print_section('HTTP METHOD ENUMERATION')
    print_field('OPTIONS Status:', str(result.options_status) if result.options_status else 'No response')

    if result.allowed_methods:
        print(f'\n  {DIM}{"─" * 20} Allowed Methods {"─" * 14}{RESET}')
        for method in result.allowed_methods:
            risky = method in {'PUT', 'DELETE', 'TRACE', 'CONNECT'}
            color = R if risky else G
            flag = f'  {R}← potentially dangerous{RESET}' if risky else ''
            print(f'    {color}{BOLD}{method}{RESET}{flag}')
    else:
        print(f'\n  {DIM}No Allow header returned — methods could not be enumerated.{RESET}')

    if result.risky_methods:
        print(f'\n  {Y}⚑ Risky methods detected: {", ".join(result.risky_methods)}{RESET}')

def print_csp_quality_section(csp: CspQuality) -> None:
    print_section('CONTENT SECURITY POLICY QUALITY')

    grade_color = G if csp.grade == 'Good' else Y if csp.grade == 'Weak' else R
    print_field('Header Present:', 'Yes' if csp.header_present else 'No',
                G if csp.header_present else R)
    print_field('Grade:', csp.grade, grade_color)

    if csp.header_present and csp.raw_value:
        print(f'\n  {DIM}Policy:{RESET}')
        print(f'    {DIM}{csp.raw_value}{RESET}')

    if csp.issues:
        print(f'\n  {DIM}{"─" * 20} Issues Found {"─" * 17}{RESET}')
        for issue in csp.issues:
            print(f'    {Y}⚑ {issue}{RESET}')
    elif csp.header_present:
        print(f'\n    {G}No CSP issues detected.{RESET}')

def print_server_version_section(sv: ServerVersionInfo) -> None:
    print_section('SERVER VERSION ANALYSIS')
    print_field('Server Header:', sv.server_header)
    print_field('Version Detected:', sv.version_detected,
                R if sv.version_detected != 'Unknown' else DIM)
    print_field('Powered By:', sv.powered_by)

    if sv.version_risks:
        print(f'\n  {DIM}{"─" * 20} Disclosure Risks {"─" * 13}{RESET}')
        for risk in sv.version_risks:
            print(f'    {Y}⚑ {risk}{RESET}')
    else:
        print(f'\n    {G}No version disclosure concerns detected.{RESET}')

def print_crawl_section(crawl_result: CrawlResult) -> None:
    print_section('CRAWL RESULTS')
    crawl_color = Y if crawl_result.truncated else G
    print_field('Pages Crawled:', str(crawl_result.pages_crawled), crawl_color)
    print_field('Pages Attempted:', str(crawl_result.pages_attempted))
    print_field('Truncated:', 'Yes — links remain unvisited' if crawl_result.truncated else 'No', crawl_color)

    if crawl_result.truncated:
        print(f'\n  {Y}Warning: crawl stopped at page limit. Some pages were not visited.{RESET}')

    if crawl_result.emails:
        print(f'\n  {DIM}{"─" * 22} Emails Found {"─" * 16}{RESET}')
        for email in crawl_result.emails:
            print(f'    {G}{email}{RESET}')
    else:
        print(f'\n  {DIM}No email addresses found.{RESET}')

    if crawl_result.external_domains:
        print(f'\n  {DIM}{"─" * 19} Referenced External Domains {"─" * 5}{RESET}')
        for ext in crawl_result.external_domains:
            print(f'    {C}{ext}{RESET}')

    print(f'\n  {DIM}{"─" * 22} Internal Pages {"─" * 15}{RESET}')
    for link in crawl_result.internal_links[:30]:
        print(f'    {DIM}{link}{RESET}')
    if len(crawl_result.internal_links) > 30:
        print(f'    {DIM}... and {len(crawl_result.internal_links) - 30} more (save report for full list){RESET}')


def print_report(report: DomainReport) -> None:
    print(f'{DIM}  Scan time : {report.scan_time}{RESET}')
    print(f'{DIM}  Target    : {report.target}{RESET}')

    print_dns_section(report.dns, report.ip_address)
    print_whois_section(report.whois)
    print_ssl_section(report.ssl)
    print_http_section(report.http)

    if report.tech:
        print_tech_section(report.tech)
    if report.server_version:
        print_server_version_section(report.server_version)
    if report.csp_quality:
        print_csp_quality_section(report.csp_quality)
    if report.http_methods:
        print_http_methods_section(report.http_methods)
    if report.email_security:
        print_email_security_section(report.email_security)
    if report.sensitive_paths:
        print_sensitive_paths_section(report.sensitive_paths)
    if report.wordpress:
        print_wordpress_section(report.wordpress)
    if report.risk:
        print_risk_section(report.risk)
    if report.ipqs_scan:
        print_ipqs_scan_section(report.ipqs_scan)
    if report.port_scan:
        print_port_scan_section(report.port_scan)
    if report.crawl:
        print_crawl_section(report.crawl)

    print(f'\n{DIVIDER}\n')


# Save
def save_report(report: DomainReport) -> None:
    '''Save full report to JSON.'''
    data: dict[str, object] = {
        'scan_time': report.scan_time,
        'target': report.target,
        'ip_address': report.ip_address,
        'dns': asdict(report.dns),
        'whois': asdict(report.whois),
        'ssl': asdict(report.ssl) if report.ssl is not None else None,
        'http': asdict(report.http) if report.http is not None else None,
        'tech': asdict(report.tech) if report.tech is not None else None,
        'risk': asdict(report.risk) if report.risk is not None else None,
        'ipqs_scan': asdict(report.ipqs_scan) if report.ipqs_scan is not None else None,
        'crawl': asdict(report.crawl) if report.crawl is not None else None,
        'sensitive_paths': asdict(report.sensitive_paths) if report.sensitive_paths is not None else None,
        'wordpress': asdict(report.wordpress) if report.wordpress is not None else None,
        'email_security': asdict(report.email_security) if report.email_security is not None else None,
        'port_scan': asdict(report.port_scan) if report.port_scan is not None else None,
        'http_methods': asdict(report.http_methods) if report.http_methods is not None else None,
        'csp_quality': asdict(report.csp_quality) if report.csp_quality is not None else None,
        'server_version': asdict(report.server_version) if report.server_version is not None else None,
    }
    filename = f'domain_osint_{report.target.replace(".", "_")}.json'
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    print(f'{G}  Report saved → {filename}{RESET}\n')


# Main
def main() -> None:
    save = '--save' in sys.argv

    print(BANNER)

    domain, max_pages = get_domain_input()

    print(f'\n{DIM}Resolving DNS...{RESET}')
    ip_address, dns_info = resolve_dns(domain)

    print(f'{DIM}Fetching WHOIS...{RESET}')
    whois_info = fetch_whois(domain)

    print(f'{DIM}Fetching SSL certificate...{RESET}')
    ssl_info = fetch_ssl(domain)

    print(f'{DIM}Fetching HTTP headers...{RESET}')
    http_info = fetch_http_info(domain)

    # Fingerprint — fetch root page soup once, reuse everywhere
    root_soup: BeautifulSoup | None = None
    if http_info is not None:
        try:
            root_response = requests.get(
                f'https://{domain}',
                headers=REQUEST_HEADERS,
                timeout=10,
            )
            root_soup = BeautifulSoup(root_response.text, 'html.parser')
        except Exception:
            pass

    tech = fingerprint_tech(http_info.all_headers, root_soup) if http_info is not None else None

    print(f'{DIM}Analyzing server version headers...{RESET}')
    server_version = analyze_server_version(http_info)

    print(f'{DIM}Grading Content Security Policy...{RESET}')
    csp_quality = grade_csp(http_info)

    print(f'{DIM}Enumerating HTTP methods...{RESET}')
    http_methods = check_http_methods(domain)

    print(f'{DIM}Checking email security records (SPF / DMARC / DKIM)...{RESET}')
    email_security = check_email_security(domain)

    print(f'{DIM}Probing sensitive paths...{RESET}')
    sensitive_paths = probe_sensitive_paths(domain)

    print(f'{DIM}Checking for WordPress...{RESET}')
    wordpress = scan_wordpress(domain, root_soup, sensitive_paths)

    report_data: dict[str, object] = {
        'target': domain,
        'http': http_info,
        'ssl': ssl_info,
        'whois': whois_info,
    }
    risk = calculate_risk_score(report_data)

    # Optional: IPQS scrape
    print(f'\n{Y}Run URL threat scan? Scrapes public data sources.{RESET}')
    print(f'{Y}May fail if page structures change.{RESET}')
    ipqs_choice = input(f'{C}> Run URL threat scan? [y/N]: {RESET}').strip().lower()
    ipqs_scan: IpqsUrlScan | None = None
    if ipqs_choice == 'y':
        print(f'{DIM}Scraping for URL threats...{RESET}')
        ipqs_scan = scrape_ipqs_url_scan(domain)

    # Optional: port scan
    print(f'\n{Y}Run port scan? Checks {len(COMMON_PORTS)} common ports via raw socket.{RESET}')
    print(f'{Y}Target: {ip_address} — ensure you are authorized.{RESET}')
    port_choice = input(f'{C}> Run port scan? [y/N]: {RESET}').strip().lower()
    port_scan_result: PortScanResult | None = None
    if port_choice == 'y':
        print(f'{DIM}Scanning ports on {ip_address}...{RESET}')
        port_scan_result = port_scan(ip_address)

    # Optional: crawl
    print(f'\n{Y}Run page crawl? This will visit up to {max_pages} pages with a 1 second{RESET}')
    print(f'{Y}delay between requests. May take several minutes on larger sites.{RESET}')
    crawl_choice = input(f'{C}> Run crawl? [y/N]: {RESET}').strip().lower()
    crawl_result: CrawlResult | None = None
    if crawl_choice == 'y':
        print(f'\n{DIM}Starting crawl (max {max_pages} pages)...{RESET}')
        crawl_result = crawl(domain, max_pages)

    report = DomainReport(
        target=domain,
        scan_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        ip_address=ip_address,
        dns=dns_info,
        whois=whois_info,
        ssl=ssl_info,
        http=http_info,
        tech=tech,
        risk=risk,
        ipqs_scan=ipqs_scan,
        crawl=crawl_result,
        sensitive_paths=sensitive_paths,
        wordpress=wordpress,
        email_security=email_security,
        port_scan=port_scan_result,
        http_methods=http_methods,
        csp_quality=csp_quality,
        server_version=server_version,
    )

    print_report(report)

    if not save:
        save_choice = input(f'{C}> Save report to current directory? [y/N]: {RESET}').strip().lower()
        if save_choice == 'y':
            save = True

    if save:
        save_report(report)


if __name__ == '__main__':
    main()