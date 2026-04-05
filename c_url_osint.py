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
        try: # There are definitely better ways to do this
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

# Whois
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

# SSL and TLS
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
    
def fingerprint_tech(headers: dict[str, str], soup: BeautifulSoup | None) -> TechFingerprint:
    ''' Fingerprint web technologies from response headers and HTML content. '''
    headers_lower = {k.lower(): v for k, v in headers.items()}
    other: list[str] = []

    # Web server
    web_server = headers_lower.get('server', 'Unknown')

    # Language / runtime
    language = 'Unknown'
    powered_by = headers_lower.get('x-powered-by', '')
    if powered_by:
        language = powered_by
    elif 'php' in headers_lower.get('x-pingback', '').lower():
        language = 'PHP'

    # CDN detection
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

    # Hosting provider
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

    # CMS detection — headers
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

    # CMS detection — HTML
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

    # CMS detection — HTML link/script patterns
    if soup is not None and cms == 'Unknown':
        page_text = str(soup)
        if '/wp-content/' in page_text or '/wp-includes/' in page_text:
            cms = 'WordPress'
        elif '/sites/default/files/' in page_text:
            cms = 'Drupal'
        elif 'Shopify.theme' in page_text:
            cms = 'Shopify'

    # JS framework detection
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

    # Other potentially interesting headers
    interesting = [
        'x-generator', 'x-frame-options', 'x-runtime',
        'x-aspnet-version', 'x-aspnetmvc-version',
    ]
    for h in interesting:
        if h in headers_lower and headers_lower[h] not in ('', 'N/A'):
            other.append(f'{h}: {headers_lower[h]}')

    # Via header can reveal proxy/CDN chain
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

def calculate_risk_score(report_data: dict[str, object]) -> RiskScore:
    '''
    Calculate a low-resource risk score from already-collected data.
    No additional calls or requests required.
    Not extremely accurate.
    '''
    score = 0
    flags: list[str] = []

    http = report_data.get('http')
    ssl = report_data.get('ssl')
    whois_data = report_data.get('whois')
    target = str(report_data.get('target', '')) # type: ignore because not currently using it

    # HTTP vs HTTPS
    if isinstance(http, HttpInfo):
        if http.status_code and not any(
            r.startswith('https://') for r in [str(report_data.get('target', ''))] + http.redirect_chain
        ):
            score += 20
            flags.append('Not using HTTPS')

    # SSL checks
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

    # Security headers
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

    # Domain age
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


def scrape_ipqs_url_scan(domain: str) -> IpqsUrlScan:
    '''
    Scrape IPQS malicious URL scanner page for domain threat data.
    No API key, scrapes the public results page.
    Returns IpqsUrlScan with scrape_success=False if scraping fails, preserves data if possible.
    Target rows: 1, 2, 5, 6, 7, 8, 9 from the results tbody.
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

        # Navigate to the results table table
        table = soup.find('table')
        if not table:
            print(f'\n  {Y}IPQS URL scan: could not locate results table.{RESET}')
            return IpqsUrlScan(**defaults)  # type: ignore

        rows = table.find_all('tr')  # type: ignore

        def get_row_text(index: int) -> str:
            '''Extract result text from a specific row index (0-based).'''
            try:
                row = rows[index]
                # Try result td first
                result_td = row.find('td', class_='right')
                if result_td:
                    # Check for nested span (risk score row)
                    span = result_td.find('span')
                    if span:
                        return span.get_text(strip=True)
                    return result_td.get_text(strip=True)
                return 'Unavailable'
            except (IndexError, AttributeError):
                return 'Unavailable'

        # Rows are 0-indexed: 1st=0, 2nd=1, 5th=4, 6th=5, 7th=6, 8th=7, 9th=8
        safe = get_row_text(0)
        suspicious = get_row_text(1)
        malware = get_row_text(4)
        phishing = get_row_text(5)
        risk_score = get_row_text(6)
        parked = get_row_text(7)
        spamming = get_row_text(8)

        return IpqsUrlScan(
            safe=safe,
            suspicious=suspicious,
            malware=malware,
            phishing=phishing,
            risk_score=risk_score,
            parked=parked,
            spamming=spamming,
            scrape_success=True,
        )

    except Exception as e:
        print(f'\n  {Y}IPQS URL scan parse error: {e}{RESET}')
        return IpqsUrlScan(**defaults) # type: ignore

# Crawling 
def extract_emails(text: str) -> set[str]:
    '''Extract email addresses from a block of text.'''
    return set(EMAIL_REGEX.findall(text))

def extract_links(soup: BeautifulSoup, base_url: str, target_domain: str) -> tuple[set[str], set[str]]:
    '''
    Extract internal and external links from a parsed page.
    Returns (internal_urls, external_domains).
    Internal URLs are absolute, on the target domain.
    External domains are bare domain strings.
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
    Soupy crawl of the target domain up to max_pages pages.
    Collects internal links, external domains, emails, and builds a domain link map.
    Wait 1 second between requests.
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
            linked_paths: list[str] = []
            for link in internal:
                path = urlparse(link).path or '/'
                linked_paths.append(path)
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

# Printing the report
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
    '''Print technology fingerprint results.'''
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
    '''Print the calculated low-resource risk score.'''
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
    '''Print IPQS URL scan results.'''
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
    else:
        print(f'\n  {DIM}No external domains referenced.{RESET}')

    print(f'\n  {DIM}{"─" * 22} Internal Pages {"─" * 15}{RESET}')
    for link in crawl_result.internal_links[:30]:
        print(f'    {DIM}{link}{RESET}')
    if len(crawl_result.internal_links) > 30:
        print(f'    {DIM}... and {len(crawl_result.internal_links) - 30} more (save report for full list){RESET}')

def print_report(report: DomainReport) -> None:
    print(BANNER)
    print(f'{DIM}  Scan time : {report.scan_time}{RESET}')
    print(f'{DIM}  Target    : {report.target}{RESET}')

    print_dns_section(report.dns, report.ip_address)
    print_whois_section(report.whois)
    print_ssl_section(report.ssl)
    print_http_section(report.http)
    if report.tech:
        print_tech_section(report.tech)

    if report.risk:
        print_risk_section(report.risk)

    if report.ipqs_scan:
        print_ipqs_scan_section(report.ipqs_scan)

    if report.crawl:
        print_crawl_section(report.crawl)

    print(f'\n{DIVIDER}\n')

# Save it
# Currently works like 'python c_url_osint.py --save'
# Maybe this isn't the best
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
    }
    filename = f'domain_osint_{report.target.replace(".", "_")}.json'
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    print(f'{G}  Report saved → {filename}{RESET}\n')

# Maim
def main() -> None:
    save = '--save' in sys.argv

    domain, max_pages = get_domain_input()

    print(f'\n{DIM}Resolving DNS...{RESET}')
    ip_address, dns_info = resolve_dns(domain)

    print(f'{DIM}Fetching WHOIS...{RESET}')
    whois_info = fetch_whois(domain)

    print(f'{DIM}Fetching SSL certificate...{RESET}')
    ssl_info = fetch_ssl(domain)

    print(f'{DIM}Fetching HTTP headers...{RESET}')
    http_info = fetch_http_info(domain)

    report_data: dict[str, object] = {
        'target': domain,
        'http': http_info,
        'ssl': ssl_info,
        'whois': whois_info,
    }
    risk = calculate_risk_score(report_data)

    # Fingerprint runs immediately from headers
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

    # Optional IPQS scrape
    print(f'\n{Y}Run URL threat scan? Scrapes public data sources.{RESET}')
    print(f'{Y}May fail if page structures change.{RESET}')
    ipqs_choice = input(f'{C}> Run URL threat scan? [y/N]: {RESET}').strip().lower()

    ipqs_scan: IpqsUrlScan | None = None
    if ipqs_choice == 'y':
        print(f'{DIM}Scraping for URL threats...{RESET}')
        ipqs_scan = scrape_ipqs_url_scan(domain)

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