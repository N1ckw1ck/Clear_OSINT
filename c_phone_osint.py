#!/usr/bin/env python3

'''
(Clear Web) Phone Number OSINT Tool
For authorized research and investigative purposes only.
Please don't break any laws.
'''

import sys
import json
import requests
import phonenumbers
import xml.etree.ElementTree as ET
from phonenumbers import (geocoder, carrier, timezone, number_type,
                          is_valid_number, is_possible_number, format_number,
                          PhoneNumberFormat, PhoneNumberType, NumberParseException)
from dataclasses import dataclass, asdict
from datetime import datetime

# IPQS offers a free API to determine the risk score, carrier, owner information, etc. of phone numbers
# Using it will increase the amount of/enhance the quality of the OSINT report generated
# Sign up at: https://www.ipqualityscore.com/create-account
# paste your IPQS API key below

IPQS_API_KEY: str = ''  # Put it in here
# If you leave it blank the scan will still work, but won't be able to display certain data
# Like fraud score, whether the number is on the DNC registry, etc.

# SerpApi offers a free API as well, which allows headless scans of the internet
# Sign up at https://serpapi.com — 100 free searches/month
SERPAPI_KEY: str = ''
# If left blank the scan will still work, but with diminished capabilities
# You will not be able to see mentions of the target number on the internet

# ANSI styling
R = '\033[91m'
G = '\033[92m'
Y = '\033[93m'
B = '\033[94m'
C = '\033[96m'
W = '\033[97m'
DIM = '\033[2m'
BOLD = '\033[1m'
RESET = '\033[0m'

BANNER = f'''
{C}{BOLD}
 ██████╗ ██╗  ██╗ ██████╗ ███╗   ██╗███████╗      ██████╗ ███████╗██╗███╗   ██╗████████╗
 ██╔══██╗██║  ██║██╔═══██╗████╗  ██║██╔════╝     ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
 ██████╔╝███████║██║   ██║██╔██╗ ██║█████╗       ██║   ██║███████╗██║██╔██╗ ██║   ██║
 ██╔═══╝ ██╔══██║██║   ██║██║╚██╗██║██╔══╝       ██║   ██║╚════██║██║██║╚██╗██║   ██║
 ██║     ██║  ██║╚██████╔╝██║ ╚████║███████╗     ╚██████╔╝███████║██║██║ ╚████║   ██║
 ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝      ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝
{RESET}{DIM}Phone Number OSINT Tool | Authorized research use only{RESET}
'''

DIVIDER = f'{DIM}{"─" * 62}{RESET}'

# Docs: https://daviddrysdale.github.io/python-phonenumbers/
LINE_TYPE_MAP = {
    PhoneNumberType.MOBILE: 'Mobile',
    PhoneNumberType.FIXED_LINE: 'Fixed Line (Landline)',
    PhoneNumberType.FIXED_LINE_OR_MOBILE: 'Fixed Line or Mobile',
    PhoneNumberType.TOLL_FREE: 'Toll-Free',
    PhoneNumberType.PREMIUM_RATE: 'Premium Rate',
    PhoneNumberType.SHARED_COST: 'Shared Cost',
    PhoneNumberType.VOIP: 'VoIP',
    PhoneNumberType.PERSONAL_NUMBER: 'Personal Number',
    PhoneNumberType.PAGER: 'Pager',
    PhoneNumberType.UAN: 'UAN',
    PhoneNumberType.VOICEMAIL: 'Voicemail',
    PhoneNumberType.UNKNOWN: 'Unknown'
}

# Display helpers
def print_section(title: str) -> None:
    print(f'\n{B}{BOLD}[ {title} ]{RESET}')
    print(DIVIDER)

def print_field(label: str, value: str, color: str = W) -> None:
    print(f'  {DIM}{label:<28}{RESET}{color}{value}{RESET}')

def bool_display(raw: str) -> tuple[str, str]:
    '''Return (display_text, color) for a true/false string value.'''
    normalized = raw.strip().lower()
    if normalized == 'true':
        return 'Yes', G
    if normalized == 'false':
        return 'No', DIM + W
    return raw, W

SCAM_REPORT_DOMAINS = {
    '800notes.com', 'whocallsme.com', 'nomorobo.com', 'complaints.com',
    'callercenter.com', 'shouldianswer.com', 'callercomplaints.com',
    'spamcalls.net', 'whocalledus.us', 'didtheyread.com',
}

DATA_BROKER_DOMAINS = {
    'whitepages.com', 'spokeo.com', 'truepeoplesearch.com', 'intelius.com',
    'beenverified.com', 'peoplefinder.com', 'instantcheckmate.com',
    'fastpeoplesearch.com', 'radaris.com', 'anywho.com', 'zabasearch.com',
}

SOCIAL_DOMAINS = {
    'facebook.com', 'instagram.com', 'twitter.com', 'x.com', 'linkedin.com',
    'tiktok.com', 'reddit.com', 'youtube.com', 'pinterest.com',
}

BUSINESS_DOMAINS = {
    'yelp.com', 'bbb.org', 'yellowpages.com', 'manta.com', 'chamberofcommerce.com',
    'bizapedia.com', 'opencorporates.com', 'glassdoor.com', 'indeed.com',
}


# Define function return types
@dataclass
class LocalAnalysis:
    country: str
    region: str
    carrier: str
    line_type: str
    timezones: list[str]
    valid: bool
    possible: bool
    e164: str
    intl: str
    national: str

@dataclass
class SpamResult:
    is_spam: bool
    message: str
    report_count: int
    last_reported: str

@dataclass
class GeoResult:
    lat: str
    lon: str
    display_name: str

@dataclass
class SmsPumping:
    risk_score: str
    message: str
    velocity: str

@dataclass
class IpqsResult:
    message: str
    success: str
    formatted: str
    local_format: str
    valid: str
    fraud_score: str
    recent_abuse: str
    voip: str
    prepaid: str
    risky: str
    active: str
    name: str
    carrier: str
    line_type: str
    country: str
    region: str
    city: str
    timezone: str
    zip_code: str
    accurate_country_code: str
    dialing_code: str
    do_not_call: str
    leaked: str
    spammer: str
    user_activity: str
    active_status: str
    mcc: str
    mnc: str
    request_id: str
    tcpa_blacklist: str
    sms_pumping: SmsPumping

@dataclass
class MentionResult:
    url: str
    domain: str
    title: str
    snippet: str
    category: str
    is_scam_report: bool


@dataclass
class WebScanResult:
    mentions: list[MentionResult]
    query_count: int
    total_found: int
    truncated: bool


# User input
def get_phone_input() -> str:
    '''Prompt in parts and return a fully-formed E.164 string (e.g. +18005554312).'''
    print(f'\n{Y}Select number type:{RESET}')
    print(f' {DIM}[1]{RESET} US / Canada')
    print(f' {DIM}[2]{RESET} International')

    mode = input(f'\n{C}> Mode [1/2]: {RESET}').strip()

    if mode == '2':
        country_code = input(f'{C}> Country code (digits only, e.g. 44 for UK): {RESET}').strip()
        number = input(f'{C}> Number: {RESET}').strip()
        return f'+{country_code}{number}'
    else:
        area = input(f'{C}> Area code (e.g. 800): {RESET}').strip()
        number = input(f'{C}> Number (7 digits, e.g. 4445555): {RESET}').strip()
        return f'+1{area}{number}'

def analyze_local(parsed: phonenumbers.PhoneNumber) -> LocalAnalysis:
    '''Local analysis - phonenumbers library.'''
    return LocalAnalysis(
        country=geocoder.country_name_for_number(parsed, 'en') or 'Unknown',
        region=geocoder.description_for_number(parsed, 'en') or 'Unknown',
        carrier=carrier.name_for_number(parsed, 'en') or 'Unknown',
        line_type=LINE_TYPE_MAP.get(number_type(parsed), 'Unknown'),
        timezones=list(timezone.time_zones_for_number(parsed)),
        valid=is_valid_number(parsed),
        possible=is_possible_number(parsed),
        e164=format_number(parsed, PhoneNumberFormat.E164),
        intl=format_number(parsed, PhoneNumberFormat.INTERNATIONAL),
        national=format_number(parsed, PhoneNumberFormat.NATIONAL)
    )

def fetch_spam(national: str) -> SpamResult | None:
    '''
    Query SkipCalls for spam likelihood.
    No API key required, reasonable use limits apply.
    Strips formatting to digits only before querying.
    '''
    digits_only = ''.join(filter(str.isdigit, national))
    url = f'https://spam.skipcalls.app/check/{digits_only}'
    try:
        response = requests.get(url, timeout=8)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f'\n  {R}SkipCalls request failed: {e}{RESET}')
        return None

    raw = response.text.strip()
    if not raw:
        print(f'\n  {R}SkipCalls returned an empty response.{RESET}')
        return None

    try:
        data = response.json()
    except ValueError as e:
        print(f'\n  {R}SkipCalls JSON parse error: {e}{RESET}')
        return None

    is_spam = data.get('isSpam', False)
    report_count = int(data.get('reportCount', 0))
    last_reported = data.get('lastReported', 'N/A') or 'N/A'
    message = 'Likely spam' if is_spam else 'Not flagged as spam'

    return SpamResult(
        is_spam=is_spam,
        message=message,
        report_count=report_count,
        last_reported=last_reported,
    )

def fetch_geocode(region: str) -> GeoResult | None:
    '''
    Query Nominatim to geocode the region string from the phonenumbers library into coordinates.
    No API key or account required. 1 req/sec usage policy.
    Precision is limited by the region string quality - typically city or state level.
    '''
    if not region or region == 'Unknown':
        return None

    url = 'https://nominatim.openstreetmap.org/search'
    params: dict[str, str | int] = { # This could be a dataset but does it really need to be
        'q': region,
        'format': 'json',
        'limit': 1,
    }
    # Usage policy: https://operations.osmfoundation.org/policies/nominatim/
    headers = {
        'User-Agent': 'PhoneOSINT/1.0 (research tool)'
    }
    try:
        response = requests.get(url, params=params, headers=headers, timeout=8)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f'\n  {R}Geocoding request failed: {e}{RESET}')
        return None

    raw = response.text.strip()
    if not raw:
        print(f'\n  {R}Geocoding returned an empty response.{RESET}')
        return None

    try:
        data = response.json()
    except ValueError as e:
        print(f'\n  {R}Geocoding JSON parse error: {e}{RESET}')
        return None

    if not data:
        return None

    result = data[0]
    return GeoResult(
        lat=str(result.get('lat', 'N/A')),
        lon=str(result.get('lon', 'N/A')),
        display_name=str(result.get('display_name', 'N/A')),
    )

# Docs: https://www.ipqualityscore.com/documentation/phone-number-validation-api/overview
def fetch_ipqs(e164: str, api_key: str) -> IpqsResult | None:
    '''
    Query the IPQualityScore phone validation API.
    Returns an IpqsResult dataclass, or None on failure.
    '''
    clean_number = e164.replace('+', '%2B')
    clean_key = api_key.strip()

    url = f'https://www.ipqualityscore.com/api/xml/phone/{clean_key}/{clean_number}'
    try:
        response = requests.get(url, timeout=8)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f'\n  {R}IPQS request failed: {e}{RESET}')
        return None

    raw = response.text.strip()
    if not raw:
        print(f'\n  {R}IPQS returned an empty response body.{RESET}')
        print(f'  {DIM}URL attempted: {url}{RESET}')
        print(f'  {DIM}HTTP status: {response.status_code}{RESET}')
        return None

    try:
        root = ET.fromstring(response.text)
    except ET.ParseError as e:
        print(f'\n  {R}IPQS XML parse error: {e}{RESET}')
        return None

    success = root.findtext('success', default='false').strip().lower()
    if success != 'true':
        message = root.findtext('message', default='Unknown error')
        print(f'\n  {R}IPQS returned failure: {message}{RESET}')
        return None

    def field(tag: str) -> str:
        text = root.findtext(tag)
        return text.strip() if text else 'N/A'

    sms_node = root.find('sms_pumping')
    if sms_node is not None:
        sms_pumping = SmsPumping(
            risk_score=sms_node.findtext('risk_score', 'N/A'),
            message=sms_node.findtext('message', 'N/A'),
            velocity=sms_node.findtext('velocity', 'N/A'),
        )
    else:
        sms_pumping = SmsPumping(risk_score='N/A', message='N/A', velocity='N/A')

    return IpqsResult(
        message=field('message'),
        success=field('success'),
        formatted=field('formatted'),
        local_format=field('local_format'),
        valid=field('valid'),
        fraud_score=field('fraud_score'),
        recent_abuse=field('recent_abuse'),
        voip=field('VOIP'),
        prepaid=field('prepaid'),
        risky=field('risky'),
        active=field('active'),
        name=field('name'),
        carrier=field('carrier'),
        line_type=field('line_type'),
        country=field('country'),
        region=field('region'),
        city=field('city'),
        timezone=field('timezone'),
        zip_code=field('zip_code'),
        accurate_country_code=field('accurate_country_code'),
        dialing_code=field('dialing_code'),
        do_not_call=field('do_not_call'),
        leaked=field('leaked'),
        spammer=field('spammer'),
        user_activity=field('user_activity'),
        active_status=field('active_status'),
        mcc=field('mcc'),
        mnc=field('mnc'),
        request_id=field('request_id'),
        tcpa_blacklist=field('tcpa_blacklist'),
        sms_pumping=sms_pumping
    )

def extract_domain(url: str) -> str:
    '''Extract bare domain from a URL, stripping www prefix.'''
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain
    except Exception:
        return url


def infer_category(domain: str, snippet: str) -> str:
    '''
    Infer the likely category of a search result based on domain and snippet text.
    Returns a readable category string.
    '''
    if domain in SCAM_REPORT_DOMAINS:
        return 'Scam / Complaint Report'
    if domain in DATA_BROKER_DOMAINS:
        return 'Data Broker / People Search'
    if domain in SOCIAL_DOMAINS:
        return 'Social Media'
    if domain in BUSINESS_DOMAINS:
        return 'Business Directory'

    snippet_lower = snippet.lower()
    domain_lower = domain.lower()

    if any(word in snippet_lower for word in ['scam', 'fraud', 'spam', 'robocall', 'complaint', 'reported']):
        return 'Scam / Complaint Report'
    if any(word in snippet_lower for word in ['for sale', 'listing', 'contact us', 'call us', 'reach us']):
        return 'Business / Listing'
    if any(word in domain_lower for word in ['news', 'press', 'media', 'herald', 'times', 'post']):
        return 'News / Media'
    if any(word in domain_lower for word in ['gov', 'edu']):
        return 'Government / Education'
    if any(word in snippet_lower for word in ['profile', 'member', 'account', 'user']):
        return 'Profile / Account'

    return 'General Web'

# No stub types :(
def fetch_web_mentions(local: LocalAnalysis, serpapi_key: str) -> WebScanResult | None:
    '''
    Search Google and DuckDuckGo via SerpAPI for clearnet mentions of the phone number in multiple formats.
    Deduplicates results by URL across both engines.
    Costs 2 API calls per scan.
    '''
    import serpapi # type: ignore

    national_clean = local.national.strip()
    e164_clean = local.e164.strip()
    digits_only = ''.join(filter(str.isdigit, national_clean))
    intl_spaced = local.intl.strip()

    # Build deduplicated query list
    seen_queries: set[str] = set()
    unique_queries: list[str] = []
    for q in [f'"{national_clean}"', f'"{e164_clean}"', f'"{intl_spaced}"', f'"{digits_only}"']:
        if q not in seen_queries:
            seen_queries.add(q)
            unique_queries.append(q)

    # Combine into one broad OR query per engine to save API calls
    combined_query = ' OR '.join(unique_queries)

    client = serpapi.Client(api_key=serpapi_key)
    seen_urls: set[str] = set()
    all_mentions: list[MentionResult] = []

    engines: list[dict[str, str]] = [
        {'engine': 'google', 'gl': 'us', 'hl': 'en'},
        {'engine': 'duckduckgo', 'kl': 'us-en'},
    ]

    for engine_params in engines:
        engine_name = engine_params['engine']
        print(f'  {DIM}Querying {engine_name} via SerpAPI...{RESET}')

        params: dict[str, str] = {
            'q': combined_query,
            **engine_params,
        }

        try:
            results = client.search(params) # type: ignore
        except Exception as e:
            print(f'\n  {R}SerpAPI {engine_name} search failed: {e}{RESET}')
            continue

        organic = results.get('organic_results', []) # type: ignore

        for item in organic: # type: ignore
            url = item.get('link', '').strip() # type: ignore
            title = item.get('title', '').strip() # type: ignore
            snippet = item.get('snippet', '').strip() # type: ignore

            if not url or not title:
                continue
            if url in seen_urls:
                continue

            seen_urls.add(url) # type: ignore
            domain = extract_domain(url) # type: ignore
            category = infer_category(domain, snippet) # type: ignore
            is_scam = domain in SCAM_REPORT_DOMAINS or category == 'Scam / Complaint Report'

            all_mentions.append(MentionResult(
                url=url, # type: ignore
                domain=domain,
                title=title, # type: ignore
                snippet=snippet, # type: ignore
                category=category,
                is_scam_report=is_scam,
            ))

    total = len(all_mentions)
    return WebScanResult(
        mentions=all_mentions,
        query_count=len(engines),
        total_found=total,
        truncated=total > 10,
    )

def print_local_section(local: LocalAnalysis) -> None:
    '''Print out the local report.'''
    print_section('VALIDATION')
    valid_color = G if local.valid else R
    print_field('Valid Number:', 'YES' if local.valid else 'NO', valid_color)
    print_field('Possible Number:', 'YES' if local.possible else 'NO')

    print_section('LOCAL ANALYSIS')
    print_field('Country:', local.country)
    print_field('Region / Area:', local.region)
    print_field('Line Type:', local.line_type)
    print_field('Carrier:', local.carrier, DIM + W)
    for tz in local.timezones:
        print_field('Timezone:', tz)

    print_section('NUMBER FORMATS')
    print_field('E.164:', local.e164, G)
    print_field('International:', local.intl)
    print_field('National:', local.national)

def print_enrichment_section(spam: SpamResult | None, geo: GeoResult | None) -> None:
    '''Print enrichment data from SkipCalls and Nominatim geocoding.'''
    print_section('PUBLIC DATA ENRICHMENT')

    if spam:
        spam_color = R if spam.is_spam else G
        print_field('Spam Status:', spam.message, spam_color)
        print_field('Report Count:', str(spam.report_count))
        print_field('Last Reported:', spam.last_reported)
    else:
        print(f'  {DIM}Spam check unavailable.{RESET}')

    if geo:
        print(f'\n  {DIM}{"─" * 18} Geolocation (approximate) {"─" * 8}{RESET}')
        print_field('Latitude:', geo.lat)
        print_field('Longitude:', geo.lon)
        print_field('Resolved Location:', geo.display_name)
        print(f'  {DIM}Note: coordinates are derived from carrier region data{RESET}')
        print(f'  {DIM}and may only be accurate to the city or state level.{RESET}')
    else:
        print(f'  {DIM}Geolocation unavailable.{RESET}')

def print_ipqs_section(ipqs: IpqsResult) -> None:
    '''Print out IP Quality score report.'''
    print_section('IPQUALITYSCORE (live enrichment)')

    print_field('Name (CNAM):', ipqs.name)
    print_field('Carrier:', ipqs.carrier)
    print_field('Line Type:', ipqs.line_type)
    print_field('Active Status:', ipqs.active_status)

    print(f'\n  {DIM}{"─" * 20} Location {"─" * 20}{RESET}')
    print_field('Country:', ipqs.country)
    print_field('Region:', ipqs.region)
    print_field('City:', ipqs.city)
    print_field('ZIP Code:', ipqs.zip_code)
    print_field('Timezone:', ipqs.timezone)
    print_field('Dialing Code:', f'+{ipqs.dialing_code}')

    print(f'\n  {DIM}{"─" * 22} Risk {"─" * 22}{RESET}')

    score: str = ipqs.fraud_score
    try:
        score_int = int(score)
        score_color = R if score_int >= 75 else Y if score_int >= 40 else G
    except ValueError:
        score_color = W
    print_field('Fraud Score (0-100):', score, score_color)

    for label, key in [
        ('Risky:', 'risky'),
        ('Recent Abuse:', 'recent_abuse'),
        ('Spammer:', 'spammer'),
        ('VOIP:', 'voip'),
        ('Prepaid:', 'prepaid'),
        ('Leaked:', 'leaked'),
        ('Do Not Call:', 'do_not_call'),
        ('TCPA Blacklist:', 'tcpa_blacklist')
    ]:
        text, color = bool_display(getattr(ipqs, key))
        print_field(label, text, color)

    print_field('User Activity:', ipqs.user_activity)

    sms = ipqs.sms_pumping
    if sms:
        print(f'\n  {DIM}{"─" * 19} SMS Pumping {"─" * 19}{RESET}')
        print_field('Risk Score:', sms.risk_score)
        print_field('Velocity:', sms.velocity)
        print_field('Assessment:', sms.message)

    print(f'\n  {DIM}{"─" * 20} Technical {"─" * 19}{RESET}')
    print_field('MCC:', ipqs.mcc)
    print_field('MNC:', ipqs.mnc)
    print_field('Accurate Country:', ipqs.accurate_country_code)
    print_field('Request ID:', ipqs.request_id)
    print_field('IPQS Message:', ipqs.message)

def print_web_section(web: WebScanResult) -> None:
    '''Print clearnet mention results.'''
    print_section('CLEARNET MENTIONS')

    if not web.mentions:
        print(f'  {DIM}No clearnet mentions found.{RESET}')
        return

    print_field('Total found:', str(web.total_found))
    print_field('Queries run:', str(web.query_count))

    if web.truncated:
        print(f'  {Y}More than 10 results found — showing top 10.{RESET}')

    display = web.mentions[:10]

    for i, mention in enumerate(display, 1):
        cat_color = R if mention.is_scam_report else W
        print(f'\n  {BOLD}{DIM}[{i}]{RESET} {C}{mention.title}{RESET}')
        print(f'      {DIM}URL:     {RESET}{W}{mention.url}{RESET}')
        print(f'      {DIM}Domain:  {RESET}{W}{mention.domain}{RESET}')
        print(f'      {DIM}Category:{RESET}{cat_color}{mention.category}{RESET}')
        if mention.snippet:
            # Truncate the long snippety for display
            snippet = mention.snippet[:120] + '...' if len(mention.snippet) > 120 else mention.snippet
            print(f'      {DIM}Snippet: {RESET}{DIM}{snippet}{RESET}')

def print_report(raw_input: str, local: LocalAnalysis, spam: SpamResult | None, geo: GeoResult | None, ipqs: IpqsResult | None) -> None:
    print(f'{DIM} Scan time : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{RESET}')
    print(f'{DIM} Target    : {raw_input}{RESET}')

    print_local_section(local)
    print_enrichment_section(spam, geo)

    if ipqs:
        print_ipqs_section(ipqs)
    else:
        print(f'\n {Y}IPQS data unavailable (check API key or network).{RESET}') # You left it blank didn't you

    print(f'\n{DIVIDER}\n')

def save_report(local: LocalAnalysis, spam: SpamResult | None, geo: GeoResult | None, ipqs: IpqsResult | None, web: WebScanResult | None = None) -> None:
    '''Optional JSON save'''
    report: dict[str, object] = {
        'scan_time': datetime.now().isoformat(),
        'local_analysis': asdict(local),
        'spam': asdict(spam) if spam is not None else None,
        'geo': asdict(geo) if geo is not None else None,
        'ipqs': asdict(ipqs) if ipqs is not None else None,
        'web_mentions': asdict(web) if web is not None else None,
    }
    filename = f'phone_osint_{local.e164.replace("+", "")}.json'
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2)
    print(f'{G}  Report saved → {filename}{RESET}\n')

def main() -> None:
    save = '--save' in sys.argv

    print(BANNER)

    raw = get_phone_input()

    print(f'\n{DIM}Parsing number...{RESET}')
    try:
        parsed = phonenumbers.parse(raw)
    except NumberParseException as e:
        print(f'{R}Could not parse number: {e}{RESET}')
        sys.exit(1)

    local = analyze_local(parsed)

    print(f'{DIM}Querying SkipCalls spam database...{RESET}')
    spam = fetch_spam(local.national)

    print(f'{DIM}Geocoding region via Nominatim...{RESET}')
    geo = fetch_geocode(local.region)

    ipqs: IpqsResult | None = None
    if IPQS_API_KEY.strip():
        print(f'{DIM}Querying IPQualityScore...{RESET}')
        ipqs = fetch_ipqs(local.e164, IPQS_API_KEY)

    print_report(raw, local, spam, geo, ipqs)
    print(f'\n{Y}Run clearnet mention scan? This queries Google and DuckDuckGo{RESET}')
    print(f'{Y}across multiple number formats and may take 10-20 seconds.{RESET}')
    web_choice = input(f'{C}> Scan for clearnet mentions? [y/N]: {RESET}').strip().lower()

    web: WebScanResult | None = None
    if web_choice == 'y':
        print(f'\n{DIM}Scanning clearnet for mentions...{RESET}')
        web: WebScanResult | None = None
        if web_choice == 'y':
            if not SERPAPI_KEY.strip():
                print(f'\n  {R}No SerpAPI key set. Set SERPAPI_KEY at the top of the file.{RESET}')
            else:
                print(f'\n{DIM}Scanning clearnet for mentions...{RESET}')
                web = fetch_web_mentions(local, SERPAPI_KEY)
                if web is not None:
                    print_web_section(web)
                    if web.truncated:
                        save_choice = input(f'\n{C}> More than 10 results found. Save all to file? [y/N]: {RESET}').strip().lower()
                        if save_choice == 'y':
                            save = True

    if save:
        save_report(local, spam, geo, ipqs, web) # Saves like 'phone_osint_12223334444.json' in current dir

if __name__ == '__main__':
    main()