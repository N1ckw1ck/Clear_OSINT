# Clear Web OSINT Toolkit - Quick start guide

## Setup

#### Assuming you have a recent version of python installed on your system:
1. Create a new folder in your desired location
2. Clone this repository or copy the desired `.py` files into that folder
3. Create a Python virtual environment inside that folder
4. Activate the virtual environment
5. Install dependencies:
```bash
   pip install -r requirements.txt
```
6. Run the tool:
```bash
   python <filename>.py
```
---
> Note: If only using one tool, install only what you need by selecting specific packages from `requirements.txt`  
---


███████████████████████████████████████████████
███████████████████████████████████████████████
## Clear Web Phone OSINT Tool

### Usage
```bash
python c_phone_osint.py
```

### Optional flags
```bash
python c_phone_osint.py --save    # Saves full report to JSON after scan completes
```

### Usage flow

1. You will be prompted for country code, area code, and the rest of the number separately
2. The main report is generated immediately after
3. You will then be asked whether to run a clearnet mention scan — default is **no**
4. If the scan finds more than 10 results, you will be prompted to save the full results as a `.json` file

### How it works

- Uses phonenumbers library to assess number validity,  country, region, line type, carrier info, and timezone
- Determines spam likelihood with external query to SkipCalls service
- Determines rough geocoordinates with external query to Nominatim (openstreetmap)
- If valid IPQS API key was provided, additional data will be added to the report like Do Not Call list status
- If valid SerpApi API key was provided and clearnet mention scan ran, the tool will query SerpAPIs Google and DuckDuckGo search APIs for mentions of the number in different formats across the clear web

### Screenshots

#### Report if no valid IPQS API key:
![No Valid IPQS Key Report](assets/no_ipqs_key_report.png)

#### What IPQS Key adds to report:
![Valid IPQS Key Full Report](assets/full_ipqs_key_report.png)

#### Clearnet mention scan (only works with valid SerpAPI Key):
![CLearnet mention scan results](assets/clearnet_mention_scan.png)

#### If more than ten results:
![CLearnet mention scan save results](assets/clearnet_mention_scan_save.png)

### Notes:
#### Spam likelihood check with SkipCalls is far from perfect and will produce a lot of false negatives, but there are not many truly free services offering programmatic access to large datasets of known spam numbers so it will have to do until I find a better way

#### phonenumbers library carrier detection iffy particularly for U.S. numbers, paid services would do a better job. But would require payment. 

#### Geocoding is Region/City level not very exact (This is expected)

#### IPQS can prove to be a very difficult service to deal with. They use aggressive duplicate free account prevention software, potentially making access to the API very difficult without paying them money. When creating an account for the first time, my advice is to do so while not connected to a VPN or public Wifi network, and from a browser like Google or Safari.
---
███████████████████████████████████████████████
---

## Clear Web Domain OSINT Tool

### Usage
```bash
python c_domain_osint.py
```

### Optional flags
```bash
python c_domain_osint.py --save    # Saves full report to JSON after scan completes
```

### Usage flow

1. You will be prompted for the target domain and a max page crawl limit (1-50, default 20)
2. DNS, WHOIS, SSL, HTTP headers, technology fingerprint, and calculated risk score run automatically
3. You will be prompted whether to run the IPQS URL threat scan — scrapes the public IPQS results page, no API key required
4. You will be prompted whether to run the page crawl — visits up to your specified limit of pages on the target domain, collecting emails, internal links, and external domain references
5. You will be prompted whether to save the report at the end, or pass `--save` to skip the prompt

### How it works

- Resolves A, PTR (reverse DNS), MX, NS, and TXT records via DNS
- Fetches WHOIS registration data including registrar, creation date, expiry, and nameservers
- Retrieves and parses the SSL/TLS certificate including issuer, expiry, days remaining, and Subject Alternative Names
- Fetches HTTP response headers and checks for the presence or absence of key security headers (HSTS, CSP, X-Frame-Options, and more)
- Fingerprints web technologies from headers and HTML including web server, CMS, JS framework, CDN, and hosting provider
- Calculates a passive risk score (0-100) derived entirely from already-collected data — no extra network calls
- Optionally scrapes the IPQS public URL threat scanner for malware, phishing, spam, and risk score data
- Optionally crawls the target domain breadth-first up to the page limit, extracting emails, mapping internal page links, and cataloguing all referenced external domains

### Screenshots

#### Main report (DNS, WHOIS, SSL, HTTP, Tech Fingerprint, Risk Score):
![Main Report](assets/domain_main_report.png)

#### IPQS URL threat scan:
![IPQS URL Scan](assets/domain_ipqs_scan.png)

#### Crawl results (emails, external domains, internal links):
![Crawl Results](assets/domain_crawl_results.png)

### Notes

#### The crawl uses a 1 second delay between requests out of politeness to the target server. On sites with many pages, hitting the 50 page cap will be common — this is expected behaviour. The tool will warn you if links were detected but the crawl was stopped early due to the page limit.

#### Technology fingerprinting is based on headers and static HTML only. Client-side rendered sites (React, Vue, Angular SPAs) may not reveal their full stack this way, and some detections may be absent or inaccurate if a site actively suppresses identifying headers.

#### The IPQS URL threat scan scrapes a public web page rather than using an API. It may break if IPQS changes their page structure, in which case the tool will report the section as unavailable without affecting the rest of the scan.

#### WHOIS data availability varies significantly by registrar and TLD. Privacy-protected domains will return minimal registrant information, and some TLDs rate-limit or block WHOIS queries entirely.

#### The calculated risk score is a passive heuristic derived from your own scan data. It is not a substitute for a dedicated threat intelligence feed and should be treated as an indicator rather than a definitive assessment.