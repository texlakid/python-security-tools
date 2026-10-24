#!/usr/bin/env python3
"""
link_scraper.py -- Attack Surface URL Extractor 
Extracts absolute URLs from a target webpage (anchors, scripts, forms, images).

Usage:
    python3 link_scraper.py -u https://target.lab -o links.txt --authorized
"""

import argparse
import sys
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}


MAX_HTML_SIZE = 5 * 1024 * 1024

def extract_links(url, insecure):
    print(f"[*] Fetching {url}...")
    try:
   
        with requests.get(url, headers=HEADERS, timeout=10, verify=not insecure, stream=True) as r:
            r.raise_for_status()
            
        
            content_length = int(r.headers.get('Content-Length', 0))
            if content_length > MAX_HTML_SIZE:
                print(f"[-] Aborted: Page is too large ({content_length} bytes). Max is {MAX_HTML_SIZE}.")
                return set()

          
            html_content = r.content[:MAX_HTML_SIZE].decode(r.apparent_encoding or 'utf-8', errors='ignore')
            
    except requests.exceptions.RequestException as e:
        print(f"[-] Error connecting: {e}")
        return set()

    soup = BeautifulSoup(html_content, "html.parser")
    unique_urls = set()


    targets = {
        "a": "href",
        "script": "src",
        "link": "href",
        "img": "src",
        "form": "action"
    }

    for tag, attr in targets.items():
        for element in soup.find_all(tag):
            val = element.get(attr)
            if val and not val.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                absolute_url = urljoin(url, val)
                unique_urls.add(absolute_url)

    return unique_urls

def main():
    parser = argparse.ArgumentParser(description="Attack Surface URL Extractor")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default="links.txt", help="Output file")
    parser.add_argument("-k", "--insecure", action="store_true", help="Skip TLS verification")
    parser.add_argument("--authorized", action="store_true", required=True, 
                        help="Confirm you have authorization to scrape this target")
    args = parser.parse_args()

    urls = extract_links(args.url, args.insecure)
    
    if not urls:
        print("[-] No URLs found or request failed.")
        sys.exit(1)

    print(f"[+] Found {len(urls)} unique endpoints.")
    
    try:
        with open(args.output, "w", encoding="utf-8") as f:
            for link in sorted(urls):
                f.write(link + "\n")
        print(f"[+] Saved to {args.output}")
    except OSError as e:
        print(f"[-] Could not write to file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
