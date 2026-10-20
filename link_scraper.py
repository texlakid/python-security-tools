#!/usr/bin/env python3
"""
Professional Web Link Scraper
Extracts unique, absolute URLs from a target webpage.

Usage:
    python3 link_scraper.py -u https://example.com -o links.txt
"""

import requests
from bs4 import BeautifulSoup
import argparse
from urllib.parse import urljoin, urlparse


HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

def scrape_links(url, output_file):
    print(f"[*] Fetching {url}...")
    
    try:
   
        response = requests.get(url, headers=HEADERS, timeout=10, verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[-] Error connecting: {e}")
        return

    soup = BeautifulSoup(response.text, "html.parser")
    links = soup.find_all("a")
    
  
    unique_urls = set()
    
    for link in links:
        href = link.get("href")
        if href:
            
            absolute_url = urljoin(url, href)
            unique_urls.add(absolute_url)

    print(f"[+] Found {len(unique_urls)} unique links.")

    
    with open(output_file, "w") as f:
        for link in sorted(unique_urls):
            f.write(link + "\n")
            
    print(f"[+] Saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Professional Web Link Scraper")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g. https://example.com)")
    parser.add_argument("-o", "--output", default="links.txt", help="Output file name (default: links.txt)")
    
    args = parser.parse_args()
    
   
    requests.packages.urllib3.disable_warnings()
    
    scrape_links(args.url, args.output)
