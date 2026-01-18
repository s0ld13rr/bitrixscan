# bitrixscan

A security auditing tool for Bitrix CMS environments. This tool automates common reconnaissance and vulnerability discovery tasks based on public security research.

## Technical Overview

The scanner implements a multi-threaded engine to identify misconfigurations and known entry points. It is designed for use during the active phase of a penetration test.

### Install dependencies

```bash
pip3 install -r requirements.txt
```

## Usage

```bash
usage: bitrixscan.py [-h] [-l {quick,normal,full}] [-t THREADS] [-v] [-o OUTPUT] url

positional arguments:
  url                   Target URL

optional arguments:
  -h, --help            show this help message and exit
  -l, --level           Scan depth level (default: normal)
  -t, --threads         Concurrent threads (default: 5)
  -v, --verbose         Enable verbose output
  -o, --output          Export findings to JSON file
```
