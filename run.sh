#! /bin/bash
set -o pipefail

set -ex

owaspzap='c:\Program Files (x86)\OWASP\Zed Attack Proxy'

/cygdrive/c/Python27/python zapcmd.py -v "${owaspzap}" https://mliw3fz8g12.americas.manulife.net/bodgeit/ 2>&1 | tee log.txt
