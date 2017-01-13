#! /bin/bash
set -o pipefail

if (( $# < 1 )) ; then
    echo "Usage: $0 TARGET_URL" >&2
    exit 1
fi

set -ex

owaspzap='c:\Program Files (x86)\OWASP\Zed Attack Proxy'

python zapcmd.py -v "${owaspzap}" "$1" 2>&1 | tee log.txt
