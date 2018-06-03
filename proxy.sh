#!/bin/bash
. ./venv/bin/activate
#mitmproxy -T --host -p 4432   -s /opt/1-1e100/proxy.py -e -v --no-http2 --no-upstream-cert "$@"
mitmdump --mode transparent -p 4432   -s /home/1-1e100/1-1e100/proxy.py  -v --no-http2  "$@"
#--no-upstream-cert --host