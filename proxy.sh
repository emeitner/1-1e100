#!/bin/bash
. ./venv/bin/activate
mitmdump --mode transparent -p 4432   -s /opt/1-1e100/proxy.py  -v --no-http2 "$@"
