#!/bin/bash
. ./venv/bin/activate 
#mitmproxy -T --host -p 4432   -s /opt/1-1e100/cache.py -e -v
mitmdump -T --host -p 4432   -s /opt/1-1e100/cache.py  -v
