#!/bin/bash
#mitmproxy -T --host -p 4432   -s cache.py -e -v --no-http2
mitmdump -T --host -p 4432   -s cache.py  -v --no-http2