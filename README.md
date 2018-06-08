1/1e100 (or 1-1e100)
=======

Install
=======
  sudo apt-get install python-pip python-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev libjpeg8-dev zlib1g-dev g++ python-bs4 ipset
  sudo mkdir -p /opt
  cd /opt 
  git ..... 1-1e100
  cd 1-1e100

  pip install virtualenv
OR
sudo apt-get install  python-virtualenv
 . venv/bin/activate
pip install mitmproxy

mkdir /var/cache/1-1e100
mkdir /var/run/1-1e100
log /var/log/1-1e100

add user "1-1e100"
  1-1e100:x:1001:1001:1/1e100,,,:/opt/1-1e100:/bin/bash 

Components
==========


IPTables:
  Traffic to all Google IP networks for ports 80/443 redirected to 127.0.0.1:4432
  All other traffic to Google IPs is rejected.

MITMProxy:

  Reverse Proxy:
    Listening on 127.0.0.10:4432
    Uses basic rules to determine if a request:
      # should be sent straight through(Blogger.com...)
      should be retrieved, cached, and serviced from cache for all future requests
      should be ignored and not serviced.(return RST?)

