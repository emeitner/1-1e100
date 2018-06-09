1/1e100 (or 1-1e100)
=======

Install
=======
  sudo apt-get install python3 python3-pip python3-virtualenv python3-dev
  sudo apt-get install ipset

  sudo adduser --force-badname 1-1e100

  sudo mkdir /opt/1-1e100
  sudo mkdir /var/cache/1-1e100
  sudo mkdir /var/run/1-1e100
  sudo chown 1-1e100: /opt/1-1e100 /var/cache/1-1e100 /var/run/1-1e100
  sudo -u 1-1e100 -i
  cd /opt/1-1e100
  git clone https://github.com/emeitner/1-1e100.git .
  cp config.ini.example config.ini

  virtualenv -p python3 venv
  . venv/bin/activate
  pip install mitmproxy==3.0.4
  pip install configparser


Components
==========


IPTables:
  Traffic to all Google IP networks for ports 80/443 redirected to 127.0.0.1:4432
  All other traffic to Google IPs is rejected.

MITMProxy:

  Reverse Proxy:
    Listening on 127.0.0.10:4432
    Uses basic rules to determine if a request:
      # should be retrieved, cached, and serviced from cache for all future requests
      # should be sent straight through
      # should be ignored and not serviced.
