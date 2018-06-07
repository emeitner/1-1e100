#!/home/1-1e100/venv/bin/python

from urllib.request import urlopen
import bs4
import lxml
from bs4 import BeautifulSoup
from netaddr import *
import re

#import tempfile
#temp_fd,temp_path = tempfile.mkstemp()
#print temp_path


netnames= [
  'GOGL'
  ,'GOOGL-2'
  ]

for netname in netnames:
  url = 'https://whois.arin.net/rest/org/{}/nets'.format(netname)
  uf = urlopen( url )
  page = uf.read()

  # <?xml version='1.0'?>
  # <?xml-stylesheet type='text/xsl' href='https://whois.arin.net/xsl/website.xsl' ?>
  # <nets xmlns="https://www.arin.net/whoisrws/core/v1" xmlns:ns2="https://www.arin.net/whoisrws/rdns/v1" xmlns:ns3="https://www.arin.net/whoisrws/netref/v2" inaccuracyReportUrl="https://www.arin.net/public/whoisinaccuracy/index.xhtml" termsOfUse="https://www.arin.net/whois_tou.html">
  # <limitExceeded limit="256">false</limitExceeded>
  # <netRef endAddress="209.185.108.255" startAddress="209.185.108.128" handle="NET-209-185-108-128-1" name="SAVV-S232078-3">https://whois.arin.net/rest/net/NET-209-185-108-128-1</netRef>
  # <netRef endAddress="63.158.137.231" startAddress="63.158.137.224" handle="NET-63-158-137-224-1" name="Q0702-63-158-137-224">https://whois.arin.net/rest/net/NET-63-158-137-224-1</netRef>

  parsed = BeautifulSoup(page,'xml')
  for netref in  parsed.find_all('netRef'):
    if re.search('^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$',netref['startAddress']):
      #print "%s-%s" % (netref['startAddress'], netref['endAddress']),
      ip_list = list(iter_iprange(netref['startAddress'],netref['endAddress']))
      merged = cidr_merge(ip_list)
      #print " -> %s" % (merged[0].cidr)
      print( merged[0].cidr)
