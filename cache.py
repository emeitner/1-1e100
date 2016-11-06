#from libmproxy.protocol.http import HTTPResponse

from mitmproxy.models.http import HTTPResponse
#from libmproxy.models import HTTPResponse
from netlib.http import Headers

from mitmproxy import ctx

#from netlib.odict import ODictCaseless
from pprint import pprint
from os.path import exists, isdir, dirname
from os import makedirs
from urllib import urlretrieve, quote_plus

import urlparse

from hashlib import md5
import os
import re
from mimetools import Message
from StringIO import StringIO
import pickle

from pprint import pformat

"""
Based on: https://raw.githubusercontent.com/mitmproxy/mitmproxy/master/examples/redirect_requests.py

To do:

"""

local_cache = '/var/cache/1-1e100'

cache_patterns = {
  'ajax.googleapis.com': '/ajax/.+'
  ,'fonts.googleapis.com': '/.*'
  ,'fonts.gstatic.com': '/.*'
  ,'www.gstatic.com': '/images/icons/.*'
}

# Download all missing resources to the cache
download_missing = True

# What to do if a request was not handled:
# True = block it
# False = let it go through
default_policy_is_block = True

# FIXME
# Domains to divert to local server
divert_domains = [
  'ajax.googleapis.com'
  ,'fonts.googleapis.com'
#  ,'gstatic.com'
#  ,'googlecommerce.com'
#  ,'apis.google.com'
#  ,'googleusercontent.com'
  ]
suggest_archiveorg = True

############################################33
# @concurrent
def request(flow):
  ctx.log.debug( 'request():')
  block = False

  # pretty_host(hostheader=True) takes the Host: header of the request into account,
  # which is useful in transparent mode where we usually only have the IP otherwise.
  host = flow.request.pretty_host
  orig_url = flow.request.url
  urlparts = urlparse.urlparse(orig_url)
  url = urlparse.urlunsplit([urlparts.scheme,host,urlparts.path,urlparts.query,''])

  # # Method 1: Answer with a locally generated response
  # if host.endswith("example.com"):
  #     resp = HTTPResponse(
  #         [1, 1], 200, "OK"
  #         ,Headers( Content_Type="text/html" )
  #         ,"You been hacksed!"
  #         )
  #     flow.reply(resp)
  #     return

  if host in cache_patterns.keys():
    if re.search(cache_patterns[host],get_path(url)):
      ctx.log.debug( ('cache_pattern match: %s %s' % (host, cache_patterns[host]) ))
      if 'referer' in flow.request.headers : #.keys():
        ctx.log.debug( 'Referred by: %s' % ( flow.request.headers['referer'] ) )
      cache = CacheFile( url,local_cache)
      if cache.is_in_cache():
        cache.load()
        ctx.log.debug(  'Retrieved from cache: '+url )
        data = cache.data
        content_type = cache.headers['Content-Type']
        status_code = 200
        reason = "OK2"
        #ctx.log.debug( 'Cache data=: '+data )
      else: # not cached
        if download_missing:
          if cache.retrieve():
            ctx.log.debug(  'Downloaded: '+url  )
            data = cache.data
            content_type = cache.headers['Content-Type']
            status_code = 200
            reason = "OK3"
          else:
            ctx.log.debug( 'ERROR: '+cache.error_text )
            data=''
            content_type = "text/html"
            status_code = 500
            reason = "FAILED TO RETRIEVE"
        else: #  not download_missing
          data = ''
          content_type = "text/html"
          status_code = 403
          reason = "NOPE"
        # end else: #not cached
      # end if re.search(cache_patterns[host],get_path(url)):
    # end if host in cache_patterns.keys()
    else: # host NOT in cache_patterns.keys()
      block = True
  elif default_policy_is_block:
      block = True

  if block == True:
    # Use flow.kill(resp) ??
    if suggest_archiveorg:
      data = '<html><b>1/1e100</b><br ><a href="https://web.archive.org/web/*/%s">https://web.archive.org/web/*/%s</a></html>' % (url,url)
    else:
      data = '1/1e100'
    content_type = "text/html"
    status_code = 403
    reason = "1/1e100"
    ctx.log.debug( 'BLOCKED: '+url) 

  resp = HTTPResponse(
      'HTTP/1.1'  # http://stackoverflow.com/questions/34677062/return-custom-response-with-mitmproxy
      ,status_code
      ,reason
      ,Headers(
        Content_Type=content_type
        )
      ,data
      )
  #ctx.log.debug( 'HTTPResponse: '+pformat(resp) )
  flow.response = resp
  #ctx.log.debug( 'WHOA! HOW\'D THIS HAPPEN? '+url )
  return



def get_path(url):
  _, _, path, _, _, _ = urlparse.urlparse(url)
  return path

def get_host(url):
  _, host, _, _, _, _ = urlparse.urlparse(url)
  return host

def abort():
  return False



###########################
#
###########################
class CacheFile(object):
  def __init__(self,url,cache_dir):
    self.__url = url
    self.__cache_dir = cache_dir
    scheme, host, path, params,query,fragment = urlparse.urlparse( url )
    self.__host = host
    self.__path = path
    self.__query = query
    self.__cache_file_path = self._create_cache_file_name(self.__host,self.__path+'?'+self.__query)
    self.__data = ''
    self.__headers = ''
    self.__error_text = ''

  @property
  def url(self):
     return self.__url
  @property
  def host(self):
     return self.__host
  @property
  def path(self):
     return self.__path
  @property
  def query(self):
     return self.__query
  @property
  def data(self):
     return self.__data
  @property
  def headers(self):
     return self.__headers
  @property
  def cache_file_path(self):
     return self.__cache_file_path
  @property
  def error_text(self):
     return self.__error_text

  #
  # download the file pointed at by self.__url and store it in the cache
  # along with the headers
  #
  def retrieve(self):
    host_dir = os.path.join( self.__cache_dir,self.__host )
    if not exists( host_dir  ):
      try:
        makedirs( host_dir )
      except OSError,e:
        self.__error_text = "retrieve() makedirs: "+e.strerror
        return False
    if exists( self.__cache_file_path ):
      os.remove( self.__cache_file_path )
    try:
      [fn,resp] = urlretrieve(self.__url,self.__cache_file_path )
    except IOError,e:
      self.__error_text = "retrieve(%s,%s) urlretrieve(): %s" %(self.__url,self.__cache_file_path, e.strerror)
      return False
    headers = dict(map((lambda h: (h.replace("\r\n",'')).split(':',1)),resp.headers))
    headers_file = self.__cache_file_path+'.headers'
    try:
      file_fd = open(headers_file, 'w')
      pickle.dump(headers,file_fd)
      file_fd.close()
    except:
      return False
    if self.load():
      #self.__write_log("OK data="+self.__data)
      return True
    #self.__write_log("NO data="+self.__data)
    return False

  #
  # Check if the file from self.__url is in the cache
  #
  def is_in_cache(self):
    return exists( self.__cache_file_path )


  #
  # Load the data from the cache
  #
  def load(self):
    self.__data = self.__load_file(self.__cache_file_path)
    self.__headers = self.__load_headers( self.__cache_file_path+'.headers' )
    if not self.__data or not self.__headers:
      return False
    return True

  #
  # Get the contents of a file
  #
  def __load_file(self,path):
    try:
      file_fd = open(path, 'rb')
      content = file_fd.read(-1)
    except OSError:
      return False
    file_fd.close()
    return content

  #
  # Get the contents of a file and unpickle it. used only for headers data
  #
  def __load_headers(self,path):
    try:
      file_fd = open(path, 'r')
      data = pickle.load( file_fd )
    except IOError,e:
      self.__error_text = e.strerror
      return False
    file_fd.close()
    return data

  #
  # Create a file name from the cache directory and path data in the url
  #
  def _create_cache_file_name(self,host,path):
    return os.path.join( self.__cache_dir, host, quote_plus( path ) )

  def __write_log(self,msg,extra=None):
    log_fd = open('/tmp/1-1e100.log', 'a')
    log_fd.write("%s :: %s\n" % (self.__url, msg) )
    if extra:
      log_fd.write(pformat(extra))
    log_fd.close()




# end class CacheFile(object):
