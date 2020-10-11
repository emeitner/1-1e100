"""

Part of the 1/1e100 project: https://github.com/emeitner/1-1e100
This is a script for mitmproxy/mitmdump running in transparent mode.
Based on: https://raw.githubusercontent.com/mitmproxy/mitmproxy/master/examples/redirect_requests.py

Copyright (c) 2019 Erik Meitner

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""

from mitmproxy import ctx
from mitmproxy.net.http import Headers
from mitmproxy import http
from pprint import pprint,pformat
from os.path import exists, isdir, dirname
from urllib.request import urlopen
from urllib.parse import quote_plus
from urllib.parse import urlparse,urlunsplit
from urllib.error import HTTPError

import configparser
import os
import re
import sys
from io import StringIO
import pickle
import logging
import traceback
from pprint import pprint,pformat

class OneOver1e100Proxy:

  def __init__(self):
    ctx.log.debug('__init__() Start')
    self.config = {}
    self.req_id = 0
    cfgparser = configparser.ConfigParser()

    #traceback.print_exc(file=sys.stdout)
    try:
      cfgparser.read("config.ini")
      self.config['local_cache'] = cfgparser.get('paths', 'local_cache')
      self.config['log_file'] = cfgparser.get('paths', 'log_file')
      self.config['log_level'] = cfgparser.get('options', 'log_level')
      self.config['download_missing'] = cfgparser.getboolean('options', 'download_missing')
      self.config['default_policy_is_block'] = cfgparser.getboolean('options', 'default_policy_is_block')
      self.config['suggest_archiveorg'] = cfgparser.getboolean('options', 'suggest_archiveorg')
      self.config['rules'] = {}
      for host,regex in cfgparser.items('rules'):
        self.config['rules'][host] = regex
      self.config['passthrough'] = {}
      for host,regex in cfgparser.items('passthrough'):
        self.config['passthrough'][host] = regex
    except configparser.ParsingError:
      ctx.log.critical("Exception occurred while parsing 1/1e100 config")
      sys.exit(1)

    #if not re.match('^(debug|info|warn|error|critical)$', self.config['log_level']) :
    #  raise("Invalid value for 'log_level' setting in configuration.")
    #  exit(1)
    #else:
    #  self.config['log_level'] = eval('ctx.log.'+self.config['log_level'].upper())

    #logging.basicConfig(
    #  filename=self.config['log_file']
    #  ,format='%(asctime)s %(levelname)s: %(message)s'
    #  , datefmt='%m/%d/%Y %I:%M:%S %p'
    #  , level=logging.INFO
    #)

    ctx.options.upstream_cert = False

    ctx.log.debug('__init__() done.')

  def request(self,flow):
    ctx.log.debug( 'request():' )
    block = False
    handled = False
    status_code = 0
    reason=''
    content_type=''
    data=''
    cache = None
    # pretty_host(hostheader=True) takes the Host: header of the request into account,
    # which is useful in transparent mode where we usually only have the IP otherwise.
    host = flow.request.pretty_host

    orig_url = flow.request.url
    try:
      urlparts = urlparse(orig_url)
    except Exception as e:
      logging.critical('Unable to parse URL {}: {}'.format(orig_url,e))

    url = urlunsplit([urlparts.scheme,host,urlparts.path,urlparts.query,''])

    self.req_id += 1
    rid = '%06d' %(self.req_id)

    if host in self.config['rules'].keys():
      if re.search(self.config['rules'][host],self.get_path(url)):
        ctx.log.debug( rid+' Rule match: %s %s' % (host, self.config['rules'][host]) )
        if 'referer' in flow.request.headers : #.keys():
          ctx.log.info( rid+ ' Referred by: %s' % ( flow.request.headers['referer'] ) )
        cache = CacheFile( url,self.config['local_cache'])
        if cache.is_in_cache():
          cache.load()
          ctx.log.info( rid+  ' Retrieved from cache: '+url )
          data = cache.data
          ctx.log.debug(pformat(cache.headers))
          content_type = cache.headers['Content-Type']
          status_code = 200
          reason = "OK2"
          ctx.log.debug( rid+ ' Cached data loaded. ' )
        else: # not cached
          if self.config['download_missing']:
            if cache.retrieve():
              ctx.log.info(  rid+ ' Downloaded: '+url  )
              data = cache.data
              content_type = cache.headers['Content-Type']
              status_code = 200
              reason = "OK3"
            elif cache.code==404:
              ctx.log.error( rid+ ' ERROR: '+cache.error_text  )
              data=''
              content_type = "text/html"
              status_code = cache.code
              reason = "Not found"
            else:
              ctx.log.error( rid+ ' ERROR: '+cache.error_text  )
              data=''
              content_type = "text/html"
              status_code = 500
              reason = "FAILED TO RETRIEVE"
          else: #  not download_missing
            data = ''
            content_type = "text/html"
            status_code = 404
            reason = "NOPE"
        # end else: #not cached
        handled = True
      # end if re.search(self.config['rules'][host],get_path(url)):
      #else: # not re.search(self.config['rules'][host],self.get_path(url)):
      #  block = self.config['default_policy_is_block']
    if not handled:
      if host in self.config['passthrough'].keys():
        if re.search(self.config['passthrough'][host],self.get_path(url)):
          ctx.log.info( '{} ****************************** PASSTHROUGH {} - {}: {}'.format(rid,host,self.config['passthrough'][host],url)  )
          return
        else:
          block = self.config['default_policy_is_block']
      elif '*' in self.config['passthrough'].keys():
        if re.search(self.config['passthrough']['*'],self.get_path(url)):
          ctx.log.info( '{} ****************************** PASSTHROUGH {} - {}: {}'.format(rid,'*',self.config['passthrough']['*'],url)  )
          return
        else:
          block = self.config['default_policy_is_block']
      else: # host NOT in self.config['rules'].keys()
        block = self.config['default_policy_is_block']

    if self.config['default_policy_is_block']:
      ctx.log.info('Default policy: BLOCK')

    if block == True:
      ctx.log.info('URL blocked: '+url)
      # Use flow.kill(resp) ??
      content_type = "text/html"
      reason = "1/1e100"
      if self.config['suggest_archiveorg']:
        data = '<html><b>1/1e100</b><br ><a href="https://web.archive.org/web/*/%s">https://web.archive.org/web/*/%s</a></html>' % (url,url)
        status_code = 200
        ctx.log.debug('a.o!')
      else:
        data = '1/1e100'
        status_code = 403
        ctx.log.info( rid+ ' BLOCKED: '+url  )

    if type(data) == str:
      data = data.encode()
    if type(reason) == str:
      reason = reason.encode()
    if type(content_type) == str:
      content_type = content_type.encode()

    print('content_type={} block={} reason={}'.format(content_type,block,reason))

    if cache is not None:
      headers = cache.headers
    else:
      headers = Headers(
        Content_Type=content_type
        ,Crampus='Engaged'
      )

    resp = http.HTTPResponse(
      'HTTP/1.1'  # http://stackoverflow.com/questions/34677062/return-custom-response-with-mitmproxy
      ,status_code
      ,reason
      ,headers
      ,data
    )
    ctx.log.debug('RESPONSE, new: '+pformat(resp))
    flow.response = resp
    #flow.kill()
    ctx.log.debug("request() done. ---------------------------------")
    #return True
    # end request()

  def get_path(self,url):
      _, _, path, _, _, _ = urlparse(url)
      return path

  def get_host(self,url):
    _, host, _, _, _, _ = urlparse(url)
    return host


##############################
# Simple class to encapsulate
# the cacheing functionality
class CacheFile(object):
  def __init__(self,url,cache_dir):
    self.__url = url
    self.__cache_dir = cache_dir
    scheme, host, path, params,query,fragment = urlparse( url )
    self.__host = host
    self.__path = path
    self.__query = query
    self.__cache_file_path = self._create_cache_file_name(self.__host,self.__path+'?'+self.__query)
    self.__data = ''
    self.__headers = ''
    self.__error_text = ''
    self.__code = 0

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
  @property
  def code(self):
      return self.__code
  #
  # download the file pointed at by self.__url and store it in the cache
  # along with the headers
  #
  def retrieve(self):
    host_dir = os.path.join( self.__cache_dir,self.__host )
    if not exists( host_dir  ):
      try:
        os.makedirs( host_dir )
      except OSError as e:
        self.__error_text = "retrieve() makedirs: "+e.strerror
        return False
    if exists( self.__cache_file_path ):
      os.remove( self.__cache_file_path )
    try:
      resp = urlopen( self.__url )
    except HTTPError as e:
      self.__code = e.code
      self.__error_text = "retrieve(%s,%s) urlretrieve(): %s: %s" %(self.__url,self.__cache_file_path, e.code, e.strerror)
      return False
    except IOError as e:
      self.__error_text = "retrieve(%s,%s) urlretrieve(): %s" %(self.__url,self.__cache_file_path, e.strerror)
      return False
    self.__code = resp.getcode()
    data = resp.read()
    try:
      with open(self.__cache_file_path, 'wb') as file_fd:
        file_fd.write(data)
    except OSError as e:
      self.__error_text = "retrieve(%s,%s) saving data : %s" %(self.__url,self.__cache_file_path, e.strerror)
      return False
    headers = dict( resp.getheaders() )
    headers_file = self.__cache_file_path+'.headers'
    try:
      file_fd = open(headers_file, 'wb')
      pickle.dump(headers,file_fd)
      file_fd.close()
    except pickle.PicklingError as e:
      ctx.log.critical('Unable to pickle headers.')
      raise e
    except Exception as e:
      ctx.log.debug(str(e))
      return False

    if self.load():
      ctx.log.debug("OK data="+self.__data.decode())
      return True
    ctx.log.debug("NO data="+self.__data.decode())
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
    self.__code = 200
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
      file_fd = open(path, 'rb')
      data = pickle.load( file_fd )
    except IOError as e:
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

addons = [
    OneOver1e100Proxy()
]
