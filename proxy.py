"""

Part of the 1/1e100 project: https://github.com/emeitner/1-1e100
This is a script for mitmproxy/mitmdump running in transparent mode.
Based on: https://raw.githubusercontent.com/mitmproxy/mitmproxy/master/examples/redirect_requests.py

Copyright (c) 2016 Erik Meitner

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

#from mitmproxy.models.http import HTTPResponse
from mitmproxy.net.http import Headers

#from mitmproxy.script import concurrent

from pprint import pprint,pformat
from os.path import exists, isdir, dirname
from urllib.request import urlretrieve
from urllib.parse import quote_plus
import urllib.parse

import configparser
import os
import re
import sys
#from mimetools import Message
from io import StringIO
import pickle
import logging

import traceback


class OneOver1e100Proxy:

	def __init__(self):
		self.config = {}
		self.req_id = 0
		configparser = ConfigParser.ConfigParser()

		#traceback.print_exc(file=sys.stdout)
		try:
			configparser.read("config.ini")
			self.config['local_cache'] = configparser.get('paths', 'local_cache')
			self.config['log_file'] = configparser.get('paths', 'log_file')
			self.config['log_level'] = configparser.get('options', 'log_level')
			self.config['download_missing'] = configparser.getboolean('options', 'download_missing')
			self.config['default_policy_is_block'] = configparser.getboolean('options', 'default_policy_is_block')
			self.config['suggest_archiveorg'] = configparser.getboolean('options', 'suggest_archiveorg')
			self.config['rules'] = {}
			for host,regex in configparser.items('rules'):
				self.config['rules'][host] = regex
		except ConfigParser.ParsingError:
			print("Exception occurred while parsing 1/1e100 config")
			sys.exit(1)

		if not re.match('^(debug|info|warn|error|critical)$', self.config['log_level']) :
			raise("Invalid value for 'log_level' setting in configuration.")
			exit(1)
		else:
			self.config['log_level'] = eval('logging.'+self.config['log_level'].upper())

		logging.basicConfig(
			filename=self.config['log_file']
			,format='%(asctime)s %(levelname)s: %(message)s'
			, datefmt='%m/%d/%Y %I:%M:%S %p'
			, level=logging.INFO
		)
		#! logging.info('Starting up.')

	def request(flow):
		global req_id
		#! logging.debug( 'request():' )
		block = False

		# pretty_host(hostheader=True) takes the Host: header of the request into account,
		# which is useful in transparent mode where we usually only have the IP otherwise.
		host = flow.request.pretty_host

		orig_url = flow.request.url
		urlparts = urlparse.urlparse(orig_url)
		url = urlparse.urlunsplit([urlparts.scheme,host,urlparts.path,urlparts.query,''])

		req_id += 1
		rid = '%06d' %(req_id)

		if host in config['rules'].keys():
			if re.search(config['rules'][host],get_path(url)):
				#! logging.debug( rid+' Rule match: %s %s' % (host, config['rules'][host]) )
				#! if 'referer' in flow.request.headers : #.keys():
					#! logging.info( rid+ ' Referred by: %s' % ( flow.request.headers['referer'] ) )
				cache = CacheFile( url,config['local_cache'])
				if cache.is_in_cache():
					cache.load()
					#! logging.info( rid+  ' Retrieved from cache: '+url )
					data = cache.data
					content_type = cache.headers['Content-Type']
					status_code = 200
					reason = "OK2"
					#! logging.debug( rid+ ' Cache data=: '+data  )
				else: # not cached
					if config['download_missing']:
						if cache.retrieve():
							#! logging.info(  rid+ ' Downloaded: '+url  )
							data = cache.data
							content_type = cache.headers['Content-Type']
							status_code = 200
							reason = "OK3"
						else:
							#! logging.error( rid+ ' ERROR: '+cache.error_text  )
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
				# end if re.search(config['rules'][host],get_path(url)):
			# end if host in config['rules'].keys()
			else: # host NOT in config['rules'].keys()
				block = True
		elif config['default_policy_is_block']:
			block = True

		if block == True:
			# Use flow.kill(resp) ??
			if config['suggest_archiveorg']:
				data = '<html><b>1/1e100</b><br ><a href="https://web.archive.org/web/*/%s">https://web.archive.org/web/*/%s</a></html>' % (url,url)
			else:
				data = '1/1e100'
				content_type = "text/html"
				status_code = 403
				reason = "1/1e100"
				#! logging.info( rid+ ' BLOCKED: '+url  )

				resp = HTTPResponse(
					'HTTP/1.1'  # http://stackoverflow.com/questions/34677062/return-custom-response-with-mitmproxy
					,status_code
					,reason
					,Headers(
						Content_Type=content_type
					)
					,data
				)
				flow.response = resp
				return

	def get_path(url):
  		_, _, path, _, _, _ = urlparse.urlparse(url)
  		return path

	def get_host(url):
		_, host, _, _, _, _ = urlparse.urlparse(url)
		return host


	##############################
	# Simple class to encapsulate
	# the cacheing functionality
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
					os.makedirs( host_dir )
				except OSError as e:
					self.__error_text = "retrieve() makedirs: "+e.strerror
					return False
			if exists( self.__cache_file_path ):
				os.remove( self.__cache_file_path )
			try:
				[fn,resp] = urlretrieve(self.__url,self.__cache_file_path )
			except IOError as e:
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
