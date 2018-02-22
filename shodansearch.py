#!/usr/bin/env python
#https://shodan.readthedocs.io/en/latest/api.html

import shodan

class ShodanSearch(object):

	""" 
	Class to make Shodan Search and manipulate the results

	Args:
		API_KEY (str): Shodan API KEY
	"""

	def __init__(self, API_KEY):
		"""
		Test and, if valid, set, as propertie, the API_KEY for Shodan
		"""
		self.api = shodan.Shodan(API_KEY)
		# Making a test search to see if API_KEY is valid
		try:
			self.api.count('apache')
		except:
			self.api = None
			print 'Invalid API_KEY'

	def search(self, term, page=1, limit=None, offset=None):
		"""
		Make a search to the Shodan server

		Args:
			term (str): the search term
			page (int, optional): page number of the search results
			limit (int, optional): limit the number of results returned
			offset (int, optional): search offset to begin getting results from

		Returns:
			if succeed:
			search_results (dict): dictionary with results
			else:
			search_results (None):
		"""
		try:
			search_results = self.api.search(term, page=page, limit=limit)
			self.search_results = search_results
			return self.search_results
		except:
			print 'Error while making the search! Debug the exception to find out why (:'
			self.search_results = None
			return None

	def filter_by_protocol(self, protocol):
		"""
		Filter search results by protocol

		Args:
			protocol (str): should be like 'telnet', 'ssh', 'http'... and so on

		Returns:
			filtered_by_protocol (dict): the filtered results
		"""
		if self.search_results == None:
			print 'Search results not found, try call the search() method first!'
			self.filtered_by_protocol = None
			return None

		# Creating dict to hold the filtered values
		self.filtered_by_protocol = {}

		for service in self.search_results['matches']:
			# _shodan[module] holds the protocol value
			if service['_shodan']['module'] == protocol:
				key = str(service['hostnames']) # Converting value to str because has to be imutable to be a key
				self.filtered_by_protocol.update({key: service})

		return self.filtered_by_protocol


shodan_search = ShodanSearch('ufck')
shodan_search.search('gvt', 1, 3)
shodan_search.filter_by_protocol('telnet')