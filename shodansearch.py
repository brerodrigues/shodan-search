#!/usr/bin/env python

import shodan

class ShodanSearch(object):

	def __init__(self, API_KEY):
		self.api = shodan.Shodan(API_KEY)
		# Testing if API_KEY is valid
		try:
			self.api.count('apache')
		except:
			print 'Invalid API_KEY'
			return None

	def search(self, term, page=1, limit=None, offset=None):
		try:
			search_results = self.api.search(term, page=page, limit=limit)
			self.search_results = search_results
			return self.search_results
		except:
			print 'Error while making the search!'
			self.search_results = None
			return None

	def filter_by_protocol(self, protocol):
		if self.search_results == None:
			print 'Search results not found, try call the search method first!'
			self.filtered_by_protocol = None
			return None

		self.filtered_by_protocol = {}

		for service in self.search_results['matches']:
			if service['_shodan']['module'] == protocol:
				key = str(service['hostnames']) # Converting value to str because has to be imutable to be a key
				self.filtered_by_protocol.update({key: service})

		return self.filtered_by_protocol


shodan_search = ShodanSearch('ufck')
shodan_search.search('gvt', 1, 3)
shodan_search.filter_by_protocol('telnet')