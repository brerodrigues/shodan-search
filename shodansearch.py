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

	def filter(self, filter_by, filter_term, search_results=None):
		"""
		Filter the results of a Shodan search based on filter properties and terms

		Args:
			filter_by (str): the propertie to be used in the filter. Can be:
				'port' (int): from 0 to 65535
				'protocol' (str): telnet, ssh, http... and so on
				'city' (str): you name it
				'country' (str): you name it
			filter_term (str): the term used in the filter process
			search_results (dic, optional): the search results to be filtered

		Returns:
			filtered (dict): dictionary with the results
		"""
		port_filter = 'port'
		#data_filter = 'data'
		protocol_filter = ['_shodan', 'module']
		city_filter = ['location', 'city']
		country_filter = ['location', 'country_name']

		if filter_by == 'port':
			filter_key = port_filter
			filter_term = int(filter_term)
		#elif filter_by == 'data':
		#	filter_key = data_filter
		elif filter_by == 'protocol':
			filter_key = protocol_filter
		elif filter_by == 'city':
			filter_key = city_filter
		elif filter_by == 'country':
			filter_key = country_filter
		else:
			print 'Invalid filter key'
			filter_key = None
			return None

		# If not set as argument, get the propertie
		if search_results == None:
			search_results = self.search_results

		# If still None...
		if search_results == None:
			print 'Search results not found, try call the search() method first!'
			self.filtered = None
			return None

		self.filtered = {}

		for service in search_results['matches']:
			if type(filter_key) == list:
				if service[filter_key[0]][filter_key[1]] == filter_term:
					key = str(service['hostnames']) # Converting value to str because has to be imutable to be a key
					self.filtered.update({key: service})
			elif type(filter_key) == str:
				if service[filter_key] == filter_term:
					key = str(service['hostnames']) # Converting value to str because has to be imutable to be a key
					self.filtered.update({key: service})

		return self.filtered