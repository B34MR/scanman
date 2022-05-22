#!/usr/bin/python3

import dns.resolver
import logging
import json
import sys


def query(name, service='', protocol='', recordtype='', nameserver=''):
	'''Queries a Domain Name to resolve it's SRV records
	or queries a Hostname to resolve it's IP records.

	Keyword arguments:
	name -- DomainName or HostName (required, default none)
	service -- Service name (optional, accepted values _kerberos./_ldap./_autodiscover., default none)
	protocol -- Transport protocol of the service (optional, accepted values _tcp./_udp., default none)
	recordtype -- DNS Record type (optional, accepted values SRV/A, default SRV)
	nameserver -- Nameserver to query from (optional, default /etc/resolv.conf)
	'''
	
	# Hostname list
	host_lst = []

	try:

		if recordtype == 'SRV':
			if nameserver: # custom nameserver was defined
				custom_resolver = dns.resolver.Resolver(configure=False)
				custom_resolver.nameservers = [nameserver]
				answer = custom_resolver.resolve(service + protocol + name, recordtype, raise_on_no_answer=True)
			else: # default nameserver selected
				answer = dns.resolver.resolve(service + protocol + name, recordtype, raise_on_no_answer=True)

			for record in answer:
				if service == '_autodiscover.': # autodiscover was defined
					hostname = str(record).lower()[8::] # parse record for autodiscover
				elif service == '_kerberos.':
					hostname = str(record).lower()[9:] # parse record for kerberos
				host_lst.append(hostname) # populate host_list with hostname
		else:
			if nameserver: # custom nameserver selected
				custom_resolver = dns.resolver.Resolver(configure=False)
				custom_resolver.nameservers = [nameserver]
				answer = custom_resolver.resolve(service + protocol + name, recordtype, raise_on_no_answer=True)
			else: # default nameserver selected
				answer = dns.resolver.resolve(service + protocol + name, recordtype, raise_on_no_answer=True)
			
			for record in answer:
				ipaddress = str(record)	# convert rdata to string
				host_lst.append(ipaddress) # populate host_list with ipaddress (IPAddress)

	except dns.resolver.NXDOMAIN as error:
		logging.debug(f'NXDOMAIN-{error}\n')
		pass
	except dns.resolver.NoAnswer as error:
		logging.debug(f'NoAnswer-{error}\n')
		pass
	except dns.resolver.YXDOMAIN as error:
		logging.debug(f'YXDOMAIN-{error}\n')
		pass
	except dns.resolver.NoNameservers as error:
		logging.debug(f'NoNameservers-{error}\n')
		pass
	except Exception as error:
		logging.debug(f'Script Error-{error}\n')
	
	return host_lst
