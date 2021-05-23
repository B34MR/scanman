#!/usr/bin/env python3

from utils import arguments
from utils import masscanner as ms
from utils import nmapper as nm
from utils import richard as r
from utils import sqlite as db
from configparser import ConfigParser
import os
import logging


def main():
	''' Main Func '''

	# Args - init.
	args = arguments.parse_args()

	# Args - configfile
	configfile = args.configfile
	
	if os.path.basename(configfile) == 'masscan.ini':

		# Args - droptable
		if args.drop:
			db.drop_table()

		# ConfigParser - read onfigfile.
		config = ConfigParser(delimiters='=')
		config.optionxform = str
		config.read(configfile)
		
		# ConfigParser - declare dict values.
		MSCONFIG = {k: v for k, v in config['masscanconfig'].items()}
		PORTSCANS = {k: v for k, v in config['myscans'].items()}

		# Sqlite - databse init.
		db.create_table()

		# Masscanner - instance init (interface, rate, targets:-iL).
		masscanner = ms.Masscanner(MSCONFIG['interface'], MSCONFIG['rate'], args.inputlist)
		
		# Masscanner - launch scan(s).
		for k, v in PORTSCANS.items():
			results = masscanner.run_scan(k, v)
			# Sqlite - insert results (k:ipaddress, v[0]:port, v[1]:protocol, v[2]:description).
			for k, v in results.items():
				db.insert_result(k, v[0], v[1], v[2])
				# Print results.
				print(k, v[0], v[1], v[2])

	elif os.path.basename(configfile) == 'nmap.ini':
		nmapper = nm.Nmapper()
		nmapper.run_scan('smb2-security-mode', '445', './outfiles/smb2-security-mode.xml')
		
		# XmlParser - instance init.
		xmlparser = nm.XmlParser('./outfiles/smb2-security-mode.xml')
		# XmlParser - obtain hosts:lst.
		hosts = xmlparser.get_hosts()
		# XmlParser - obtain ipaddresses and results from hosts:lst.
		for host in hosts:
			ipaddress = xmlparser.get_addr(host)
			result = xmlparser.get_hostscript(host)
			# Find hosts with results.
			if result is not None:
				print(ipaddress, result)


if __name__ == '__main__':
	main()
