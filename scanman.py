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

		# Args - droptable
		if args.drop:
			db.drop_table()

		# ConfigParser - read onfigfile.
		config = ConfigParser(delimiters='=')
		config.optionxform = str
		config.read(configfile)

		# ConfigParser - declare dict values.
		NMCONFIG = {k: v for k, v in config['nmapconfig'].items()}
		NSESCANS = {k: v for k, v in config['myscans'].items()}

		# Nmapper - instance init.
		nmapper = nm.Nmapper()
		
		# XmlParser - instance init.
		xmlparser = nm.XmlParser()
		
		# Nmapper - launch scan(s).
		for k, v in NSESCANS.items():
			
			# Sqlite - Fetch targets by nse-script scan port.
			results = [i[0] for i in db.get_ipaddress_by_port(v)]
			targets = ' '.join(results)

			# Nmapper - launch scan(s).
			xml_filepath = f'./outfiles/{k}.xml'
			nmapper.run_scan(k, v, targets, xml_filepath)
		
			# XmlParser - read xml file and parse.
			xmlparser.read_xml(xml_filepath)
			# XmlParser - obtain hosts:lst from xml file.
			hosts = xmlparser.get_hosts()
			# XmlParser - obtain ipaddress(es) and nse-script scan result(s) from hosts:lst.
			for host in hosts:
				ipaddress = xmlparser.get_addr(host)
				result = xmlparser.get_hostscript(host)
				# Exclude hossts with no nse script-scan result(s).
				if result is not None:
					print(ipaddress, result)


if __name__ == '__main__':
	main()
