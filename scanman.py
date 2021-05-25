#!/usr/bin/env python3

from utils import arguments
from utils import masscanner as ms
from utils import nmapper as nm
from utils import richard as r
from utils import sqlite as db
from utils import xmlparser as xp
from configparser import ConfigParser
import os
import logging


def main():
	''' Main Func '''

	# Args - init.
	args = arguments.parse_args()

	# Args - configfile
	configfile = args.configfile

	# ConfigParser - read onfigfile.
	config = ConfigParser(delimiters='=')
	config.optionxform = str
	config.read(configfile)
	
	if os.path.basename(configfile) == 'masscan.ini':

		# Args - droptable
		if args.drop:
			db.drop_table('Masscanner')

		# ConfigParser - declare dict values.
		MSCONFIG = {k: v for k, v in config['masscanconfig'].items()}
		PORTSCANS = {k: v for k, v in config['portscans'].items()}

		# Sqlite - databse init.
		db.create_table_masscanner()

		# Masscanner - instance init (interface, rate, targets:-iL).
		masscanner = ms.Masscanner(MSCONFIG['interface'], MSCONFIG['rate'], args.inputlist)
		
		# Masscanner - launch scan(s).
		for k, v in PORTSCANS.items():
			results = masscanner.run_scan(k, v)
			# Sqlite - insert results (k:ipaddress, v[0]:port, v[1]:protocol, v[2]:description).
			for k, v in results.items():
				db.insert_masscanner(k, v[0], v[1], v[2])
				# Print results.
				print(k, v[0], v[1], v[2])

		# DEV - write database results to file.
		for k, v in PORTSCANS.items():
			filepath = f'./outfiles/masscanner/{k}.txt'
			results = db.get_ipaddress_by_description(k)
			if results != []:
				with open(filepath, 'w+') as f1:
					[f1.write(f'{result[0]}\n') for result in results]


	elif os.path.basename(configfile) == 'nmap.ini':

		# Args - droptable
		if args.drop:
			db.drop_table('Nmapper')

		# ConfigParser - declare dict values.
		NMCONFIG = {k: v for k, v in config['nmapconfig'].items()}
		NSESCANS = {k: v for k, v in config['nsescans'].items()}

		# Sqlite - databse init.
		db.create_table_nmapper()

		# Nmapper - instance init.
		nmapper = nm.Nmapper()
		
		# XmlParser - instance init.
		xmlparser = xp.NSEParser()
		
		# Nmapper - launch scan(s).
		for k, v in NSESCANS.items():
			logging.info(f'Using scan: {k} = {v}')
			
			# Sqlite - fetch targets by filtering the nse-script scan port.
			results = [i[0] for i in db.get_ipaddress_by_port(v)]
			targets = ' '.join(results)
			logging.info(f'Found targets in databse.db via port: {v}')

			# DEV - targets.
			filepath = f'./outfiles/nmapper/targets.txt'
			with open(filepath, 'w+') as f1:
				[f1.write(f'{result}\n') for result in results]
				logging.info(f'Targets written to: {f1.name}')
			
			# Nmapper - launch scan(s).
			xmlfile = f'./outfiles/xmlfiles/{k}.xml'
			nmapper.run_scan(k, v, filepath, xmlfile)
		
			# XmlParser - read xml file and parse.
			xmlparser.read_xml(xmlfile)
			# XmlParser - obtain hosts:lst from xml file.
			hosts = xmlparser.get_hosts()
			# XmlParser - obtain ipaddress(es) and nsescript scan result(s) from hosts:lst.
			for host in hosts:
				ipaddress = xmlparser.get_addr(host)
				result = xmlparser.get_hostscript(host)
				# Exclude hossts with no nsescript scan result(s).
				if result is not None:
					# Sqlite - insert results (ipaddress, result[2]:nseoutput, result[0]:nsescript).
					db.insert_nmapper(ipaddress, result[2], result[0])
					# Print results.
					logging.info(f'{ipaddress}: {result[2]}')
			logging.info(f'End of scan: {k}\n')
		logging.info('All scans have completed.\n')

		# DEV - write database results to file.
		for k, v in NSESCANS.items():
			filepath = f'./outfiles/nmapper/{k}.txt'
			results = db.get_ipaddress_by_nsescript(k)
			if results != []:
				logging.info(f'Found results in databse.db via nsescript: {k}')
				with open(filepath, 'w+') as f1:
					[f1.write(f'{result[0]}, {result[1]}\n') for result in results]
					logging.info(f'Results written to: {f1.name}')


if __name__ == '__main__':
	main()
