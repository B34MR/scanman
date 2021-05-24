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


# def write_file(filename):
# 	''' '''
# 	filepath = os.path.join(f'./outfiles/masscanner/', filename)

# 	with open(filepath, 'w+') as f1:
# 		f1.write(f'{}\n')


def main():
	''' Main Func '''

	# Args - init.
	args = arguments.parse_args()

	# Args - configfile
	configfile = args.configfile
	
	if os.path.basename(configfile) == 'masscan.ini':

		# Args - droptable
		if args.drop:
			db.drop_table('Masscanner')

		# ConfigParser - read onfigfile.
		config = ConfigParser(delimiters='=')
		config.optionxform = str
		config.read(configfile)
		
		# ConfigParser - declare dict values.
		MSCONFIG = {k: v for k, v in config['masscanconfig'].items()}
		PORTSCANS = {k: v for k, v in config['portscans'].items()}

		# Sqlite - databse init.
		db.create_table1()

		# Masscanner - instance init (interface, rate, targets:-iL).
		masscanner = ms.Masscanner(MSCONFIG['interface'], MSCONFIG['rate'], args.inputlist)
		
		# Masscanner - launch scan(s).
		for k, v in PORTSCANS.items():
			results = masscanner.run_scan(k, v)
			# Sqlite - insert results (k:ipaddress, v[0]:port, v[1]:protocol, v[2]:description).
			for k, v in results.items():
				db.insert_result1(k, v[0], v[1], v[2])
				# Print results.
				print(k, v[0], v[1], v[2])

		# DEV - write database results to outfile.
		for k, v in PORTSCANS.items():
			results = db.get_ipaddress_by_description(k)
			with open(f'./outfiles/masscanner/{k}.txt', 'w+') as f1:
				[f1.write(f'{result[0]}\n') for result in results]


	elif os.path.basename(configfile) == 'nmap.ini':

		# Args - droptable
		if args.drop:
			db.drop_table('Nmapper')

		# ConfigParser - read onfigfile.
		config = ConfigParser(delimiters='=')
		config.optionxform = str
		config.read(configfile)

		# ConfigParser - declare dict values.
		NMCONFIG = {k: v for k, v in config['nmapconfig'].items()}
		NSESCANS = {k: v for k, v in config['nsescans'].items()}

		# Sqlite - databse init.
		db.create_table2()

		# Nmapper - instance init.
		nmapper = nm.Nmapper()
		
		# XmlParser - instance init.
		xmlparser = xp.NSEParser()
		
		# Nmapper - launch scan(s).
		for k, v in NSESCANS.items():
			
			# Sqlite - fetch targets by filtering the nse-script scan port.
			results = [i[0] for i in db.get_ipaddress_by_port(v)]
			targets = ' '.join(results)

			# Nmapper - launch scan(s).
			xml_file = f'./outfiles/xmlfiles/{k}.xml'
			nmapper.run_scan(k, v, targets, xml_file)
		
			# XmlParser - read xml file and parse.
			xmlparser.read_xml(xml_file)
			# XmlParser - obtain hosts:lst from xml file.
			hosts = xmlparser.get_hosts()
			# XmlParser - obtain ipaddress(es) and nse-script scan result(s) from hosts:lst.
			for host in hosts:
				ipaddress = xmlparser.get_addr(host)
				result = xmlparser.get_hostscript(host)
				# Exclude hossts with no nse script-scan result(s).
				if result is not None:
					print(f'{ipaddress}: {result}')

					# DEV - # Sqlite - insert results ().
					db.insert_result2(ipaddress, result[2], result[0])

		# DEV - write database results to outfile.
		for k, v in NSESCANS.items():
			results = db.get_ipaddress_by_nsescript(k)
			with open(f'./outfiles/nmapper/{k}.txt', 'w+') as f1:
				[f1.write(f'{result[0]}\n') for result in results]


if __name__ == '__main__':
	main()
