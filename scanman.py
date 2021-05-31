#!/usr/bin/env python3

from utils import arguments
from utils import masscanner
from utils import mkdir
from utils import nmapper
from utils import richard as r
from utils import sqlite as db
from utils import xmlparser
from configparser import ConfigParser
import os
import logging

# Outputfile dirs.
MAIN_DIR = './outputfiles'
ms_dir = os.path.join(MAIN_DIR, 'masscanner')
nm_dir = os.path.join(MAIN_DIR, 'nmapper')
xml_dir = os.path.join(MAIN_DIR, 'xmlfiles')

# Nmapper target/inputlist Filepath.
nm_targetfile = os.path.join(nm_dir, 'targets.txt')

# Create output dirs.
directories = [ms_dir, nm_dir, xml_dir]
dirs = [mkdir.mkdir(directory) for directory in directories]
[logging.info(f'Created directory: {d}') for d in dirs if d is not None]


def main():
	''' Main Func '''

	# Args - init.
	args = arguments.parse_args()

	# Args - configfile.
	configfile = args.configfile

	# Args - inputlist
	ms_targetfile = args.inputlist
		
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
		ms = masscanner.Masscanner(MSCONFIG['interface'], MSCONFIG['rate'], ms_targetfile)
		
		# Banner
		r.banner('Masscanner')
		
		# Masscanner - launch scan(s).
		with r.console.status(spinner='bouncingBar', status=f'[status.text]Scanning') as status:
			for key, value in PORTSCANS.items():
				results = ms.run_scan(key, value)
				# Sqlite - insert results (k:ipaddress, v[0]:port, v[1]:protocol, v[2]:description).
				for k, v in results.items():
					db.insert_masscanner(k, v[0], v[1], v[2])
					# Print results.
					r.console.print(f'[chartreuse3][+][/chartreuse3] {k}: {v[0]}')
				r.console.print(f'[grey37]Completed:[/grey37] {key.upper()}\n')
			r.console.print('All scans have completed!\n')

		# Sqlite - write database results to output file.
		for k, v in PORTSCANS.items():
			filepath = os.path.join(ms_dir, f'{k}.txt')
			results = db.get_ipaddress_by_description(k)
			if results != []:
				logging.info(f'Found results in databse.db via description: {k}')
				with open(filepath, 'w+') as f1:
					[f1.write(f'{result[0]}\n') for result in results]
					r.console.print(f'Results written to: {f1.name}')


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
		nm = nmapper.Nmapper()
		
		# Banner
		r.banner('Nmap-Script Scanner')
		
		# Nmapper - launch scan(s).
		with r.console.status(spinner='bouncingBar', status=f'[status.text]Scanning') as status:
			for k, v in NSESCANS.items():
				# r.console.print(f'[grey37]{k}:')
				
				# Sqlite - fetch targets by filtering the nse-script scan port.
				results = [i[0] for i in db.get_ipaddress_by_port(v)]
				# targets = ' '.join(results)
				logging.info(f'Found targets in databse.db via port: {v}')
				# Write targets to output file (targets are overwritten on each loop).
				with open(nm_targetfile, 'w+') as f1:
					[f1.write(f'{i}\n') for i in results]
					logging.info(f'Targets written to: {f1.name}')
				
				# Nmapper - launch scan(s).
				xmlfilepath = os.path.join(xml_dir, f'{k}.xml')
				nm_cmd = nm.run_scan(k, v, nm_targetfile, xmlfilepath)
				r.console.print(f'[white]{nm_cmd}')
			
				# DEV - fix the cls, self within the NseParser class.			
				# XmlParser - read xml file.
				results = xmlparser.NseParser().get_nse_results(xmlfilepath)

				# Sqlite - insert xml results (i[0]:ipaddress, i[1]:nseoutput, i[2]:nsescript).
				[db.insert_nmapper(i[0], i[1], i[2]) for i in results if i != None]
				
				# DEV Print - Experimental SMB-Signing print.
				for i in results:
					if i[1] == 'Message signing enabled but not required':
						r.console.print(f'[chartreuse3][+][/chartreuse3] {i[0]}: {i[1]}')
					else:
						r.console.print(f'[-] {i[0]}: {i[1]}')

				r.console.print(f'[grey37]Completed:[/grey37] {k.upper()}\n')
			r.console.print('All scans have completed!\n')

		# Sqlite - write database results to output file.
		for k, v in NSESCANS.items():
			filepath = os.path.join(nm_dir, f'{k}.txt')
			results = db.get_ipaddress_by_nsescript(k)
			if results != []:
				logging.info(f'Found results in databse.db via nsescript: {k}')
				with open(filepath, 'w+') as f1:
					[f1.write(f'{result[0]}, {result[1]}\n') for result in results]
					r.console.print(f'Results written to: {f1.name}')


if __name__ == '__main__':
	main()
