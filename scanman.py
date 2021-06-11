#!/usr/bin/env python3

from utils import arguments
from utils import metasploiter
from utils import masscanner
from utils import mkdir
from utils import nmapper
from utils import richard as r
from utils import sqlite as db
from utils import xmlparser
from configparser import ConfigParser
import os
import re
import logging


# Stable versions.
ms_stablever = '1.3.2'
msf_stablever = '6.0.30'
nm_stablever = '7.91'

# Outputfile dirs.
MAIN_DIR = './outputfiles'
findings_dir = os.path.join(MAIN_DIR, 'findings')
portscans_dir = os.path.join(MAIN_DIR, 'portscans')
xml_dir = os.path.join(MAIN_DIR, 'xml')

# Nmap / Metasploit temp target/inputlist filepath.
targetfilepath = os.path.join(MAIN_DIR, 'targets.txt')

# Banner - main header.
r.banner('Scanman'.upper())

# Create output dirs.
directories = [portscans_dir, findings_dir, xml_dir]
dirs = [mkdir.mkdir(directory) for directory in directories]
[logging.info(f'Created directory: {d}') for d in dirs if d is not None]


# Version check.
def version_check(mystr, currentver, stablever):
	''' 
	Returns if app version is supported or not to stdout. 
	arg(s):mystr:str, currentver:str, stablever:str '''

	if currentver == stablever:
		r.console.print(f'[i grey37]{mystr} {currentver}')
	else:
		r.console.print(f'[red][!] Warning[i] using {mystr} {currentver}')


# Targetfile creation.
def create_targetfile(port, targetfilepath):
	'''
	Fetch target ipaddresses from db by filtering the port 
	and write results to a flatfile.
	arg(s)port:str, targetfilepath:str '''
	
	# DEV - support multiple ports.
	# Sqlite - fetch targets by filtering the nse-scan port (v).
	results = [i[0] for i in db.get_ipaddress_by_port(port)]
	logging.info(f'Found targets in databse.db via port: {port}')
	# Write targets to temp outputfile (targets are overwritten on each loop).
	with open(targetfilepath, 'w+') as f1:
		[f1.write(f'{i}\n') for i in results]
		logging.info(f'Targets written to: {f1.name}')


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
		# Sqlite - databse init.
		db.create_table_masscanner()
		# ConfigParser - declare dict values.
		MSCONFIG = {k: v for k, v in config['masscanconfig'].items()}
		PORTSCANS = {k: v for k, v in config['portscans'].items()}
		interface = MSCONFIG['interface']
		rate = MSCONFIG['rate']
		# Masscanner - version check.
		version = version_check('Masscan', \
			masscanner.Masscanner.get_version(), ms_stablever)
		print('\n')

		# Masscanner - instance int and run scan.
		for key, value in PORTSCANS.items():
			ms = masscanner.Masscanner(interface, rate, key, value, ms_targetfile)
			# Masscanner - print cmd to stdout.
			print(ms.cmd)			
			# Masscanner - launch scam.
			with r.console.status(spinner='bouncingBar', status=f'[status.text]Scanning {key.upper()}') as status:
				results = ms.run_scan()
				r.console.print(f'[grey37]{key.upper()}')

				# Sqlite - insert results (k:ipaddress, v[0]:port, v[1]:protocol, v[2]:description).
				for k, v in results.items():
					db.insert_masscanner(k, v[0], v[1], v[2])
					# Print masscanner results to stdout.
					r.console.print(f'{k} {v[0]}')
				print('\n')
		r.console.print('[bold gold3]All scans have completed!\n')

		# Sqlite - write database results to outputfile.
		for k, v in PORTSCANS.items():
			filepath = os.path.join(portscans_dir, f'{k}.txt')
			results = db.get_ipaddress_by_description(k)
			if results != []:
				logging.info(f'Found results in databse.db via description: {k}')
				with open(filepath, 'w+') as f1:
					[f1.write(f'{result[0]}\n') for result in results]
					r.console.print(f'Results written to: {f1.name}')


	elif os.path.basename(configfile) == 'metasploit.ini':
		# Args - droptable
		if args.drop:
			db.drop_table('Metasploiter')
		# Sqlite - database init.
		db.create_table_metasploiter()
		# ConfigParser - declare dict values.
		MSFMODULES = {k: v for k, v in config['msfmodules'].items()}
		# Metasploiter - version check.
		version = version_check('Metasploit', \
			metasploiter.Metasploiter.get_version(), msf_stablever)
		print('\n')
		
		for k, v in MSFMODULES.items():
			if args.inputlist:
				# Metasploiter - instance init.
				metasploit = metasploiter.Metasploiter(k, v, args.inputlist)
			else:
				# Sqlite - fetch targets by metasploiter port(v) and write to flatfile.
				create_targetfile(v, targetfilepath)
				# Metasploiter - instance init.
				metasploit = metasploiter.Metasploiter(k, v, targetfilepath)

			# Metasploiter - print cmd and launch scan. 
			print(metasploit.cmd)
			r.console.print(f'[grey37]{os.path.basename(k.upper())}')
			with r.console.status(spinner='bouncingBar', status=f'[status.text]Scanning {os.path.basename(k.upper())}') as status:
				results = metasploit.run_scan()
				
				# Regex - ipv4 pattern
				pattern = re.compile('''((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)''')
				# Regex -  find all matches for ipv4 addresses in metasploiter results.
				all_matches = re.finditer(pattern, results)
				# Sqlite - insert metasploiter results (match.group():ipaddress, k:msfmodule)
				for match in all_matches:
					db.insert_metasploiter(match.group(), os.path.basename(k))
					# Print metasploiter results to stdout.
					r.console.print(f'{match.group()}[red] VULNERABLE')
				print('\n')
			r.console.print('[bold gold3]All scans have completed!\n')
		
		# Sqlite - write database results to outputfile.
		for k, v in MSFMODULES.items():
			filepath = os.path.join(findings_dir, f'{os.path.basename(k)}.txt')
			results = db.get_ipaddress_by_msfmodule(os.path.basename(k))
			if results != []:
				logging.info(f'Found results in databse.db via msfmodule: {os.path.basename(k)}')
				with open(filepath, 'w+') as f1:
					[f1.write(f'{result[0]}\n') for result in results]
					r.console.print(f'Results written to: {f1.name}')


	elif os.path.basename(configfile) == 'nmap.ini':
		# Args - droptable
		if args.drop:
			db.drop_table('Nmapper')
		# Sqlite - databse init.
		db.create_table_nmapper()
		# ConfigParser - declare dict values.
		#NMCONFIG = {k: v for k, v in config['nmapconfig'].items()}
		NSESCANS = {k: v for k, v in config['nsescans'].items()}
		# Nmapper - version check.
		version = version_check('Nmapper', \
			nmapper.Nmapper.get_version(), nm_stablever)
		print('\n')
		
		for k, v in NSESCANS.items():
			# XmlParse - define xml outputfileapth.
			xmlfile = os.path.join(xml_dir, f'{k}.xml')
			
			if args.inputlist:
				# Nmapper - instance init and run scan.
				nm = nmapper.Nmapper(k, v, args.inputlist, xmlfile)
			else:
				# Sqlite - fetch targets by metasploiter port(v) and write to flatfile.
				create_targetfile(v, targetfilepath)
				# Nmapper - instance init and run scan.
				nm = nmapper.Nmapper(k, v, targetfilepath, xmlfile)

			# Nmapper - print cmd to stdout.
			print(nm.cmd)
			# Nmapper - launch scam.
			r.console.print(f'[grey37]{k.upper()}')
			with r.console.status(spinner='bouncingBar', status=f'[status.text]Scanning {k.upper()}') as status:
				nm.run_scan()
			
				# XmlParse - instance init, read xmlfile and return results to database.
				xmlparse = xmlparser.NseParser()
				xmlresults = xmlparse.run(xmlfile)
				# DEV - need to omit positive reults from database insert. currently all results are logged.
				invalidlst = ['Message signing enabled and required', 'required']
				# Sqlite - insert xmlfile results (i[0]:ipaddress, i[2]:nsescript, i[1]:nseoutput).
				[print(i) for i in xmlresults] if i is not [for invalid in invalidlst]
				exit()
				db.insert_nmapper(x[0], x[2], x[1]) 
				exit()
				# Omit positive results and print to stdout.
				for i in xmlresults:
					if i[1] != 'Message signing enabled and required' and i[1] != 'required':
						# Print nse-scan results to stdout.
						r.console.print(f'{i[0]} [red]{i[1].upper()}')
				print('\n')
		r.console.print('[bold gold3]All scans have completed!\n')

		# Sqlite - write database results to outputfile.
		for k, v in NSESCANS.items():
			filepath = os.path.join(findings_dir, f'{k}.txt')
			results = db.get_ipaddress_by_nsescript(k)
			if results != []:
				logging.info(f'Found results in databse.db via nsescript: {k}')
				with open(filepath, 'w+') as f1:
					[f1.write(f'{result[0]}\n') for result in results]
					r.console.print(f'Results written to: {f1.name}')


if __name__ == '__main__':
	main()
