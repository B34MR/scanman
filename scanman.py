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
import time


# Stable versions.
ms_stablever = '1.3.2'
msf_stablever = '6.0.52'
nmap_stablever = '7.91'

# Config file dirs.
# DEV - use masscan_config var.
masscan_config = './configs/masscan.ini'
msf_config = './configs/metasploit.ini'
nmap_config = './configs/nmap.ini'

# Outputfile dirs.
MAIN_DIR = './outputfiles'
findings_dir = os.path.join(MAIN_DIR, 'findings')
portscans_dir = os.path.join(MAIN_DIR, 'portscans')
xml_dir = os.path.join(MAIN_DIR, 'xml')

# Nmap / Metasploit temp target/inputlist filepath.
targetfilepath = os.path.join(MAIN_DIR, 'targets.txt')

# Banner - main header.
# r.banner('Scanman'.upper())
print('\n')

# Create output dirs.
directories = [portscans_dir, findings_dir, xml_dir]
dirs = [mkdir.mkdir(directory) for directory in directories]
[logging.info(f'Created directory: {d}') for d in dirs if d is not None]


def version_check(mystr, currentver, stablever):
	''' 
	Returns if app version is supported or not to stdout. 
	arg(s):mystr:str, currentver:str, stablever:str '''

	if currentver == stablever:
		r.console.print(f'[i grey37]{mystr} {currentver}')
	else:
		r.console.print(f'[red][!] Warning[i] using {mystr} {currentver}')


def print_config(config, dictionary):
	'''Print config info '''

	r.console.print(f'Reading config file: {config}')
	r.console.print(f'Loading scans...')
	[(time.sleep(.2), r.console.print(f':arrow_right_hook: [grey37]{k.upper()}:[grey58]{v}'))\
		for k, v in dictionary.items()]
	r.console.print(f':+1: [gold3]Scans loaded!')


def create_targetfile(port, targetfilepath):
	'''
	Fetch target ipaddresses from db by filtering the port 
	then write results to a flatfile.
	arg(s)port:str, targetfilepath:str '''
	
	# DEV - support multiple ports.
	# Sqlite - fetch targets by filtering the port.
	results = [i[0] for i in db.get_ipaddress_by_port(port)]
	# Write targets to temp outputfile (targets are overwritten on each loop).
	with open(targetfilepath, 'w+') as f1:
		[f1.write(f'{i}\n') for i in results]
		logging.info(f'Targets written to: {f1.name}')


def write_results(dictionary, directory, dbquery):
	''' 
	Write database results to a flatfile. 
	arg(s)dictionary:dict, directory:str, dbquery:funcobj '''

	for k, v in dictionary.items():
		filepath = os.path.join(directory, f'{os.path.basename(k)}.txt')
		results = dbquery(os.path.basename(k))
		if results != []:
			logging.info(f'Found results in databse.db:')
			with open(filepath, 'w+') as f1:
				[f1.write(f'{result[0]}\n') for result in results]
				r.console.print(f'Results written to: {f1.name}')


def sort_ipaddress(filepath):
	''' 
	Sort and unique IP addresses from a file.
	arg(s)filepath:str '''
	
	# Read file and gather IP addresses.
	with open(filepath, 'r') as f1:
		ipaddr_lst = [line.strip() for line in f1]
		ipaddr_set = set(ipaddr_lst)
	# Write file with sorted and unique ip addresses. 
	with open(filepath, 'w+') as f2:
		for ip in sorted(ipaddr_set, key = lambda ip: [int(ip) for ip in ip.split(".")] ):
			f2.write(f'{ip}\n')


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
	
	# DEV - fix args
	# Masscanner - enable mode.
	if os.path.basename(configfile) == 'masscan.ini':
		# Read config file.
		config.read(configfile)
		# Args - droptable
		if args.droptable:
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
		r.console.rule(style='grey37')
		# Masscanner - print config information.
		print_config(masscan_config, PORTSCANS)
		print('\n')

		# Masscanner - instance int and run scan.
		for key, value in PORTSCANS.items():
			ms = masscanner.Masscanner(interface, rate, key, value, ms_targetfile)
			# Masscanner - print cmd and launch scan. 
			print(ms.cmd)		
			with r.console.status(spinner='bouncingBar', status=f'[status.text]Scanning {key.upper()}') as status:
				count = 0
				results = ms.run_scan()
				r.console.print(f'[grey37]{key.upper()}')
				# Sqlite - insert results (i[0]:ipaddress, i[1]:port, i[2]:protocol, i[3]:description).
				for i in results:
					db.insert_masscanner(i[0], i[1], i[2], i[3])
					r.console.print(f'{i[0]}:{i[1]}')
					count += 1
				r.console.print(f'[bold gold3]Instances {count}')
				print('\n')
		r.console.print('[bold gold3]All Masscans have completed!')
		
		# Sqlite - write db results to file.
		write_results(PORTSCANS, portscans_dir, db.get_ipaddress_by_description)
		print('\n')

	# Metasploiter - enable mode.
	if args.msf:
		# ConfigParser - read config file.
		config.read(msf_config)
		# Args - droptable
		if args.droptable:
			db.drop_table('Metasploiter')
		# Sqlite - database init.
		db.create_table_metasploiter()
		# ConfigParser - declare dict values.
		MSFMODULES = {k: v for k, v in config['msfmodules'].items()}
		# Metasploiter - version check.
		version = version_check('Metasploit', \
			metasploiter.Metasploiter.get_version(), msf_stablever)
		r.console.rule(style='grey37')
		# Metasploiter - print config information.
		print_config(msf_config, MSFMODULES)
		print('\n')
		
		for k, v in MSFMODULES.items():

			# DEV - fix inputlist for msf.
			# if args.inputlist:
			# 	# Metasploiter - instance init.
			# 	metasploit = metasploiter.Metasploiter(k, v, args.inputlist)
			# else:
			# 	# Sqlite - fetch targets by metasploiter port(v) and write to flatfile.
			# 	create_targetfile(v, targetfilepath)
			# 	# Metasploiter - instance init.
			# 	metasploit = metasploiter.Metasploiter(k, v, targetfilepath)

			# Skip 'msfmodule scan' if port does not exists in database.
			targetlst = db.get_ipaddress_by_port(v)
			if not targetlst:
				pass
				r.console.print(f'No Targets found for port: {v}\
				 \n[grey37]{k.upper()}\n[gold3]Skipped')
				print('\n')
			else:
				# Sqlite - fetch targets by metasploiter port(v) and write to flatfile.
				create_targetfile(v, targetfilepath)
				# Metasploiter - instance init.
				metasploit = metasploiter.Metasploiter(k, v, targetfilepath)

				# Metasploiter - print cmd and launch scan. 
				print(metasploit.cmd)
				with r.console.status(spinner='bouncingBar', status=f'[status.text]Scanning {os.path.basename(k.upper())}') as status:
					count = 0
					results = metasploit.run_scan()
					r.console.print(f'[grey37]{os.path.basename(k.upper())}')
					
					# Regex - ipv4 pattern
					pattern = re.compile('''((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)''')
					# Regex -  find all matches for ipv4 addresses in metasploiter results.
					all_matches = re.finditer(pattern, results)
					# Sqlite - insert metasploiter results (match.group():ipaddress, k:msfmodule)
					for match in all_matches:
						db.insert_metasploiter(match.group(), os.path.basename(k))
						# Print metasploiter results to stdout.
						r.console.print(f'{match.group()}[red] VULNERABLE')
						count += 1
					r.console.print(f'[bold gold3]Instances {count}')
					print('\n')

		r.console.print('[bold gold3]All Metasploit scans have completed!')	
		# Sqlite - write database results to file.
		write_results(MSFMODULES, findings_dir, db.get_ipaddress_by_msfmodule)
		print('\n')

	# Nmapper - enable mode.
	if args.nmap:
		# ConfigParser - read config file.
		config.read(nmap_config)
		# Args - droptable
		if args.droptable:
			db.drop_table('Nmapper')
		# Sqlite - databse init.
		db.create_table_nmapper()
		# ConfigParser - declare dict values.
		# Dev - add feature for Nmap interface.
		#NMCONFIG = {k: v for k, v in config['nmapconfig'].items()}
		NSESCRIPTS = {k: v for k, v in config['nsescripts'].items()}
		# Nmapper - version check.
		version = version_check('Nmap', \
			nmapper.Nmapper.get_version(), nmap_stablever)
		r.console.rule(style='grey37')
		# Metasploiter - print config information.
		print_config(nmap_config, NSESCRIPTS)
		print('\n')
		
		for k, v in NSESCRIPTS.items():
			# XmlParse - define xml outputfileapth.
			xmlfile = os.path.join(xml_dir, f'{k}.xml')
			# DEV - fix inputlist for nmap.
			# if args.inputlist:
			# 	# Nmapper - instance init and run scan.
			# 	nm = nmapper.Nmapper(k, v, args.inputlist, xmlfile)
			# else:
			# 	# Sqlite - fetch targets by nmapper port(v) and write to flatfile.
			# 	create_targetfile(v, targetfilepath)
			# 	# Nmapper - instance init and run scan.
			# 	nm = nmapper.Nmapper(k, v, targetfilepath, xmlfile)

			# Skip 'msfmodule scan' if port does not exists in database.
			targetlst = db.get_ipaddress_by_port(v)
			if not targetlst:
				pass
				r.console.print(f'No Targets found for port: {v}\
				 \n[grey37]{k.upper()}\n[gold3]Skipped')
				print('\n')
			else:
				# Sqlite - fetch targets by nmapper port(v) and write to flatfile.
				create_targetfile(v, targetfilepath)
				# Nmapper - instance init and run scan.
				nm = nmapper.Nmapper(k, v, targetfilepath, xmlfile)

				# Nmapper - print cmd and launch scan. 
				print(nm.cmd)
				with r.console.status(spinner='bouncingBar', status=f'[status.text]Scanning {k.upper()}') as status:
					count = 0
					nm.run_scan()
					r.console.print(f'[grey37]{k.upper()}')
				
					# XmlParse - instance init, read xmlfile and return results to database.
					xmlparse = xmlparser.NseParser()
					xmlresults = xmlparse.run(xmlfile)
					# Omit positive results and print to stdout.
					for i in xmlresults:
						if i[1] != None \
						and i[1] != 'Message signing enabled and required' \
						and i[1] != 'required':
							# Sqlite - insert xmlfile results (i[0]:ipaddress, i[2]:nsescript, i[1]:nseoutput). 
							db.insert_nmapper(i[0], i[2], i[1])
							# Print nse-scan results to stdout.
							r.console.print(f'{i[0]} [red]{i[1].upper()}')
							count += 1
					r.console.print(f'[bold gold3]Instances {count}')
					print('\n')

		r.console.print('[bold gold3]All Nmap scans have completed!')
		# Sqlite - write db results to file.
		write_results(NSESCRIPTS, findings_dir, db.get_ipaddress_by_nsescript)
		print('\n')
	
	# Sort / unique ip addresses from files in the 'portscan' dir.
	for file in os.listdir(portscans_dir):
		sort_ipaddress(os.path.join(portscans_dir, file))
	# Sort / unique ip addresses from files in the 'findings' dir.
	for file in os.listdir(findings_dir):
		sort_ipaddress(os.path.join(findings_dir, file))


if __name__ == '__main__':
	main()
