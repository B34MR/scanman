#!/usr/bin/env python3

from utils import arguments
from utils import dbmanager
from utils import ewrapper
from utils import getdc
from utils import metasploiter
from utils import masscanner
from utils import mkdir
from utils import nmapper
# from utils import nullsession
from utils import richard as r
from utils import rpcdumpper
from utils import sqlite as db
from utils import xmlparser
from utils import zerologon
from configparser import ConfigParser
import os
import sys
import re
import logging
import time


# Config filepath.
scanman_config = './configs/config.ini'

# Scanman - directories and filepaths.
scanman_filepath = __file__
scanman_dir = os.path.dirname(__file__)

# Relative directories and filepaths.
MAIN_DIR = 'results'
TMP_DIR = os.path.join(MAIN_DIR, '.tmp')
VULN_DIR = os.path.join(MAIN_DIR, 'vuln')
DC_DIR = os.path.join(MAIN_DIR, 'dc')
# Subdirs for MAIN_DIR/TMP.
web_dir = os.path.join(MAIN_DIR, 'web')
xml_dir = os.path.join(TMP_DIR, 'xml')
# Subddirs for DC_DIR.
enum_dir = os.path.join(DC_DIR, 'enum')
mspar_msrprn_dir = os.path.join(DC_DIR, 'mspar_msrprn')
smbsign_dir = os.path.join(DC_DIR, 'smbsign')
zerologon_dir = os.path.join(DC_DIR, 'zerologon')
# Subddirs for VULN_DIR.
egress_dir = os.path.join(VULN_DIR, 'egress')
masscan_dir = os.path.join(VULN_DIR, 'masscan')
metasploit_dir = os.path.join(VULN_DIR, 'metasploit')
nmap_dir = os.path.join(VULN_DIR, 'nmap')

# Webscan vars / absolute directories and filepaths.
webscan_desc_key = 'http'
web_target_fp = os.path.join(scanman_dir, web_dir, f'{webscan_desc_key}.txt')

# Nmap / Metasploit temp target/inputlist filepath.
targetfilepath = os.path.join(TMP_DIR, 'targets.txt')

# Create output dirs.
directories = [
	egress_dir,
	enum_dir,
	masscan_dir,
	metasploit_dir,
	mspar_msrprn_dir,
	nmap_dir,
	smbsign_dir,
	web_dir,
	xml_dir,
	zerologon_dir
]

dirs = [mkdir.mkdir(directory) for directory in directories]
[logging.info(f'Created directory: {d}') for d in dirs if d is not None]

# ConfigParser - init and defined instance options.
config = ConfigParser(allow_no_value=True, delimiters='=')
config.optionxform = str

# Application versions.
masscan_ver = masscanner.Masscanner.get_version()
msf_ver = metasploiter.Metasploiter.get_version()
nmap_ver = nmapper.Nmapper.get_version()

# Application filepaths.
masscan_filepath = masscanner.Masscanner.get_filepath()
msf_filepath = metasploiter.Metasploiter.get_filepath()
nmap_filepath = nmapper.Nmapper.get_filepath()

# Egress - ports to print via STDOUT.
egress_portlst = [
'21', '22', '23', '25', '53', '69', '80', '123', '135', 
'137', '138', '139', '161', '162', '443', '445', '514', 
'3389', '6660', '6661', '6662', '6663', '6664', '6665', 
'6666', '6667', '6668', '6669'
]


# DEV - may move to arguments.py
def remove_key(dictionary, key):
	''' Argparser func.
	Remove dictionary key if value is None.
	arg(s) dictionary:dict, key:str '''

	if dictionary[key] is None:
		try:
			value = dictionary.pop(key, None)
		except Exception as e:
			raise e
		else:
			logging.info(f'REMOVED ARGUMENT: "{key}: {value}"')


def create_targetfile(port, targetfilepath):
	''' Fetch target ipaddresses from db by filtering the port 
	then write results to a flatfile.
	arg(s)port:str, targetfilepath:str '''
	
	# Write targets to temp outputfile (targets are overwritten on each loop).
	with open(targetfilepath, 'w+') as f1:
		# Sqlite - fetch targets by filtering the port.
		[f1.write(f'{i}\n') for i in db.get_ipaddress_by_port(port)]
		logging.info(f'Targets written to: {f1.name}')


def keyboard_interrupt():
	''' Menu and stdout for Ctrl-C '''

	r.console.print(f'\nCtrl-C detected, the current scan was skipped.')
	option = input('(Q)uit / [ENTER] to proceed with next scan: ')
	if option.upper() == '':
		r.console.print(f'\n')
		pass
	elif option.upper() == 'Q':
		r.console.print(':v: Peace')
		sys.exit(0)


def remove_ansi(string):
	''' Remove ANSI escape sequences from a string.
	arg(s):string:str'''
	
	reaesc = re.compile(r'\x1b[^m]*m')
	new_string = reaesc.sub('', string)
	
	return new_string


def write_results(file_ext, directory, dictionary, dbquery):
	''' Write database results to a flatfile. 
	arg(s)file_ext:str, dictionary:dict, directory:str, dbquery:funcobj '''

	for k, v in dictionary.items():
		filepath = os.path.join(directory, f'{os.path.basename(k)}.{file_ext}')
		results = dbquery(os.path.basename(k))
		if results != [] and results != set():
			# Debug - print.
			# print(results)
			with open(filepath, 'w+') as f1:
				[f1.write(f'{result}\n') for result in results]
				r.console.print(f'Results from db written to: {f1.name}')


def write_set_results(filename, results):
	''' Write database results type:set to a flatfile. 
	arg(s)filename:str, results:set '''

	if results != [] and results != set():
		# print(results)
		with open(filename, 'w+') as f1:
			[f1.write(f'{result}\n') for result in results]
		# Print successful completion.
		r.console.print(f'Results from db written to: {f1.name}')


def sort_ipaddress(filepath):
	''' Sort and unique IP addresses from a file.
	arg(s)filepath:str '''
	
	# Patch < - fixed issue after introducing .stdout file extensions.
	filename, file_ext = os.path.splitext(filepath)
	if file_ext == '.ip': 
		# Patch />.		
		# Read file and gather IP addresses.
		with open(filepath, 'r') as f1:
			ipaddr_lst = [line.strip() for line in f1]
			ipaddr_set = set(ipaddr_lst)
		# Write file with sorted and unique ip addresses. 
		with open(filepath, 'w+') as f2:
			for ip in sorted(ipaddr_set, key = lambda ip: [int(ip) for ip in ip.split(".")] ):
				f2.write(f'{ip}\n')


def sort_alphabetical(filepath):
	''' Sort files alphabetically from a file.
	arg(s)filepath:str '''
	
	# Patch < - fixed issue after introducing .stdout file extensions.
	filename, file_ext = os.path.splitext(filepath)
	if file_ext == '.fqdn' \
	or file_ext == '.fqdnip'\
	or file_ext == '.zerologon': 
		# Patch />.		
		# Read file and gather IP addresses.
		with open(filepath, 'r') as f1:
			lines = [line for line in f1]
		# Write file with alphabetically sorted and #DEV - 'unique' data. 
		with open(filepath, 'w+') as f2:
			for line in sorted(lines):
				f2.write(f'{line}')


def main():
	''' Main Func '''

	# Argparse - init and parse.
	args = arguments.parser.parse_args()

	# Argparse - return args for the specific "Argparse Group".
	masscan_kwargs = arguments.group_kwargs('Masscan Arguments')
	# Argparse - remove 'excludefile' k,v if value is None.
	remove_key(masscan_kwargs, '--excludefile')

	# ConfigParser - clear config cache and read newconfig file.
	config.clear()
	config.read(scanman_config)

	# Args - droptables
	if args.droptables:
		dbmanager.menu_option_droptables()

	# Database-manager Menu.
	dbmanager.menu()

	# MODE - DC.
	if args.subparser == 'A':
		# Sqlite - database init.
		db.create_table_domaincontroller()
		# ConfigParser - declare dict values.
		DC_VULNSCANS = {k: v for k, v in config['dc-vulnscans'].items()}
		vulnscan_lst = [k[0] for k in DC_VULNSCANS.items()]
		# Targets - vars.
		targetlst = []
		targets_ip = os.path.join(DC_DIR, 'temp.ip')
		# Targets - ZEROLOGON.
		if args.zerologonlist:
			zerologon_target_fp = args.zerologonlist
			with open(zerologon_target_fp, 'r') as f1:
				lines = [line.strip() for line in f1]
				# print(lines)
			for line in lines:
				hostname, ipaddress = line.split()
				targetlst.append([hostname.rstrip('$'), ipaddress])
			# Targets - parse IPs from zerologon inputlist and write to flat file.
			lines =  [i[1] for i in targetlst]
			with open(targets_ip, 'w+') as f1:
			 	for line in lines:
			 		f1.write(f'{line}\n')
		# Targets - INPUTLIST.
		if args.inputlist:
			inputlist_target_fp = args.inputlist
			with open(inputlist_target_fp, 'r') as f1:
				targetlst = [line.strip() for line in f1]
			print(targetlst)

		# Getdc - option.
		if args.domain:
			# Heading1
			print('\n')
			r.console.print(f'GetDomainController', style='appheading')
			r.console.rule(style='rulecolor')
			# Hostname dictionary
			host_dct = {
			}
			# DNS query for domain controllers and populate 'host_dct' with results.
			for domain in args.domain:
				try:
					with r.console.status(spinner='bouncingBar', status=f'[status.text]{domain.upper()}') as status:
						# initiate nested dict(s) from args.domain
						host_dct[domain] = {}
						# call query(srv) to find dc hostname
						answer_srv = getdc.query(domain, service='_kerberos.', protocol='_tcp.',\
							recordtype='SRV', nameserver=args.nameserver)			
						for hostname in answer_srv:
							# populate host_dct with hostname.
							host_dct[domain][str(hostname)] = ''
							 # call query(a) to find dc ipaddress
							answer_a = getdc.query(hostname, service='', protocol='',\
								recordtype='A', nameserver=args.nameserver)
							# convert list to string
							ipaddress = '\n'.join(answer_a)
							# populate host_dct with ipaddress
							host_dct[domain][str(hostname)] = ipaddress
				except KeyboardInterrupt:
					keyboard_interrupt()
			# Read results from 'host_dct', populate database.
			count = 0
			for domain in host_dct.keys():
				r.console.print(f'[grey37]{domain.upper()}')
				for k, v in host_dct[domain].items():
					hostname = k.split(".")[0]
					db.insert_domaincontroller(domain.lower(), k.lower(), hostname.lower(), v, vulncheck='', result='')
					# Print results.
					r.console.print(f'{k} {v}')
					count +=1
				# Print number of instances via counter.
				r.console.print(f'Instances {count}', style='instances')
				# Counter, reset for nested dct items.
				count = 0
				r.console.print(f'Updated database table: {db.database_file}.DomainController\n', style='instances')
			# Print successful scan completion.
			r.console.print('All scans have completed!', style="scanresult")
			# Sqlite - write db results to file.
			write_results('fqdn', DC_DIR, host_dct, db.get_fqdn_by_domain)
			write_results('ip', DC_DIR, host_dct, db.get_ipaddress_by_domain)
			write_results('fqdnip', DC_DIR, host_dct, db.get_fqdn_and_ipaddress_by_domain)
			write_results('zerologon', DC_DIR, host_dct, db.get_hostname_and_ipaddress_by_domain)
			print('\n')

		# Nullsession - option.
		if 'nullsession' in vulnscan_lst:
			print('\n')
			r.console.print(f'Nullsession', style='appheading')
			r.console.rule(style='rulecolor')
		# SMB Signing - option.
		if 'smb2-security-mode' in vulnscan_lst:
			# Heading1
			print('\n')
			r.console.print(f'SMB Signing', style='appheading')
			r.console.rule(style='rulecolor')
			try:
				# XmlParse - define xml outputfileapth.
				xmlfile = os.path.join(xml_dir, f'{k}dc_smb.xml')
				# Nmapper - obj init.
				nm = nmapper.Nmapper('smb2-security-mode', '445', targets_ip, xmlfile)
				# Nmapper - print cmd and launch scan.
				with r.console.status(spinner='bouncingBar', status=f'[status.text]{ipaddress}') as status:
					nm.run_scan()
					# XmlParse - instance init, read xmlfile and return results to database.
					xmlparse = xmlparser.NseParser()
					xmlresults = xmlparse.run(xmlfile)
					# Omit None results and print to stdout.
					for i in xmlresults:
						if i[1] != None:
							# Sqlite - insert xmlfile results (i[0]:ipaddress, i[1]:nseoutput). 
							# db.update_smbv2_security(i[0], i[1])
							# Print nse-scan results to stdout.
							r.console.print(f'[grey58]{i[0]} [grey37]- {i[1].upper()}')
						else:
							print(i[0], i[1])
					print('\n')
			except KeyboardInterrupt:
				print(f'\nQuit: detected [CTRL-C]')
		# Print Services - option.
		if 'printservice' in vulnscan_lst:
			print('\n')
			r.console.print(f'Print Services', style='appheading')
			r.console.rule(style='rulecolor')

			# VARS.
			targetlst = []

			try:
				# Rpcdumpper - print cmd.
				# print(f"\n{rpcdumpper.Rpcdumpper('').cmd}ipaddress")
				# Heading 2 - scan type.
				r.console.print(f'[grey27]MS-PAR/MS-RPRN')

				# Printsrv - fetch targets from flatfile.
				fp = 'results/dc/infrared.local.zerologon'
				with open(fp, 'r') as f1:
					lines = [line.strip() for line in f1]
					# return lines
					for line in lines:
						hostname, ipaddress = line.split()
						targetlst.append([hostname.rstrip('$'), ipaddress])

				for target in targetlst:
					hostname, ipaddress = target
					# Rpcdumpper - init and launch scan.
					rpcdump = rpcdumpper.Rpcdumpper(ipaddress)
					with r.console.status(spinner='bouncingBar', status=f'[status.text]{hostname.upper()} {ipaddress}') as status:
						results = rpcdump.run_scan()
						# Rcpdumpper - Get results:bool and update database.
						is_mspar = rpcdump.is_substring(results, 'MS-PAR')
						is_msrprn = rpcdump.is_substring(results, 'MS-RPRN')
						# Sqlite - update table:zeroscan, column:print_services. 
						# db.update_MS_PAR(ipaddress, str(is_mspar))
						# db.update_MS_RPRN(ipaddress, str(is_msrprn))
					r.console.print(f'[grey58]{hostname.upper()} {ipaddress}[grey37] - MS-PAR: {is_mspar}, MS-RPRN: {is_msrprn}')
				print('\n')
			except KeyboardInterrupt as e:
				print(f'\nQuit: detected [CTRL-C]')
		# Zerologon - option.
		if 'zerologon' in vulnscan_lst:
			# DEV - implement version check.
			impacket_stablever = 'v0.9.23'
			# Banner
			print('\n')
			r.console.print(f'Zerologon / CVE-2020-1472', style='appheading')
			r.console.rule(style='rulecolor')
			try:
				# VARS.
				MAX_ATTEMPTS = 2000

				# if args.domain:
				# 	targetlst = []
				# 	# Sqlite - fetch targets from db.
				# 	targetlst = list(db.get_hostname_and_ipaddress())

				# Iterate over targets and unpack hostname and ip address.
				for target in targetlst:
					hostname, ipaddress = target
					# DEV, relocate sqlite insert statment.
					# Sqlite - insert target data.
					# db.insert_data(hostname.upper(), ipaddress, None, None, None, None)
				
					# Zerologon - init instance and launch authentication attack.
					zl = zerologon.ZeroLogon(ipaddress, hostname)
					with r.console.status(spinner='bouncingBar', status=f'[status.text]{hostname.upper()} {ipaddress}') as status:
						rpc_con_results = None
						# Counter - for authentication attempts.
						counter = 0
						for attempt in range(0, MAX_ATTEMPTS):
							rpc_con_results = zl.run()
							counter += 1
							if rpc_con_results != 0xc0000022:
								break

						# Print - authentication attempts.
						r.console.print(f'[grey58]{hostname.upper()} {ipaddress} [grey37] - AUTH-ATTEMPTS: {counter}')
						# if str(rpc_con_results) == '3221225506':
						# 	print('NOT VULNERABLE')
						# elif str(rpc_con_results) == 'impacket.dcerpc.v5.rpcrt.DCERPC_v5':
						# 	print('[red]VULNERABLE')
						
						# Print - Zerologn Results.
						print(hostname.upper(), ipaddress, str(rpc_con_results))
						# Sqlite - update vulncheck results.
						db.update_vulncheck(hostname.lower(), ipaddress, 'CVE-2020-1472', str(rpc_con_results))
						# db.insert_domaincontroller(domain, fqdn='', hostname, ipaddress, vulncheck='Zerologon', result=str(rpc_con_results))
					print('\n')
			except KeyboardInterrupt:
				print(f'\nQuit: detected [CTRL-C]')

	# MODE - VULN
	if args.subparser == 'B':
		# DEV - left from old model, needs fixing.
		if not masscan_kwargs['-iL'] is None:
			# Sqlite - database init.
			db.create_table_masscan()
			# Heading1
			print('\n')
			r.console.print(f'Masscan {masscan_ver} {masscan_filepath}', style='appheading')
			r.console.rule(style='rulecolor')
			# ConfigParser - declare dict values.
			MASSCAN_PORTSCANS = {k: v for k, v in config['masscan-portscans'].items()}
			# Masscan - instance int and run scan.
			for key, value in MASSCAN_PORTSCANS.items():
				try:
					# Masscanner - init, print and run scan.
					ms = masscanner.Masscanner(key, value, **masscan_kwargs)
					r.console.print(f'[grey37]{key.upper()}')
					print(ms.cmd)
					with r.console.status(spinner='bouncingBar', status=f'[status.text]{key.upper()}') as status:
						count = 0
						results = ms.run_scan()
						# Sqlite - insert results (i[0]:ipaddress, i[1]:port, i[2]:protocol, i[3]:description).
						for i in results:
							db.insert_masscan(i[0], i[1], i[2], i[3])
							r.console.print(f'{i[0]}:{i[1]}')
							count += 1
						r.console.print(f'Instances {count}', style='instances')
						r.console.print(f'Updated database table: {db.database_file}.Masscan', style='instances')
						print('\n')
				except KeyboardInterrupt:
					keyboard_interrupt()
			# Print successful scan completion.
			r.console.print('All Masscans have completed!', style="scanresult")
			# Sqlite - write db results to file.
			write_results('txt', masscan_dir, \
				MASSCAN_PORTSCANS, db.get_ipaddress_and_port_by_description)
			if args.parse_ip:
				write_results('ip', masscan_dir, \
					MASSCAN_PORTSCANS, db.get_ipaddress_by_description)
			print('\n')

		# Metasploit - option.
		if args.msf:
			# Sqlite - database init.
			db.create_table_metasploit()
			# Heading1
			r.console.print(f'Metasploit {msf_ver} {msf_filepath}', style='appheading')
			r.console.rule(style='rulecolor')
			# ConfigParser - declare dict values.
			MSF_VULNSCANS = {k: v for k, v in config['msf-vulnscans'].items()}
			for k, v in MSF_VULNSCANS.items():
				# Skip 'msfmodule scan' if port does not exists in database.
				targetlst = db.get_ipaddress_by_port(v)
				if not targetlst:
					pass
					r.console.print(f'{os.path.basename(k.upper())}', style='scancolor')
					r.console.print(f'No targets in db found with port: {v}', style='notarget')
					r.console.print(f'Skipped', style='skipcolor')
					print('\n')
				else:
					# Sqlite - fetch targets by metasploit port(v) and write to flatfile.
					create_targetfile(v, targetfilepath)
					# Metasploit- instance init.
					metasploit = metasploiter.Metasploiter(k, v, targetfilepath)
					try:
						# Metasploit - print cmd and launch scan.
						r.console.print(f'[grey37]{os.path.basename(k.upper())}')
						print(metasploit.cmd)
						with r.console.status(spinner='bouncingBar', status=f'[status.text]{os.path.basename(k.upper())}') as status:
							count = 0
							results = metasploit.run_scan()
							# Debug - print metasploit raw results
							# print(f'{results}')
							# Parse - save msf STDOUT to a file.
							results_noansi = remove_ansi(results)
							# Parse - replace/remove msf RPORT header.
							results_norport = results_noansi.replace(f'RPORT => {v}', '')
							# Parse - replace/remove msf RHOST header.
							results_norhost = results_norport.replace(f'RHOSTS => file:{targetfilepath}', '')
							# Parse - replace/remove the first two newlines.
							results_cleaned = results_norhost.replace(f'\n', '', 2)
							# Print - cleaned results to stdout.
							r.console.print(f'[red]{results_cleaned.rstrip()}')
							# Regex - ipv4 pattern
							pattern = re.compile('''((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)''')
							# Regex - convert each '\n' in 'results_cleaned' to a list indice.
							results_list = results_cleaned.rstrip().split('\n')
							# Regex -  find all matches for ipv4 addresses in each results_list indice.
							for i in results_list:
								all_matches = re.finditer(pattern, i)
								for match in all_matches:
									# Sqlite - insert metasploit results (match.group():ipaddress, k:vulncheck, i:result)
									db.insert_metasploit(match.group(), os.path.basename(k), i)
									count += 1
							r.console.print(f'Instances {count}', style='instances')
							r.console.print(f'Updated database table: {db.database_file}.Metasploit', style='instances')
							print('\n')
					except KeyboardInterrupt:
						keyboard_interrupt()
			# Print successful scan completion.
			r.console.print('All Metasploit scans have completed!', style='scanresult')
			# Sqlite - write database results to file.
			write_results('txt', metasploit_dir, \
				MSF_VULNSCANS, db.get_result_by_msf_vulncheck)
			# Args - parse-ip
			if args.parse_ip:
				write_results('ip', metasploit_dir, \
					MSF_VULNSCANS, db.get_ipaddress_by_msf_vulncheck)
			print('\n')

		# Nmap - option.
		if args.nmap:
			# Sqlite - databse init.
			db.create_table_nmap()
			# Heading1
			r.console.print(f'Nmap {nmap_ver} {nmap_filepath}', style='appheading')
			r.console.rule(style='rulecolor')
			# ConfigParser - declare dict values.
			NMAP_VULNSCANS = {k: v for k, v in config['nmap-vulnscans'].items()}
			for k, v in NMAP_VULNSCANS.items():
				# XmlParse - define xml outputfileapth.
				xmlfile = os.path.join(xml_dir, f'{k}.xml')
				# Skip 'nmap-script scan' if port does not exists in database.
				targetlst = db.get_ipaddress_by_port(v)
				if not targetlst:
					pass
					r.console.print(f'{k.upper()}', style='scancolor')
					r.console.print(f'No targets in db found with port: {v}', style='notarget')
					r.console.print(f'Skipped', style='skipcolor')
					print('\n')
				else:
					# Sqlite - fetch targets by nmap port(v) and write to flatfile.
					create_targetfile(v, targetfilepath)
					# Nmapper - instance init and run scan.
					nm = nmapper.Nmapper(k, v, targetfilepath, xmlfile)
					try:
						# Nmapper - print cmd and launch scan.
						r.console.print(f'[grey37]{k.upper()}')
						print(nm.cmd)
						with r.console.status(spinner='bouncingBar', status=f'[status.text]{k.upper()}') as status:
							count = 0
							nm.run_scan()
							# XmlParse - instance init.
							xmlparse = xmlparser.NseParser()
							# XmlParse - read xmlfile and return results to database.
							try:
								xmlresults = xmlparse.run(xmlfile)
							except Exception as e:
								pass
								logging.debug(f'ERROR: {e}')
								logging.warning(f'XMLParser failed, find vulnscan details in: {xmlfile}.')
							else:
								for i in xmlresults:
									# Omit None type and false positive results for SMB-Signing.
									if args.smbparse:
										if i[1] != None \
										and i[1] != 'Message signing enabled and required' \
										and i[1] != 'required' \
										and i[1] != 'supported':
											# Sqlite - insert xmlfile results (i[0]:ipaddress, i[2]:vulncheck, i[1]:result). 
											db.insert_nmap(i[0], i[2], i[1])
											# Print nse-scan results to stdout.
											r.console.print(f'{i[0]} [red]{i[1].upper()}')
											count += 1
									# Omit None type results from xmlresults.
									elif i[1] != None:
										# Sqlite - insert xmlfile results (i[0]:ipaddress, i[2]:vulncheck, i[1]:result). 
										db.insert_nmap(i[0], i[2], i[1])
										# Print nse-scan results to stdout.
										r.console.print(f'{i[0]} [red]{i[1].upper()}')
										count += 1
							r.console.print(f'Instances {count}', style='instances')
							r.console.print(f'Updated database table: {db.database_file}.Nmap', style='instances')
							print('\n')
					except KeyboardInterrupt:
						keyboard_interrupt()
			# Print successful scan completion.
			r.console.print('All Nmap scans have completed!', style='scanresult')
			# Sqlite - write database results to file.
			write_results('txt', nmap_dir, \
				NMAP_VULNSCANS, db.get_ipaddress_and_result_by_nse_vulncheck)
			# Args - parse-ip
			if args.parse_ip:
				write_results('ip', nmap_dir, \
					NMAP_VULNSCANS, db.get_ipaddress_by_nse_vulncheck)
			print('\n')

		# Egress - option.
		if  args.egressscan:
			# Heading1
			print('\n')
			r.console.print(f'Nmap {nmap_ver} {nmap_filepath}', style='appheading')
			r.console.rule(style='rulecolor')
			# ConfigParser - declare dict values.
			EGRESS_SCAN = {k: v for k, v in config['egressscan'].items()}
			egress_ports = EGRESS_SCAN['egress_ports']
			egress_target = EGRESS_SCAN['egress_target']
			# Egress - filepaths for XML, TXT and IP.
			xmlfile = f'{xml_dir}/egress.xml'
			egress_file_txt = f'{egress_dir}/egress.txt'
			egress_file_ip = f'{egress_dir}/egress.ip'
			# Egress - kwargs.
			nmap_oN = '-oN'
			egress_kwargs = {nmap_oN: egress_file_txt}
			# Egress - instance init and status print.
			nm_egress = nmapper.Egress(egress_ports, egress_target, xmlfile, **egress_kwargs)
			egress_desc = 'Egress-Scan'
			r.console.print(f'[grey37]{egress_desc.upper()}')
			print(nm_egress.cmd)
			try:
				# Egress - run.
				with r.console.status(spinner='bouncingBar', status=f'[status.text]{egress_desc.upper()}') as status:
					count = 0
					nm_egress.run_scan()
					# XmlParse - egressparser instance init.
					xmlparse = xmlparser.EgressParser()
					# XmlParse - read xmlfile and return results to database.
					try:
						xmlresults = xmlparse.run(xmlfile)
					except Exception as e:
						pass
						logging.debug(f'ERROR: {e}')
						logging.warning(f'XMLParser failed, find vulnscan details in: {xmlfile}.')
					else:
						for i in xmlresults:
							# Print ports from port_lst to STDOUT.
							for port in egress_portlst:
								if i[1] == port:
									if i[3] == 'open':
										r.console.print(f'[grey37]{i[0]} [white]{i[1]} {i[2].upper()} [red]{i[3].upper()}')
									else:
										r.console.print(f'[grey37]{i[0]} {i[1]} {i[2].upper()} {i[3].upper()}')
							if i[3] == 'open':
								count +=1
						# Print instances.
						r.console.print(f'\t[grey53]... Truncated ...')
					r.console.print(f'Instances {count}', style='instances')
					print('\n')
				# Print successful scan completion.
				r.console.print('All Nmap scans have completed!', style='scanresult')
				r.console.print(f'Results written to: {egress_file_txt}')
				# Args - parse-ip
				if args.parse_ip:
					with open(egress_file_ip, 'w+') as f1:
						[f1.write(f'{result[0]}, {result[1]}, {result[2]}\n') for result in xmlresults if result[3] == 'open']	
						r.console.print(f'Results written to: {f1.name}')
				print('\n')
			except KeyboardInterrupt:
				keyboard_interrupt()

	# MODE - WEB
	if args.subparser == 'C':
		# Args - ew_report.
		if args.ew_report:
			ew_report_dir = args.ew_report
			# Eyewitness - warn user the ew-report directory will overwrite all existing contents.
			try:
				if args.ew_report:
					print(f'\n')
					r.console.print(f'[orange_red1]:large_orange_diamond: WARNING :large_orange_diamond:')
					r.console.print(f'All Contents will be Overwritten: {args.ew_report}')
					input(f'[CTRL-C] to quit / [ENTER] to scan: ')
					print('\n')
			except KeyboardInterrupt:
				print(f'\nQuit: detected [CTRL-C] ')
				sys.exit(0)
		else:
			ew_report_dir = os.path.join(scanman_dir, web_dir)
		# Sqlite - database init.
		db.create_table_masscan()
		# Heading1
		print('\n')
		r.console.print(f'Webscan', style='appheading')
		r.console.rule(style='rulecolor')
		# ConfigParser - eyewitness filepath.
		ew_filepath = config['eyewitness-setup']['filepath']
		ew_wrkdir = os.path.dirname(ew_filepath)
		# ConfigParser - eyewitness ports.
		ew_ports = config['eyewitness-setup']['portscans']
		# Sqlite - check database for existing 'description' key Masscan records.
		is_record = db.is_record_masscan(webscan_desc_key)
		# WEB - target file path for web scanner.
		web_target_fp = os.path.join(web_dir, f'{os.path.basename(webscan_desc_key)}.txt')
		# Eyewitness args.
		ew_args = []
		for k, v in config['eyewitness-args'].items():
			ew_args.append(k) if v == None else ew_args.append(' '.join([k, v]))	
		# WEB - records do not exists, launch port scans.
		if is_record == False:
			r.console.print(f"[grey37]No '{webscan_desc_key}' targets from the db were found, launching port scan.\n")
			if masscan_kwargs['-iL'] is None:
				r.console.print(f'[grey37]Missing the "-iL" Targets argument.')
				r.console.print(':v: Peace')
				sys.exit(1)
			try:
				# Masscanner - init, print and run scan.
				ms = masscanner.Masscanner('http', ew_ports, **masscan_kwargs)
				r.console.print(f'[grey37]HTTP')
				print(ms.cmd)
				with r.console.status(spinner='bouncingBar', status=f'[status.text]HTTP') as status:
					count = 0
					results = ms.run_scan()
					# Sqlite - insert results (i[0]:ipaddress, i[1]:port, i[2]:protocol, i[3]:description).
					for i in results:
						db.insert_masscan(i[0], i[1], i[2], i[3])
						r.console.print(f'{i[0]}:{i[1]}')
						count += 1
					r.console.print(f'Instances {count}', style='instances')
					r.console.print(f'Updated database table: {db.database_file}.Masscan', style='instances')
			except KeyboardInterrupt:
				keyboard_interrupt()
			# Sqlite - fetch targets from db.
			results = db.get_ipaddress_and_port_by_description(webscan_desc_key)
			# Sqlite - write result to flat file.
			write_set_results(web_target_fp, results)
			print('\n')
		# WEB - records do exists, launch Eyewitness.
		if is_record == True:
			r.console.print(f"[grey37]Gathered '{webscan_desc_key}' targets from db for web scanning.")
			# Sqlite - fetch targets from db and write file.
			results = db.get_ipaddress_and_port_by_description(webscan_desc_key)
			# Sqlite - write result to flat file.
			write_set_results(web_target_fp, results)
			print('\n')
		# Eyewitness - print cmd and launch scan.
		ew_args.append(f'-f {web_target_fp}')
		ew_args.append(f'-d {ew_report_dir}')
		ew = ewrapper.Ewrapper(ew_filepath, ew_args)
		r.console.print(f'[grey37]EYEWITNESS')
		print(f'{ew.cmd}')
		with r.console.status(spinner='bouncingBar', status=f'[status.text]EYEWITNESS') as status:
			results = ew.run_scan()
			print(f'\n{results}')

	# Sort / unique ip addresses from files in the 'masscan' dir.	
	for file in os.listdir(masscan_dir):
		sort_ipaddress(os.path.join(masscan_dir, file))
	# Sort / unique ip addresses from files in the 'metasploit' dir.
	for file in os.listdir(metasploit_dir):
		sort_ipaddress(os.path.join(metasploit_dir, file))
	# Sort / unique ip addresses from files in the 'nmap' dir.
	for file in os.listdir(nmap_dir):
		sort_ipaddress(os.path.join(nmap_dir, file))
	# Sort / unique ip addresses from files in the 'dc' dir.
	for file in os.listdir(DC_DIR):
		sort_ipaddress(os.path.join(DC_DIR, file))
	# Sort data alphabetically from files in the 'dc' dir.
	for file in os.listdir(DC_DIR):
		sort_alphabetical(os.path.join(DC_DIR, file))


if __name__ == '__main__':
	main()
