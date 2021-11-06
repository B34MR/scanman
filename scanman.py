#!/usr/bin/env python3

from utils import arguments
from utils import ewrapper
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


# Config filepath.
scanman_config = './configs/config.ini'

# Scanman - directories and filepaths.
scanman_filepath = __file__
scanman_dir = os.path.dirname(__file__)

# Relative directories and filepaths.
MAIN_DIR = 'results'
TMP_DIR = os.path.join(MAIN_DIR, '.tmp')
ew_dir = os.path.join(MAIN_DIR, 'eyewitness')
masscan_dir = os.path.join(MAIN_DIR, 'masscan')
metasploit_dir = os.path.join(MAIN_DIR, 'metasploit')
nmap_dir = os.path.join(MAIN_DIR, 'nmap')
xml_dir = os.path.join(TMP_DIR, 'xml')

# Absolute directories and filepaths.
ew_xml_filepath = os.path.join(scanman_dir, xml_dir, 'eyewitness.xml')

# Nmap / Metasploit temp target/inputlist filepath.
targetfilepath = os.path.join(TMP_DIR, 'targets.txt')

# Create output dirs.
directories = [ew_dir, masscan_dir, metasploit_dir, nmap_dir, xml_dir]
dirs = [mkdir.mkdir(directory) for directory in directories]
[logging.info(f'Created directory: {d}') for d in dirs if d is not None]

# Argparse - init and parse.
args = arguments.parser.parse_args()

# ConfigParser - init and defined instance options.
config = ConfigParser(allow_no_value=True, delimiters='=')
config.optionxform = str

# Stable versions.
mass_stablever = '1.3.2'
msf_stablever = '6.1.8'
nmap_stablever = '7.91'

# Application versions.
masscan_ver = masscanner.Masscanner.get_version()
msf_ver = metasploiter.Metasploiter.get_version()
nmap_ver = nmapper.Nmapper.get_version()

# Application filepaths.
masscan_filepath = masscanner.Masscanner.get_filepath()
msf_filepath = metasploiter.Metasploiter.get_filepath()
nmap_filepath = nmapper.Nmapper.get_filepath()


def group_kwargs(group_title):
	'''
	Argparser func.
	Return arguments:dict for a specific "Argparse Group". 
	arg(s) group_title:str '''

	for group in arguments.parser._action_groups:
	  if group.title == group_title:
	    group_dict = {a.dest: getattr(args, a.dest, None) for a in group._group_actions}
	    kwargs = vars(arguments.argparse.Namespace(**group_dict))
	    logging.info(f'\n{group.title.upper()}:\n{kwargs}')

	    return kwargs


def remove_key(dictionary, key):
	''' 
	Argparser func.
	Remove dictionary key if value is None.
	arg(s) dictionary:dict, key:str '''

	if dictionary[key] is None:
		try:
		  	value = dictionary.pop(key, None)
		except Exception as e:
			raise e
		else:
			logging.info(f'REMOVED ARGUMENT: "{key}: {value}"')

# DEV - not currently used.
def heading_table(masscan_ver, msf_ver,nmap_ver,\
 	masscan_filepath, msf_filepath, nmap_filepath):
	''' '''
	# Variables - title
	title = f'\n[i grey37] Scanman v1.0'

	# Title 
	r.console.print(title)
	r.console.rule(style='rulecolor')

	# Table, toggle "#" to enable Table/Table.grid.
	table = r.Table.grid()
	# table = Table()

	# Columns - column headings are hidden in grid view.
	table.add_column("Software", justify="left", style="cyan", no_wrap=True)
	table.add_column("Version", justify="left", style="magenta", no_wrap=True)
	table.add_column("Filepath", justify="left", style="green", no_wrap=True)

	# Rows
	# table.add_row(" Eyewitness ", " NA ", " /opt/Eyewitness/Python ")
	table.add_row(" Masscan ", f" {masscan_ver} ", f" {masscan_filepath} ")
	table.add_row(" Metasploit ", f" {msf_ver} ", f" {msf_filepath} ")
	table.add_row(" Nmap ", f" {nmap_ver} ", f" {nmap_filepath} ")

	r.console.print(table)
	r.console.rule(style='rulecolor')


def create_targetfile(port, targetfilepath):
	'''
	Fetch target ipaddresses from db by filtering the port 
	then write results to a flatfile.
	arg(s)port:str, targetfilepath:str '''
	
	# Write targets to temp outputfile (targets are overwritten on each loop).
	with open(targetfilepath, 'w+') as f1:
		# Sqlite - fetch targets by filtering the port.
		[f1.write(f'{i}\n') for i in db.get_ipaddress_by_port(port)]
		logging.info(f'Targets written to: {f1.name}')


def remove_ansi(string):
	'''
	Remove ANSI escape sequences from a string.
	arg(s):string:str'''
	
	reaesc = re.compile(r'\x1b[^m]*m')
	new_string = reaesc.sub('', string)
	
	return new_string


def write_results(file_ext, directory, dictionary, dbquery):
	''' 
	Write database results to a flatfile. 
	arg(s)file_ext:str, dictionary:dict, directory:str, dbquery:funcobj '''

	for k, v in dictionary.items():
		filepath = os.path.join(directory, f'{os.path.basename(k)}.{file_ext}')
		results = dbquery(os.path.basename(k))
		if results != [] and results != set():
			# Debug - print.
			# print(results)
			logging.info(f'Found results in databse.db:')
			with open(filepath, 'w+') as f1:
				[f1.write(f'{result}\n') for result in results]
				r.console.print(f'Results written to: {f1.name}')


def sort_ipaddress(filepath):
	''' 
	Sort and unique IP addresses from a file.
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


def main():
	''' Main Func '''

	# Argparse - group titles.
	group1_title = 'Masscan Arguments'
	group2_title = 'Scanman Arguments'
	group3_title = 'Eyewitness Arguments'
	# Argparse - return args for a specific "Argparse Group".
	kwargs = group_kwargs(group1_title)	
	# Argparse - remove 'excludefile' k,v if value is None.
	remove_key(kwargs, '--excludefile')

	# ConfigParser - clear config cache and read newconfig file.
	config.clear()
	config.read(scanman_config)

	# Masscan - main mode.
	# Args - droptable
	if args.droptable:
		db.drop_table('Masscan')
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

		# Masscanner - init, print and run scan.
		ms = masscanner.Masscanner(key, value, **kwargs)
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
			print('\n')
	r.console.print('All Masscans have completed!', style="scanresult")
		
	# Sqlite - write db results to file.
	write_results('txt', masscan_dir, \
		MASSCAN_PORTSCANS, db.get_ipaddress_and_port_by_description)
	if args.parse_ip:
		write_results('ip', masscan_dir, \
			MASSCAN_PORTSCANS, db.get_ipaddress_by_description)
	print('\n')

	# Metasploit - optional mode.
	if args.msf:		
		# Args - droptable
		if args.droptable:
			db.drop_table('Metasploit')
		# Sqlite - database init.
		db.create_table_metasploit()

		# Heading1
		r.console.print(f'Metasploit {msf_ver} {msf_filepath}', style='appheading')
		r.console.rule(style='rulecolor')

		# ConfigParser - declare dict values.
		MSF_MODULES = {k: v for k, v in config['msf-modules'].items()}
		
		for k, v in MSF_MODULES.items():
			# Skip 'msfmodule scan' if port does not exists in database.
			targetlst = db.get_ipaddress_by_port(v)
			if not targetlst:
				pass
				r.console.print(f'{os.path.basename(k.upper())}', style='scancolor')
				r.console.print(f'No Targets found for port: {v}', style='notarget')
				r.console.print(f'Skipped', style='skipcolor')
				print('\n')
			else:
				# Sqlite - fetch targets by metasploit port(v) and write to flatfile.
				create_targetfile(v, targetfilepath)
				# Metasploit- instance init.
				metasploit = metasploiter.Metasploiter(k, v, targetfilepath)

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
					print('\n')

		r.console.print('All Metasploit scans have completed!', style='scanresult')
		# Sqlite - write database results to file.
		write_results('txt', metasploit_dir, \
			MSF_MODULES, db.get_result_by_msf_vulncheck)
		# Args - parse-ip
		if args.parse_ip:
			write_results('ip', metasploit_dir, \
				MSF_MODULES, db.get_ipaddress_by_msf_vulncheck)
		print('\n')

	# Nmap - optional mode.
	if args.nmap:
		# Args - droptable
		if args.droptable:
			db.drop_table('Nmap')
		# Sqlite - databse init.
		db.create_table_nmap()

		# Heading1
		r.console.print(f'Nmap {nmap_ver} {nmap_filepath}', style='appheading')
		r.console.rule(style='rulecolor')

		# ConfigParser - declare dict values.
		NMAP_SCRIPTS = {k: v for k, v in config['nmap-scripts'].items()}
		
		for k, v in NMAP_SCRIPTS.items():
			# XmlParse - define xml outputfileapth.
			xmlfile = os.path.join(xml_dir, f'{k}.xml')
			# Skip 'msfmodule scan' if port does not exists in database.
			targetlst = db.get_ipaddress_by_port(v)
			if not targetlst:
				pass
				r.console.print(f'{k.upper()}', style='scancolor')
				r.console.print(f'No Targets found for port: {v}', style='notarget')
				r.console.print(f'Skipped', style='skipcolor')
				print('\n')
			else:
				# Sqlite - fetch targets by nmap port(v) and write to flatfile.
				create_targetfile(v, targetfilepath)
				# Nmapper - instance init and run scan.
				nm = nmapper.Nmapper(k, v, targetfilepath, xmlfile)

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
						print(f'{e}')
						r.console.print(f'[orange_red1]WARNING: XMLParser failed, vulncheck skipped.')
					else:
						# Omit positive results and print to stdout.
						for i in xmlresults:
							if i[1] != None \
							and i[1] != 'Message signing enabled and required' \
							and i[1] != 'required':
								# Sqlite - insert xmlfile results (i[0]:ipaddress, i[2]:vulncheck, i[1]:result). 
								db.insert_nmap(i[0], i[2], i[1])
								# Print nse-scan results to stdout.
								r.console.print(f'{i[0]} [red]{i[1].upper()}')
								count += 1
					r.console.print(f'Instances {count}', style='instances')
					print('\n')

		r.console.print('All Nmap scans have completed!', style='scanresult')
		# Sqlite - write database results to file.
		write_results('txt', nmap_dir, \
			NMAP_SCRIPTS, db.get_ipaddress_and_result_by_nse_vulncheck)
		# Args - parse-ip
		if args.parse_ip:
			write_results('ip', nmap_dir, \
				NMAP_SCRIPTS, db.get_ipaddress_by_nse_vulncheck)
		print('\n')

	
	# EyeWitness - optional mode.
	if args.eyewitness:
		# Args - ew_report.
		if args.ew_report:
			ew_report_dir = args.ew_report
		else:
			ew_report_dir = os.path.join(scanman_dir, ew_dir)

		# Heading1
		r.console.print(f'Eyewitness', style='appheading')
		r.console.rule(style='rulecolor')

		# ConfigParser - declare eyewitness filepath.
		ew_filepath = config['eyewitness-setup']['filepath']
		ew_wrkdir = os.path.dirname(ew_filepath)
		# ConfigParser - declare eyewitness ports.
		ew_ports = config['eyewitness-setup']['portscans']	
		# ConfigParser - declare eyewitness args.
		ew_args = []
		for k, v in config['eyewitness-args'].items():
			ew_args.append(k) if v == None else ew_args.append(' '.join([k, v]))
		# Eyewitness Args - append XML input file and output directory args.
		ew_args.append(f'-x {ew_xml_filepath}')
		ew_args.append(f'-d {ew_report_dir}')

		# Masscanner - init, print and run scan.
		
		# Masscanner - add new 'oX' k, v pair.
		kwargs['-oX'] = ew_xml_filepath
		ms_ew = masscanner.Masscanner('Eyewitness Scans', ew_ports, **kwargs)
		# Masscanner - print cmd and run scan.
		r.console.print(f'[grey37]EYEWITNESS-PORTSCAN')
		print(f'{ms_ew.cmd}')
		with r.console.status(spinner='bouncingBar', status=f'[status.text]EYEWITNESS-PORTSCAN') as status:
			ms_ew.run_scan()
		print('\n')

		# Eyewitness - print cmd and launch scan.
		ew = ewrapper.Ewrapper(ew_filepath, ew_args)
		r.console.print(f'[grey37]EYEWITNESS.PY')
		print(f'{ew.cmd}')
		with r.console.status(spinner='bouncingBar', status=f'[status.text]EYEWITNESS.PY') as status:
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


if __name__ == '__main__':
	main()
