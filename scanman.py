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


# Stable versions.
mass_stablever = '1.3.2'
msf_stablever = '6.0.52'
nmap_stablever = '7.91'

# Config file dirs.
ew_config = './configs/eyewitness.ini'
masscan_config = './configs/masscan.ini'
msf_config = './configs/metasploit.ini'
nmap_config = './configs/nmap.ini'

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

# Print - aesthetic newline.
print('\n')

# Create output dirs.
directories = [ew_dir, masscan_dir, metasploit_dir, nmap_dir, xml_dir]
dirs = [mkdir.mkdir(directory) for directory in directories]
[logging.info(f'Created directory: {d}') for d in dirs if d is not None]

# Argparse - init and parse.
args = arguments.parser.parse_args()

# ConfigParser - init and defined instance options.
config = ConfigParser(allow_no_value=True, delimiters='=')
config.optionxform = str


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


def version_check(mystr, currentver, stablever):
	''' 
	Returns if app version is supported or not to stdout. 
	arg(s):mystr:str, currentver:str, stablever:str '''

	r.console.print(f'Checking version:[grey37] v{currentver}')
	if currentver == stablever:
		r.console.print(f':arrow_right_hook: [grey37]v{currentver} is supported.')
	else:
		r.console.print(f':arrow_right_hook: [orange_red1]Warning [grey53]v{currentver} is unsupported.')


def read_config(my_config):
	''' 
	ConfigParser func.
	Read and print config file.
	arg(s) my_config:str '''

	# Clear config cache and read newconfig file.
	config.clear()
	config.read(my_config)
	r.console.print(f'Reading config file: {my_config}')
	for dic in config.items():
		# Print dict key value pairs.
		for k, v in config[dic[0]].items():
			time.sleep(.2)
			r.console.print(f':arrow_right_hook: [grey37]{k.upper()}: [grey58]{v}')
	# r.console.print(f':+1: [gold3]Config loaded!')


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


def remove_ansi(string):
	'''
	Remove ANSI escape sequences from a string.
	arg(s):string:str'''
	
	reaesc = re.compile(r'\x1b[^m]*m')
	new_string = reaesc.sub('', string)
	
	return new_string



def write_results(dictionary, directory, dbquery):
	''' 
	Write database results to a flatfile. 
	arg(s)dictionary:dict, directory:str, dbquery:funcobj '''

	for k, v in dictionary.items():
		filepath = os.path.join(directory, f'{os.path.basename(k)}.ip')
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

	# Args - droptable
	if args.droptable:
		db.drop_table('Masscanner')
	# Sqlite - database init.
	db.create_table_masscanner()

	# Heading1
	mass_ver = masscanner.Masscanner.get_version()
	r.console.print(f'[i grey37]Masscan {mass_ver}')
	r.console.rule(style='grey37')
	# Masscanner - version check.
	version = version_check('Masscan', mass_ver, mass_stablever)
	
	# ConfigParser - read and print config.
	read_config(masscan_config)
	print('\n')
	# ConfigParser - declare dict values.
	PORTSCANS = {k: v for k, v in config['portscans'].items()}
	
	# Masscanner - instance int and run scan.
	for key, value in PORTSCANS.items():

		# Masscanner - init, print and run scan.
		ms = masscanner.Masscanner(key, value, **kwargs)
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
	write_results(PORTSCANS, masscan_dir, db.get_ipaddress_by_description)
	print('\n')

	# EyeWitness - optional mode.
	if args.eyewitness:

		# Args - ew_report.
		if args.ew_report:
			ew_report_dir = args.ew_report
		else:
			ew_report_dir = os.path.join(scanman_dir, ew_dir)

		# Heading1
		r.console.print(f'[i grey37]Eyewitness')
		r.console.rule(style='grey37')

		# ConfigParser - read and print config.
		read_config(ew_config)

		# ConfigParser - declare eyewitness filepath.
		ew_filepath = config['setup']['filepath']
		ew_wrkdir = os.path.dirname(ew_filepath)
		# ConfigParser - declare eyewitness ports.
		ew_ports = config['setup']['ports']	
		# ConfigParser - declare eyewitness args.
		ew_args = []
		for k, v in config['args'].items():
			ew_args.append(k) if v == None else ew_args.append(' '.join([k, v]))
		# Eyewitness Args - append XML input file and output directory args.
		ew_args.append(f'-x {ew_xml_filepath}')
		ew_args.append(f'-d {ew_report_dir}')

		# DEV - Masscanner - init, print and run scan.
		# Masscanner - add new 'oX' k, v pair.
		kwargs['-oX'] = ew_xml_filepath
		ms_ew = masscanner.Masscanner('Eyewitness Scans', ew_ports, **kwargs)

		# Masscanner - print cmd and run scan.
		r.console.print(f'\n[i grey37]Masscan Launched') 
		print(f'{ms_ew.cmd}')
		with r.console.status(spinner='bouncingBar', status=f'[status.text]Scanning Eyewitness Ports') as status:
			ms_ew.run_scan()

		# Eyewitness - change CWD for eyewitness to work properly.
		r.console.print(f'\n[i grey37]Eyewitness Launched')
		r.console.print(f':arrow_right_hook: CWD: {os.getcwd()}')
		os.chdir(ew_wrkdir)
		r.console.print(f':arrow_right_hook: CHDIR: {ew_wrkdir}')

		# Eyewitness - print cmd and launch scan.
		ew = ewrapper.Ewrapper(ew_filepath, ew_args)
		print(f'\n{ew.cmd}')

		# DEV - view current screen.
		try:
			input("Press Enter to continue...")
		except KeyboardInterrupt as e:
			print(e)
			# raise e
		else:
			ew.run_scan()

		# Return to scanman working dir.
		os.chdir(scanman_dir)

	# Metasploiter - optional mode.
	if args.msf:		
		# Args - droptable
		if args.droptable:
			db.drop_table('Metasploiter')
		# Sqlite - database init.
		db.create_table_metasploiter()

		# Heading1
		msf_ver = metasploiter.Metasploiter.get_version()
		r.console.print(f'[i grey37]Metasploit {msf_ver}')
		r.console.rule(style='grey37')
		# Metasploiter - version check.
		version = version_check('Metasploit', msf_ver, msf_stablever)
		# ConfigParser - read and print config.
		read_config(msf_config)
		print('\n')
		# ConfigParser - declare dict values.
		MSFMODULES = {k: v for k, v in config['msfmodules'].items()}
		
		for k, v in MSFMODULES.items():
			# Skip 'msfmodule scan' if port does not exists in database.
			targetlst = db.get_ipaddress_by_port(v)
			if not targetlst:
				pass
				r.console.print(f'No Targets found for port: {v}\
				 \n[grey37]{os.path.basename(k.upper())}\n[gold3]Skipped')
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

					# Dev - write stdout to a file.
					with open(f'{metasploit_dir}/{os.path.basename(k)}.stdout', 'a+') as f1:
						f1.write(f'{results_cleaned}\n')

					# Regex - ipv4 pattern
					pattern = re.compile('''((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)''')
					# Regex -  find all matches for ipv4 addresses in metasploiter results.
					all_matches = re.finditer(pattern, results)
					# Sqlite - insert metasploiter results (match.group():ipaddress, k:msfmodule)
					for match in all_matches:
						db.insert_metasploiter(match.group(), os.path.basename(k))
						count += 1
					r.console.print(f'[bold gold3]Instances {count}')
					print('\n')

		r.console.print('[bold gold3]All Metasploit scans have completed!')	
		# Sqlite - write database results to file.
		write_results(MSFMODULES, metasploit_dir, db.get_ipaddress_by_msfmodule)
		print('\n')

	# Nmapper - optional mode.
	if args.nmap:
		# Args - droptable
		if args.droptable:
			db.drop_table('Nmapper')
		# Sqlite - databse init.
		db.create_table_nmapper()

		# Heading1
		nmap_ver = nmapper.Nmapper.get_version()
		r.console.print(f'[i grey37]Nmap {nmap_ver}')
		r.console.rule(style='grey37')
		# Nmapper - version check.
		version = version_check('Nmap', nmap_ver, nmap_stablever)
		# ConfigParser - read and print config.
		read_config(nmap_config)
		print('\n')
		# ConfigParser - declare dict values.
		NSESCRIPTS = {k: v for k, v in config['nsescripts'].items()}
		
		for k, v in NSESCRIPTS.items():
			# XmlParse - define xml outputfileapth.
			xmlfile = os.path.join(xml_dir, f'{k}.xml')
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
						
						# DEV - save STDOUT to a file.
						with open(f'{nmap_dir}/{k}.stdout', 'a+') as f1:
							f1.write(f'{i[0]} {i[1].upper()}\n')
						
						# Omit positive results and print to stdout.
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
		write_results(NSESCRIPTS, nmap_dir, db.get_ipaddress_by_nsescript)
		print('\n')
	
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
