#!/usr/bin/env python3

import subprocess
import logging


class Masscanner:
	''' Masscan class wrapper '''

	# Masscan version cmd.
	version_cmd = 'masscan --version'

	def __init__(self, interface, rate, description, ports, inputlist):
		''' Init arg(s)interface:str, rate:str, description:str, ports:lst/str, inputlist:str '''
		self.interface = interface
		self.rate = rate
		self.description = description
		self.ports = self.scrub_ports(ports)
		self.inputlist = inputlist
		self.cmd = \
		f'masscan --interface {self.interface} --rate {self.rate} -iL {self.inputlist} -p {self.ports}'


	def get_version(self):
		''' Return Masscan version:str'''
		
		# Masscan version cmd.
		cmdlst = self.version_cmd.split(' ')
		
		try:
			proc = subprocess.run(cmdlst,
				shell=False,
				check=False,
				capture_output=True,
				text=True)
		except Exception as e:
			# Set check=True for the exception to catch.
			logging.exception(e)
			raise e
		else:
			# Debug print only.
			logging.info(f'STDOUT:\n{proc.stdout}')
			logging.debug(f'STDERR:\n{proc.stderr}')
		
		return proc.stdout.split(' ')[2]

	
	def scrub_ports(self, ports):
		''' 
		Scrub ports convert lst to str(if needed), remove any whitespaces
		arg(s)ports:lst/str '''
		
		# Convert lst to str.
		portsstr = ''.join(ports)
		# Remove white-space between ports and convert lst to str.
		scrubbed_ports = str(portsstr.replace(' ','') )

		return scrubbed_ports


	def parse_stdout(self, stdout):
		''' 
		Scrub stdout for processing 
		arg(s)stdout:str '''

		stdout = stdout.split()
		# Clean '' and '\n' from stdout.
		stdoutlst = [i for i in stdout if i != '' and i != '\n']
		# Parse out port(s) and IP address(es) from stdoutlst.
		parsed_stdout = {stdoutlst[i+2]: stdoutlst[i].split('/') for i in range(3, len(stdoutlst), 6)}

		return parsed_stdout


	def run_scan(self):
		''' Launch Masscan via subprocess wrapper '''

		# Masscan command.
		cmdlst = self.cmd.split(' ')

		try:
			proc = subprocess.run(cmdlst, 
				shell=False,
				check=False,
				capture_output=True,
				text=True)
		except Exception as e:
			# Set check=True for the exception to catch.
			logging.exception(e)
			pass
		else:
			# Debug print only.
			logging.info(f'STDOUT:\n{proc.stdout}')
			logging.debug(f'STDERR:\n{proc.stderr}')
			# Parse stdout, return dict.
			results = self.parse_stdout(proc.stdout)
			# Append description to dict v:lst
			[results[k].append(self.description) for k in results]
			logging.debug(f'RESULTS:{results}')
				
			return results
