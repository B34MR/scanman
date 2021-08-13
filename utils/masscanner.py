#!/usr/bin/env python3

import subprocess
import logging


class Masscanner:
	''' Masscan class wrapper '''

	# Masscan version cmd.
	version_cmd = 'masscan --version'

	
	def __init__(self, description, ports, **kwargs):
		''' Init arg(s)description:str, ports:lst/str '''
		
		self.description = description
		self.ports = self.scrub_ports(ports)
		self.kwargs = ' '.join([f'{k} {v}' for k, v in kwargs.items()])
		self.cmd = \
		f'masscan -p {self.ports} {self.kwargs}'


	@classmethod
	def get_version(cls):
		''' Return Masscan version:str'''
		
		# Masscan version cmd.
		cmdlst = cls.version_cmd.split(' ')
		
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
		# Debug print only.
		logging.debug(f'STDOUT_LIST:{stdoutlst}')
		# Parse out port(s) and IP address(es) from stdoutlst.
		parsed_stdout = []
		for i in range(3, len(stdoutlst), 6):
			port = stdoutlst[i].split('/')[0]
			protocol = stdoutlst[i].split('/')[1]
			ipaddress = stdoutlst[i+2]
			parsed_stdout.append((ipaddress, port, protocol, self.description))

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
			# Parse stdout, return list.
			parsed_results = self.parse_stdout(proc.stdout)
			logging.debug(f'PARSED_RESULTS:{parsed_results}')
				
			return parsed_results
