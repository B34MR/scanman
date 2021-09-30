#!/usr/bin/env python3

import subprocess
import logging


class Nmapper:
	''' Nmap base class wrapper '''
	
	# Nmap version cmd.
	filepath_cmd = 'which nmap'
	version_cmd = 'nmap -version'

	
	def __init__(self, nsescript, ports, inputlist, xmlfile):
		''' Init arg(s)nsescript:str, ports:lst/str, inputlist:str, xmlfile:str '''
		
		self.nsescript = nsescript
		self.ports = self.scrub_ports(ports)
		self.inputlist = inputlist
		self.xmlfile = xmlfile
		self.cmd = \
		f"nmap -Pn --script {self.nsescript} -p {self.ports} -iL {self.inputlist} -oX {self.xmlfile}"


	@classmethod
	def get_filepath(cls):
		''' Return Nmap filepath:str'''
		
		# Nmap Version cmd.
		cmdlst = cls.filepath_cmd.split(' ')
		
		try:
			proc = subprocess.run(cmdlst,
				shell=False,
				check=True,
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
		
		return proc.stdout.strip()

	
	@classmethod
	def get_version(cls):
		''' Return Nmap version:str'''
		
		# Nmap Version cmd.
		cmdlst = cls.version_cmd.split(' ')
		
		try:
			proc = subprocess.run(cmdlst,
				shell=False,
				check=True,
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


	def run_scan(self):
		''' Launch Nmap scan via subprocess wrapper.'''
		
		# Nmap command.
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

	
