#!/usr/bin/env python3

import subprocess
import logging


class Nmapper():
	''' Nmap base class wrapper '''


	def parse_ports(self, ports):
		''' 
		Scrub ports convert lst to str(if needed), remove any whitespaces
		arg(s)ports:lst/str 
		'''
		# DEV
		p = ','.join(ports.split(',')).replace(' ','')
		parsed_ports = p.replace(',',', ')
		
		# # Convert lst to str.
		# portsstr = ''.join(ports)
		# # Remove white-space between ports and convert lst to str.
		# parsed_ports = str(portsstr.replace(' ','') )

		return parsed_ports


	def run_scan(self, nsescript, ports, inputlist, xmlfile):
		''' 
		Launch Nmap scan via wrapper.
		arg(s)nsescript:str, ports:lst/str, inputlist:str, xmlfile:str

		'''
		
		# DEV
		# Scrub ports from any potential user input error.
		parsed_ports = self.parse_ports(ports)

		# Nmap command.
		cmd = f"nmap -Pn --script {nsescript} -p {parsed_ports} -iL {inputlist} -oX {xmlfile}"
		# DEV - Print
		print(f'\n{cmd}')
		cmdlst = cmd.split(' ')

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
			logging.debug(f'STDOUT: {proc.stdout}')
			logging.debug(f'STDERR: {proc.stderr}')
			
			return cmd

