#!/usr/bin/env python3

import subprocess
import logging


class Nmapper():
	''' Nmap base class wrapper '''

	# def __init__(self, inputlist):
	# 	self.inputlist = inputlist


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


	def run_scan(self, nse_script, ports, targets, xmlfile):
		''' 
		Scanner
		arg(s)description:str, ports:lst/str

		'''
		# DEV
		# Scrub ports from any potential user input error.
		parsed_ports = self.parse_ports(ports)

		# Nmap command.
		cmd = f"nmap --script {nse_script} -p {parsed_ports} -Pn {targets} -oX {xmlfile}"
		# DEV - print.
		print(f'\nCommand: {cmd}')
		cmd = cmd.split(' ')

		try:
			proc = subprocess.run(cmd, 
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

