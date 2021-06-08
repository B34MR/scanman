#!/usr/bin/env python

import logging
import subprocess


class Metasploiter:
	''' Metasploit class wrapper '''

	# MFS version cmd.
	version_cmd = f'msfconsole -v'

	
	def __init__(self, msfmodule, rport, rhostfile):
		''' '''
		self.msfmodule = msfmodule
		self.rport = rport
		self.rhostfile = rhostfile
		self.precmd =  f'msfconsole -n -q -x'
		self.modulecmd =  f"use {self.msfmodule}; set RPORT {self.rport}; set RHOST file:{self.rhostfile}; grep '[+]' run; exit"
		self.cmd = f'{self.precmd} "{self.modulecmd}"'


	def get_version(self):
		'''Return Metasploit version:str '''
		
		cmdlst = self.version_cmd.split(' ')

		try:
			proc = subprocess.run(cmdlst,
				shell=False,
				check=True,
				capture_output=True,
				text=True
				)
		except Exception as e:
			# Set check=True for the exception to catch.
			logging.exception(e)
			raise e
		else:
			# Debug print only.
			logging.info(f'STDOUT:\n{proc.stdout}')
			logging.debug(f'STDERR:\n{proc.stderr}')

			return proc.stderr.split(' ')[2]


	def run_scan(self):
		''' Launch Metasploit scan via subprocess wrapper '''

		# DEV - reconfig class attributes.
		# Metasploit cmd.
		cmdlst = self.precmd.split(' ')
		cmdlst.append(self.modulecmd)

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

			return proc.stdout