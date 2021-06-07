#!/usr/bin/env python

import logging
import subprocess


class Metasploiter:
	''' '''

	def __init__(self, msfmodule, rhostfile):
		''' '''
		self.msfcmd =  f'msfconsole -n -q -x'
		self.modulecmd =  f"use {msfmodule}; set RHOST file:{rhostfile}; grep '[+]' check; exit"
		self.cmd = f'{self.msfcmd} "{self.modulecmd}"'


	def run_scan(self):
		''' '''
		
		cmdlst = self.msfcmd.split(' ')
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
			print(proc.stdout)
			print(proc.stderr)


def main():
	''' '''
	
	# Vars
	msfmodule = 'auxiliary/scanner/rdp/cve_2019_0708_bluekeep'
	rhostfile = './outputfiles/portscans/rdp.txt'

	# Metasploiter - instance init.
	metasploiter = Metasploiter(msfmodule, rhostfile)
	# Metasploiter - print cmd to stdout.
	print(metasploiter.cmd)
	# Metasploiter - launch scan.
	msfscan = metasploiter.run_scan()
	msfscan


if __name__ == '__main__':
	main()
