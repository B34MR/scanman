#!/usr/bin/env python

import logging
import subprocess



def func():
	msfcmd = "use auxiliary/scanner/rdp/cve_2019_0708_bluekeep; set RHOST file:./outputfiles/portscans/rdp.txt; grep '[+]' check; exit"

	cmd = f'msfconsole -n -q -x'
	cmdlst = cmd.split(' ')
	cmdlst.append(msfcmd)

	print(f'{cmd} "{msfcmd}"')

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

test = func()
test