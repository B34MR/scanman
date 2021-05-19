#!/usr/bin/env python3

from utils import sqlite as db
from configparser import ConfigParser
# import os
import subprocess
# import sys

configfile = 'utils/config.ini'
config = ConfigParser(delimiters='=')
config.optionxform = str
config.read(configfile)

[print(k) for k in config['masscanconfig'].items()]
[print(k) for k in config['ports'].items()]


class Masscanner():
	''' '''

	def __init__(self, rate, ports, targets):
		self.rate = rate
		self.ports = ports
		self.targets = targets

	def read_ports(self, ports):
		''' '''
		pass
	

	def read_targets(self, targets):
		''' '''
		pass

	def scan(self):
		''' '''
		cmd = f'masscan -p {self.ports} {self.targets} --rate {self.rate}'
		cmd = cmd.split(' ')
		print(cmd)

		result = subprocess.run(cmd, 
			shell=False,
			check=False,
			capture_output=True,
			text=True)
		# print(result.stdout)

		scanresults = result.stdout.split(' ')

		print(scanresults)
		# myresults = [r for r in results]

		# print(myresults[3], myresults[5])
		db.insert_result('smb', scanresults[3], scanresults[5])

		# print(result.stderr)



db.create_table()
masscanner = Masscanner('100', '445', '192.168.3.1/24')
masscanner.scan()
# masscanner = Masscanner('100', '80', '192.168.3.1/24')
# masscanner.scan()
# masscanner = Masscanner('100', '443', '192.168.3.1/24')
# masscanner.scan()