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

MSCONFIG = {k: v for k, v in config['masscanconfig'].items()}
PORTSCANS = {k: v for k, v in config['portscan'].items()}


class Masscanner():
	''' '''

	def __init__(self, interface, rate):
		self.interface = interface
		self.rate = rate
		self.targets = None


	def read_targets(self, targets):
		''' '''
		pass


	def parse_ports(self, ports):
		''' '''
		
		# Convert lst to strgs.
		portsstr = ''.join(ports)
		# Remove white-space between ports and convert lst to str.
		parsed_ports = str(portsstr.replace(' ','') )

		return parsed_ports


	def parse_stdout(self, stdout):
		''' '''

		stdout = stdout.split()
		# Clean '' and '\n' from stdout.
		stdoutlst = [i for i in stdout if i != '' and i != '\n']
		# Parse out port(s) and IP address(es) from stdoutlst.
		parsed_stdout = {stdoutlst[i+2]: stdoutlst[i].split('/') for i in range(3, len(stdoutlst), 6)}

		return parsed_stdout


	def scan(self, description, ports):
		''' '''

		parsed_ports = self.parse_ports(ports)

		cmd = f'masscan --interface {self.interface} --rate {self.rate} -p {parsed_ports} {self.targets}'
		print(cmd)
		cmd = cmd.split(' ')

		proc = subprocess.run(cmd, 
			shell=False,
			check=False,
			capture_output=True,
			text=True)
		# Parse stdout, return dict.
		parsed_stdout = self.parse_stdout(proc.stdout)
		# Append description to dict v:lst
		[parsed_stdout[k].append(description) for k in parsed_stdout]
			
		return parsed_stdout


# Create table
db.create_table()
# Init Masscanner.
masscanner = Masscanner(MSCONFIG['interface'], MSCONFIG['rate'])
# Set targets.
masscanner.targets = '192.168.3.1/24'
# Launch scan(s).
for k, v in PORTSCANS.items():
	results = masscanner.scan(k, v)
	for k, v in results.items():
		# Insert results into database k:ipaddress, v[0]:port, v[1]:protocol, v[2]:description.
		db.insert_result(k, v[0], v[1], v[2])
		print(k, v[0], v[1], v[2])