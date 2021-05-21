#!/usr/bin/env python3

from utils import arguments
from utils import masscanner as ms
from utils import richard as r
from utils import sqlite as db
from configparser import ConfigParser
import logging


def main():
	''' Main Func '''

	# Args - init.
	args = arguments.parse_args()

	# Args - configfile
	configfile = args.configfile

	# Args - droptable
	if args.drop:
		db.drop_table()

	# ConfigParser - read onfigfile.
	config = ConfigParser(delimiters='=')
	config.optionxform = str
	config.read(configfile)
	
	# ConfigParser - declare dict values.
	MSCONFIG = {k: v for k, v in config['masscanconfig'].items()}
	PORTSCANS = {k: v for k, v in config['portscan'].items()}

	# Sqlite - databse init.
	db.create_table()

	# Masscanner - instance init (interface, rate, targets:-iL).
	masscanner = ms.Masscanner(MSCONFIG['interface'], MSCONFIG['rate'], args.inputlist)
	
	# Masscanner - launch scan(s).
	for k, v in PORTSCANS.items():
		results = masscanner.run_scan(k, v)
		# Sqlite - insert results (k:ipaddress, v[0]:port, v[1]:protocol, v[2]:description).
		for k, v in results.items():
			db.insert_result(k, v[0], v[1], v[2])
			# Print results.
			print(k, v[0], v[1], v[2])


if __name__ == '__main__':
	main()
