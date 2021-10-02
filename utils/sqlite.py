#!/usr/bin/env python3

import sqlite3
from utils import arguments

# Argparse - init and parse.
args = arguments.parser.parse_args()
if args.database:
	database_file = args.database
else:
	database_file = './database.db'

# Database init.
conn = sqlite3.connect(database_file)
c = conn.cursor()


# Masscan
def create_table_masscan():
	''' Create table masscan '''

	try:
		with conn:
			c.execute("""CREATE TABLE Masscan(
				ipaddress text,
				port text,
				protocol text,
				description text
				)""")
	except sqlite3.OperationalError:
		pass


# Masscan
def insert_masscan(ipaddress, port, protocol, description):
	''' Insert result [(IP Address, Port, Protocol, Description)] '''
	
	with conn:
		c.execute("INSERT INTO masscan VALUES (:ipaddress, :port, :protocol, :description)",
		 {'ipaddress': ipaddress, 'port': port, 'protocol':protocol, 'description': description})


# Masscan
def get_ipaddress_by_port(port):
	''' Get IP Address by filtering the port value.'''

	c.execute("SELECT * FROM masscan WHERE port=:port", {'port': port})
	
	return c.fetchall()


# Masscan
def get_ipaddress_by_description(description):
	''' Get IP Address by filtering the description value.'''

	c.execute("SELECT * FROM masscan WHERE description=:description", {'description': description})
	
	return c.fetchall()


# Metasploit
def create_table_metasploit():
	''' Create table Metasploit '''

	try:
		with conn:
			c.execute("""CREATE TABLE Metasploit(
				ipaddress text,
				vulncheck text,
				result text
				)""")
	except sqlite3.OperationalError:
		pass


# Metasploit
def insert_metasploit(ipaddress, vulncheck, result):
	''' Insert result [(ipaddress, vulncheck, result)] '''
	
	with conn:
		c.execute("INSERT INTO metasploit VALUES (:ipaddress, :vulncheck, :result)",
		 {'ipaddress': ipaddress, 'vulncheck': vulncheck, 'result': result})


# Metasploit
def get_ipaddress_by_msf_vulncheck(vulncheck):
	''' Get IP Address by filtering the vulncheck value.'''

	c.execute("SELECT * FROM metasploit WHERE vulncheck=:vulncheck", {'vulncheck': vulncheck})
	
	return c.fetchall()


# Nmap
def create_table_nmap():
	''' Create table Nmap '''

	try:
		with conn:
			c.execute("""CREATE TABLE Nmap(
				ipaddress text,
				vulncheck text,
				result text
				)""")
	except sqlite3.OperationalError:
		pass


# Nmap
def insert_nmap(ipaddress, vulncheck, result):
	''' Insert result [(ipaddress, vulncheck, result)] '''
	
	with conn:
		c.execute("INSERT INTO nmap VALUES (:ipaddress, :vulncheck, :result)",
		 {'ipaddress': ipaddress, 'vulncheck': vulncheck, 'result': result})


# Nmap
def get_ipaddress_by_nse_vulncheck(vulncheck):
	''' Get IP Address by filtering the vulncheck value.'''

	c.execute("SELECT * FROM nmap WHERE vulncheck=:vulncheck", {'vulncheck': vulncheck})
	
	return c.fetchall()


def drop_table(tablename):
	''' Drop table '''
	
	try:
		with conn:
			c.execute(f"DROP TABLE {tablename}")
	except sqlite3.OperationalError as e:
		pass