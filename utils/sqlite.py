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


# Masscanner
def create_table_masscanner():
	''' Create table Masscanner '''

	try:
		with conn:
			c.execute("""CREATE TABLE Masscanner(
				IPAddress text,
				Port text,
				Protocol text,
				Description text
				)""")
	except sqlite3.OperationalError:
		pass


# Masscanner
def insert_masscanner(ipaddress, port, protocol, description):
	''' Insert result [(IP Address, Port, Protocol, Description)] '''
	
	with conn:
		c.execute("INSERT INTO Masscanner VALUES (:ipaddress, :port, :protocol, :description)",
		 {'ipaddress': ipaddress, 'port': port, 'protocol':protocol, 'description': description})


# Masscanner
def get_ipaddress_by_port(port):
	''' Get IP Address by filtering the port value.'''

	c.execute("SELECT * FROM Masscanner WHERE port=:port", {'port': port})
	
	return c.fetchall()


# Masscanner
def get_ipaddress_by_description(description):
	''' Get IP Address by filtering the description value.'''

	c.execute("SELECT * FROM Masscanner WHERE description=:description", {'description': description})
	
	return c.fetchall()


# Metasploiter
def create_table_metasploiter():
	''' Create table Nmapper '''

	try:
		with conn:
			c.execute("""CREATE TABLE Metasploiter(
				IPAddress text,
				MSFModule text
				)""")
	except sqlite3.OperationalError:
		pass


# Metasploiter
def insert_metasploiter(ipaddress, msfmodule):
	''' Insert result [(ipaddress, msfmodule)] '''
	
	with conn:
		c.execute("INSERT INTO Metasploiter VALUES (:ipaddress, :msfmodule)",
		 {'ipaddress': ipaddress, 'msfmodule': msfmodule})


# Metasploiter
def get_ipaddress_by_msfmodule(msfmodule):
	''' Get IP Address by filtering the msfmodule value.'''

	c.execute("SELECT * FROM Metasploiter WHERE msfmodule=:msfmodule", {'msfmodule': msfmodule})
	
	return c.fetchall()


# Nmapper
def create_table_nmapper():
	''' Create table Nmapper '''

	try:
		with conn:
			c.execute("""CREATE TABLE Nmapper(
				IPAddress text,
				NSEScript text,
				NSESResult text
				)""")
	except sqlite3.OperationalError:
		pass


# Nmapper
def insert_nmapper(ipaddress, nsescript, nseresult):
	''' Insert result [(ipaddress, nsescript, nseresult)] '''
	
	with conn:
		c.execute("INSERT INTO Nmapper VALUES (:ipaddress, :nsescript, :nseresult)",
		 {'ipaddress': ipaddress, 'nsescript': nsescript, 'nseresult': nseresult})


# Nmapper
def get_ipaddress_by_nsescript(nsescript):
	''' Get IP Address by filtering the nsescript value.'''

	c.execute("SELECT * FROM Nmapper WHERE nsescript=:nsescript", {'nsescript': nsescript})
	
	return c.fetchall()


def drop_table(tablename):
	''' Drop table '''
	
	try:
		with conn:
			c.execute(f"DROP TABLE {tablename}")
	except sqlite3.OperationalError as e:
		pass