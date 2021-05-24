#!/usr/bin/env python3

import sqlite3

# Database init.
conn = sqlite3.connect('../../database.db')
# Database cursor.
c = conn.cursor()


# Masscanner
def create_table1():
	''' Create table 1 '''

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
def insert_result1(ipaddress, port, protocol, description):
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


# Nmapper
def create_table2():
	''' Create table 2 '''

	try:
		with conn:
			c.execute("""CREATE TABLE Nmapper(
				IPAddress text,
				Finding text,
				NSEScript text
				)""")
	except sqlite3.OperationalError:
		pass


# Nmapper
def insert_result2(ipaddress, finding, nsescript):
	''' Insert result [(IP Address, finding, nsename)] '''
	
	with conn:
		c.execute("INSERT INTO Nmapper VALUES (:ipaddress, :finding, :nsescript)",
		 {'ipaddress': ipaddress, 'finding': finding, 'nsescript': nsescript})


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