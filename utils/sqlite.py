#!/usr/bin/env python3

import sqlite3

# Database init.
conn = sqlite3.connect('../../database.db')

# Database cursor.
c = conn.cursor()


def create_table():
	''' Create table "Services" '''

	try:
		with conn:
			c.execute("""CREATE TABLE NetworkServices(
				IPAddress text,
				Port text,
				Protocol text,
				Description text
				)""")
	except sqlite3.OperationalError:
		pass


def drop_table():
	''' Drop table "Services" '''
	
	try:
		with conn:
			c.execute(f"DROP TABLE NetworkServices")
	except sqlite3.OperationalError as e:
		pass


def insert_result(ipaddress, port, protocol, description,):
	''' Insert result [(IP Address, Port, Protocol, Description)] '''
	
	with conn:
		c.execute("INSERT INTO NetworkServices VALUES (:ipaddress, :port, :protocol, :description)",
		 {'ipaddress': ipaddress, 'port': port, 'protocol':protocol, 'description': description})
