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
			c.execute("""CREATE TABLE Services(
				Description text,
				Port text,
				IP Address text
				)""")
	except sqlite3.OperationalError:
		pass


def drop_table():
	''' Drop table "Services" '''
	
	try:
		with conn:
			c.execute(f"DROP TABLE Services")
	except sqlite3.OperationalError as e:
		pass


def insert_result(description, port, ipaddress):
	''' Insert result [(IP, Port, Protocol)] '''
	
	with conn:
		c.execute("INSERT INTO Services VALUES (:description, :port, :ipaddress)",
		 {'description': description, 'port': port, 'ipaddress': ipaddress})
