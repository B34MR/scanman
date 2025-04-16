#!/usr/bin/env python3

import sqlite3
from utils import arguments

# Argparse - init and parse.
args = arguments.parser.parse_args()
if args.database:
	database_file = args.database
else:
	database_file = './scanman.db'

# Database init.
conn = sqlite3.connect(database_file)
# Cursor init.
c = conn.cursor()
# Cursor results in datatype dict, default is tuple.
c.row_factory = sqlite3.Row



# DomainController
def create_table_domaincontroller():
	''' Create table domaincontroller '''

	try:
		with conn:
			c.execute("""CREATE TABLE DomainController(
				domain text,
				fqdn text,
				hostname text,
				ipaddress text,
				vulncheck text,
				result text
				)""")
	except sqlite3.OperationalError:
		pass

# DomainController
def insert_domaincontroller(domain, fqdn, hostname, ipaddress, vulncheck, result):
	''' Insert result [(Domain, FQDN, IPAddress, Vulncheck, Result)] '''
	
	with conn:
		c.execute("INSERT INTO domaincontroller VALUES (:domain, :fqdn, :hostname, :ipaddress, :vulncheck, :result)",
		 {'domain' :domain, 'fqdn' :fqdn, 'hostname':hostname, 'ipaddress' :ipaddress, 'vulncheck' :vulncheck, 'result': result})

# DomainController
def get_fqdn_by_domain(domain):
	''' Get hostname column by filtering the domain value.'''

	c.execute("SELECT fqdn FROM domaincontroller WHERE domain=:domain", {'domain': domain})
	
	return  {f"{dic['fqdn']}" for dic in c.fetchall()}

# DomainController
def get_ipaddress_by_domain(domain):
	''' Get ipaddress column by filtering the domain value.'''

	c.execute("SELECT ipaddress FROM domaincontroller WHERE domain=:domain", {'domain': domain})
	
	return  {f"{dic['ipaddress']}" for dic in c.fetchall()}

# DomainController
def get_fqdn_and_ipaddress_by_domain(domain):
	''' Get fqdn, ipaddress column by filtering the domain value.'''

	c.execute("SELECT fqdn, ipaddress FROM domaincontroller WHERE domain=:domain", {'domain': domain})
	
	return  {f"{dic['fqdn']} {dic['ipaddress']}" for dic in c.fetchall()}

# DomainController
def get_hostname_and_ipaddress_by_domain(domain):
	''' Get hostname, ipaddress column by filtering the domain value.'''

	c.execute("SELECT hostname, ipaddress FROM domaincontroller WHERE domain=:domain", {'domain': domain})
	
	return  {f"{dic['hostname']} {dic['ipaddress']}" for dic in c.fetchall()}

# DomainController
def get_domaincontroller_column(column):
	''' Get domaincontroller column.'''

	c.execute(f"SELECT {column} FROM domaincontroller")
	
	return  {f"{dic[column]}" for dic in c.fetchall()}


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
	''' Get ipaddress column by filtering the port value.'''

	c.execute("SELECT ipaddress FROM masscan WHERE port=:port", {'port': port})
	
	return  {f"{dic['ipaddress']}" for dic in c.fetchall()}

# Masscan
def get_ipaddress_and_port_by_description(description):
	''' Get ipaddress and port column by filtering the description value.'''

	c.execute("SELECT ipaddress, port FROM masscan WHERE description=:description", {'description': description})

	return {f"{dic['ipaddress']}:{dic['port']}" for dic in c.fetchall()}

# Masscan
def get_ipaddress_by_description(description):
	''' Get ipaddress column by filtering the description value.'''

	c.execute("SELECT ipaddress FROM masscan WHERE description=:description", {'description': description})
	
	return {f"{dic['ipaddress']}" for dic in c.fetchall()}


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
	''' Get ipaddress column by filtering the vulncheck value.'''

	c.execute("SELECT ipaddress FROM metasploit WHERE vulncheck=:vulncheck", {'vulncheck': vulncheck})
	
	return {f"{dic['ipaddress']}" for dic in c.fetchall()}

# Metasploit
def get_result_by_msf_vulncheck(vulncheck):
	''' Get result column by filtering the vulncheck value.'''

	c.execute("SELECT result FROM metasploit WHERE vulncheck=:vulncheck", {'vulncheck': vulncheck})
	
	return {f"{dic['result']}" for dic in c.fetchall()}


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
	''' Get ipaddress column by filtering the vulncheck value.'''

	c.execute("SELECT ipaddress FROM nmap WHERE vulncheck=:vulncheck", {'vulncheck': vulncheck})
	
	return {f"{dic['ipaddress']}" for dic in c.fetchall()}

# Nmap
def get_ipaddress_and_result_by_nse_vulncheck(vulncheck):
	''' Get ipaddress and result column by filtering the vulncheck value.'''

	c.execute("SELECT ipaddress, result FROM nmap WHERE vulncheck=:vulncheck", {'vulncheck': vulncheck})
	
	return {f"{dic['ipaddress']} {dic['result']}" for dic in c.fetchall()}


# General
def get_tables():
	''' Get a list of tables in the database.'''

	tables = []
	res = c.execute("SELECT name FROM sqlite_master WHERE type='table';")
	for name in res.fetchall():
		tables.append(name[0])
		
	return tables

# General
def get_table_row_count(tablename):
	''' Get row count from table.'''

	row_count = []
	res = c.execute(f"SELECT count(*) FROM {tablename}")
	for rows in res.fetchall():
		row_count.append(rows[0])
		
	return row_count

# General
def drop_table(tablename):
	''' Drop table. '''
	
	try:
		with conn:
			c.execute(f"DROP TABLE {tablename}")
	except sqlite3.OperationalError as e:
		pass

# Kerberos
def create_table_kerberos():
    ''' Create table Kerberos '''

    try:
        with conn:
            c.execute("""CREATE TABLE Kerberos(
                domain text,
                dcip text,
                attack_type text,
                target text,
                hash_data text
                )""")
    except sqlite3.OperationalError:
        pass

# Kerberos
def insert_kerberos(domain, dcip, attack_type, target, hash_data):
    ''' Insert Kerberos attack result [(domain, dcip, attack_type, target, hash_data)] '''
    
    with conn:
        c.execute("INSERT INTO kerberos VALUES (:domain, :dcip, :attack_type, :target, :hash_data)",
         {'domain': domain, 'dcip': dcip, 'attack_type': attack_type, 'target': target, 'hash_data': hash_data})

# Kerberos
def get_kerberos_results_by_domain(domain):
    ''' Get Kerberos results by domain '''

    c.execute("SELECT attack_type, target, hash_data FROM kerberos WHERE domain=:domain", {'domain': domain})
    
    return {f"{dic['attack_type']} - {dic['target']}" for dic in c.fetchall()}
