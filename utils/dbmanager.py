#!/usr/bin/env python

from rich import box
from rich.table import Table
from utils import richard as r
from utils import sqlite as db
import sys


# Rich table obj.
def generate_table() -> Table:
	''' Make a new table.'''
	table = Table(title='Database Tables', box=box.ASCII)
	table.add_column('Table Name', justify='left', style='grey37')
	table.add_column('Number of Rows', justify='left', style='deep_sky_blue3')
	
	dbtables = db.get_tables()
	
	for dbtable in dbtables:
		num_of_rows = db.get_table_row_count(dbtable)
		table.add_row(f'{dbtable}', f'{num_of_rows}')
	
	return r.console.print(table)


# Menu - options.
def menu_option_quit():
	r.console.print(':v: Peace')
	sys.exit(0)


def menu_option_invalid():
	r.console.print('[red]Invalid option, Please try again.\n')


def menu_option_invalid_datatype():
	r.console.print('[red]Invalid option, Please enter a number.\n')


def menu_option_droptables():
	r.console.print(f'\n')
	tables = db.get_tables()
	for table in tables:
		db.drop_table(f'{table}')
		r.console.print(f'Dropped: [grey37]{table}')


def menu_status_good():
	r.console.print('\n:beers: Ready to scanman :beers:')
	r.console.print(f'Database: [repr.path]{db.database_file}')
	r.console.print('No existing entries were found in the database.')


def menu_status_bad():
	r.console.print(f'\n[orange_red1]:large_orange_diamond: WARNING :large_orange_diamond:')
	r.console.print(f'Database: [repr.path]{db.database_file}')
	r.console.print(f'[grey37]Existing entries were found in the database.')
	r.console.print(f'[grey37]Continuing with the scan will merge the new and existing data.')
	r.console.print(f'[grey37]Select the (M)enu option to drop specific db tables.')


def menu_status_all_tables_dropped():
	r.console.print('\nNo existing tables are left in the database.')
	r.console.print(':v: Peace')
	sys.exit(0)


def build_submenu_options():
	''' Build submenu options from db tables.'''
	submenu_options = {0:'All Tables'}
	dbtables = db.get_tables()

	count = 0
	for dbtable in dbtables:
		count +=1
		submenu_options[count] = dbtable
	# Appened 'Quit' to the end of the menu.
	count +=1
	submenu_options[count] = 'Quit'

	return submenu_options


def menu():
	''' Database Menu Manager. '''
	while True:
		dbtables = db.get_tables()
		# Database clean.
		if not dbtables:
			menu_status_good()
			option = input(f'(Q)uit / [ENTER] to scan: ')
			if option.upper() == 'Q':
				menu_option_quit()
			elif option.upper() == '':
				break
			else:
				menu_option_invalid()
		# Database dirty.
		else:
			menu_status_bad()
			option = input(f'(M)enu / (Q)uit / [ENTER] to scan: ')
			# r.console.print('\n')
			if option.upper() == 'Q':
				menu_option_quit()
			elif option.upper() == '':
				break
			elif option.upper() == 'M':
				# Database submenu.
				while True:
					submenu_options = build_submenu_options()
					try:
						r.console.print(f'\n')
						generate_table()
						r.console.print('\n')
						[r.console.print(f'{k}. {v}') for k, v in submenu_options.items()]
						option_key = int(input(f'Select table to drop: '))
						submenu_options[option_key]
					except ValueError:
						menu_option_invalid_datatype()
					except KeyError:
						menu_option_invalid()
					else:
						if submenu_options[option_key] == 'Quit':
							menu_option_quit()
						elif submenu_options[option_key] == 'All Tables':
							menu_option_droptables()
							if not db.get_tables(): menu_status_all_tables_dropped()
						elif option_key != '':
							db.drop_table(submenu_options[option_key])
							r.console.print(f'\n')
							r.console.print(f'Dropped: [grey37]{submenu_options[option_key]}')
							r.console.print(f'\n')
							if not db.get_tables(): menu_status_all_tables_dropped()
						else:
							menu_option_invalid()
			else:
				menu_option_invalid()