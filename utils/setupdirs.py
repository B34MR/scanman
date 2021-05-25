#!/usr/bin/env python3

from functools import partial
import os
import sys
import logging


# CONSTANTS
MAIN_DIR = 'outfiles'
SUB_DIRS = ['masscanner', 'nmapper', 'xmlfiles']

def make_dir(sub_dir, main_dir):
	'''
	Creates directory or logs if it already exists. 
	arg(s):
	- main_dir:str
	- sub_dir:str
	'''

	directory = os.path.join(main_dir, sub_dir)
	try:
		os.makedirs(directory, exist_ok = False)
	except FileExistsError as e:
		logging.warning(f'{e}')
		pass
	else:	
		return directory


def main():
	''' Main func '''

	make_dirs = partial(make_dir, main_dir=MAIN_DIR)
	results = list(map(make_dirs, SUB_DIRS))
	logresults = [logging.info(f'Created: {directory}') for directory in results if directory]


if __name__ == '__main__':
	main()