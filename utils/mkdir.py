#!/usr/bin/env python3

import os
import logging


def mkdir(directory):
	'''
	Create dir, log if dir already exists. 
	arg(s):directory:str
	'''
	try:
		os.makedirs(directory, exist_ok = False)
	except FileExistsError as e:
		logging.warning(f'{e}')
		pass
	else:	
		return directory
