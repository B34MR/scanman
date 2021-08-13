#!/usr/bin/env python

import logging
import subprocess


class Ewrapper:
	''' EyeWitness class wrapper '''

	# MFS version cmd.
	# version_cmd = f'msfconsole -v'

	def __init__(self, filepath, args):
		''' Init arg(s) **kwargs '''

		# self.args = ' '.join([f'{k} {v}' for k, v in args.items()])
		self.filepath = filepath
		self.args = ' '.join(args)
		self.cmd = f'{self.filepath} {self.args}'

	# func 1.
		# Check for EyeWitness filepath.
			# -> If not EyeWitness filepath, Print warning.

	# func 2.
		# Check if EyeWitness Python is installed.
			# Install EyeWitness
				# -> call EyeWitness_install wrapper
					# Check if install was successful.

	# @classmethod
	# def get_version(cls):
	# 	'''Return Metasploit version:str '''
		
	# 	cmdlst = cls.version_cmd.split(' ')

	# 	try:
	# 		proc = subprocess.run(cmdlst,
	# 			shell=False,
	# 			check=True,
	# 			capture_output=True,
	# 			text=True
	# 			)
	# 	except Exception as e:
	# 		# Set check=True for the exception to catch.
	# 		logging.exception(e)
	# 		raise e
	# 	else:
	# 		# Debug print only.
	# 		logging.info(f'STDOUT:\n{proc.stdout}')
	# 		logging.debug(f'STDERR:\n{proc.stderr}')
	# 		# Convert version-branch to version number only 
	# 		# i.e '6.0.30-dev' to '6.0.30'
	# 		output = proc.stderr.split(' ')[2]

	# 		return output.split('-')[0]


	def run_scan(self):
		''' Launch EyeWitness scan via subprocess wrapper '''

		# Eyewitness cmd.
		cmdlst = self.cmd.split(' ')
		print(cmdlst)
		input("Press Enter to continue...")

		try:
			proc = subprocess.run(cmdlst,
				shell=False,
				check=False,
				capture_output=True,
				text=True)
		except Exception as e:
			# Set check=True for the exception to catch.
			logging.exception(e)
			raise e
		else:
			# DEV - pipe STDOUT to a rich full screen.
			print(f'STDOUT:\n{proc.stdout}')
			print(f'STDERR:\n{proc.stderr}')
			# Debug print only.
			logging.info(f'STDOUT:\n{proc.stdout}')
			logging.debug(f'STDERR:\n{proc.stderr}')

			return proc.stdout