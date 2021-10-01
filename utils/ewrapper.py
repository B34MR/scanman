#!/usr/bin/env python

import logging
import subprocess


class Ewrapper:
	''' EyeWitness class wrapper '''

	def __init__(self, filepath, args):
		''' Init arg(s) **kwargs '''

		# self.args = ' '.join([f'{k} {v}' for k, v in args.items()])
		self.filepath = filepath
		self.args = ' '.join(args)
		self.cmd = f'{self.filepath} {self.args}'


	def run_scan(self):
		''' Launch EyeWitness scan via subprocess wrapper '''

		# Eyewitness cmd.
		cmdlst = self.cmd.split(' ')

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
			# Debug print only.
			logging.info(f'STDOUT:\n{proc.stdout}')
			logging.debug(f'STDERR:\n{proc.stderr}')

			return proc.stdout