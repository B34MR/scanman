#!/usr/bin/env python3

import sys
import argparse
from argparse import RawTextHelpFormatter

# Custom usage / help menu.
class HelpFormatter(argparse.HelpFormatter):
    def add_usage(self, usage, actions, groups, prefix=None):
        if prefix is None:
            prefix = ''
        return super(HelpFormatter, self).add_usage(
            usage, actions, groups, prefix)


def parse_args():
  ''' Define arguments '''
  
  # Custom help menu.
  custom_usage = """
  
Scanman
--------------------------------------------------\n
Usage (A): 
  python3 scanman.py -iL /path/to/targetfile.txt
  python3 scanman.py -iL /path/to/targetfile.txt --msf
  python3 scanman.py -iL /path/to/targetfile.txt --nmap
  python3 scanman.py -iL /path/to/targetfile.txt --msf --nmap
  python3 scanman.py -iL /path/to/targetfile.txt --drop
  python3 scanman.py -iL /path/to/targetfile.txt --database /path/to/database.db

Usage (B): 
  python3 scanman.py --msf --nmap

Usage (C): 
  python3 scanman.py -n -m -d
  
"""
 
  # Define parser
  parser = argparse.ArgumentParser(formatter_class=HelpFormatter, description='', usage=custom_usage, add_help=False)
  
  # DEV - positional arg.
  parser.add_argument('configfile', nargs="?", type=str, metavar='<configfile>', default='./configs/masscan.ini', help="Input from configuration file (defaults to './configs/masscan.ini')")
  
  # Primary Options.
  optional_group = parser.add_argument_group('optional_args')
  optional_group.add_argument('-iL', '--inputlist', type=str, required=False, default='', help='Input from list of hosts/networks')
  optional_group.add_argument('-m', '--msf', dest='msf', action='store_true', help='Toggle Metasploit Framework (MSF) scans on/off.')
  optional_group.add_argument('-n', '--nmap', dest='nmap', action='store_true', help='Toggle Nmap Script Engine (NSE) scans on/off.')
  
  # Secondary Options.
  optional_group.add_argument('-d', '--drop', dest='droptable', action='store_true', help='Drops database table')
  optional_group.add_argument('--database', dest='database', default='.database.db', metavar='DATABASE' ,help='Filepath for database file.')
  optional_group.add_argument('--loglevel', dest='loglevel', type=str.upper, default='WARNING', choices=['NOTSET', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help='Configure logging level')
  # DEV
  # Print 'help' if no options are defined.
  if len(sys.argv) == 1:
    parser.print_help(sys.stderr)
    sys.exit(1)
  # Initiate parser instance.
  args = parser.parse_args()
  return args

def main():
  import arguments
  arguments.parse_args()

if __name__ == "__main__":
    main()