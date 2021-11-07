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


# Custom help menu.
custom_usage = """
  
Scanman
--------------------------------------------------\n
Usage Examples: 
  python3 scanman.py -iL /path/to/targetfile.txt
  python3 scanman.py -iL /path/to/targetfile.txt --msf
  python3 scanman.py -iL /path/to/targetfile.txt --nmap
  python3 scanman.py -iL /path/to/targetfile.txt --eyewitness
  python3 scanman.py -iL /path/to/targetfile.txt --excludefile /path/to/excludefile.txt
  python3 scanman.py -iL /path/to/targetfile.txt --drop
  python3 scanman.py -iL /path/to/targetfile.txt --database /path/to/database.db

Typical Usage:
  python3 scanman.py -iL /path/to/targetfile.txt -m -n -e
  
"""
 
# Define parser
parser = argparse.ArgumentParser(formatter_class=HelpFormatter, description='', usage=custom_usage, add_help=False)

# Group1 Options.
group1 = parser.add_argument_group('Masscan Arguments')
group1.add_argument('-iL', '--inputlist', dest='-iL', type=str, required=True, help='Input from list of hosts/networks')
group1.add_argument('-eL', '--excludefile', dest='--excludefile', type=str, required=False, default=None, help='Exclude list from file')
group1.add_argument('-i', '--interface', dest='-i', type=str, required=False, default='eth0', help='Network Adapter interface')
group1.add_argument('-r', '--rate', dest='--rate', type=str, required=False, default='250', help="Masscan's rate in kpps")

# Group2 Options.
group2 = parser.add_argument_group('Scanman Arguments')
group2.add_argument('-m', '--msf', dest='msf', action='store_true', help='Enable MSF Vulnscans.')
group2.add_argument('-n', '--nmap', dest='nmap', action='store_true', help='Enable Vulnscans.')
group2.add_argument('-e', '--eyewitness', dest='eyewitness', action='store_true', help='Enable Eyewitness scans.')
group2.add_argument('-nm', '--no-masscan', dest='nomasscan', action='store_true', help='Disable Masscan portscans.')
group2.add_argument('-d', '--drop-tables', dest='droptable', action='store_true', help='Drop existing database tables.')
group2.add_argument('--ip', dest='parse_ip', action='store_true', help='Enable ipaddress parser.')
group2.add_argument('--database', dest='database', default='.database.db', metavar='' , help='Filepath for database file.')
group2.add_argument('--loglevel', dest='loglevel', type=str.upper, default='WARNING', choices=['DEBUG', 'INFO', 'WARNING'], help='Set logging level')

# Group3 Options.
group3 = parser.add_argument_group('Eyewitness Arguments')
group3.add_argument('--ew-report', dest='ew_report', type=str, required=False, metavar='', help='Eyewitness report output directory.')
  
# Print 'help' if no options are defined.
if len(sys.argv) == 1 \
or sys.argv[1] == '-h' \
or sys.argv[1] == '--help':
  parser.print_help(sys.stderr)
  sys.exit(1)

# Debug - deving and troubleshooting purposes.
def main():
  import arguments
  
  args = arguments.parser.parse_args()
  # print(vars(args))

  for group in parser._action_groups:
    if group.title == 'Masscan Arguments':
      group_dict = {a.dest: getattr(args, a.dest, None) for a in group._group_actions}
      print(group.title)
      masscan_kwargs = vars(argparse.Namespace(**group_dict))
      print(masscan_kwargs)
      print('\n')
    elif group.title == 'Scanman Arguments':
      group_dict = {a.dest: getattr(args, a.dest, None) for a in group._group_actions}
      print(group.title)
      scanman_kwargs = vars(argparse.Namespace(**group_dict))
      print(scanman_kwargs)


if __name__ == "__main__":
    main()
