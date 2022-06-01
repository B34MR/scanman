#!/usr/bin/env python3

import sys
import argparse
from argparse import RawTextHelpFormatter


# HelpFormatter - custom help menu string.
custom_usage = """
  
Scanman
--------------------------------------------------\n
Configuration File:
  For more options, see: configs/config.ini.

Usage Examples: 
  python3 scanman.py -iL /path/to/targetfile.txt
  python3 scanman.py -iL /path/to/targetfile.txt --msf
  python3 scanman.py -iL /path/to/targetfile.txt --nmap
  python3 scanman.py --domain contoso.local
  python3 scanman.py --egress
  python3 scanman.py --eyewitness


Typical Usage:
  python3 scanman.py -iL [TARGETFILE] -d [DOMAIN] -m -n -eg -ew --ipparse --smbparse
  
"""


class HelpFormatter(argparse.HelpFormatter):
    ''' Custom helpformaater subclass '''


    def add_usage(self, usage, actions, groups, prefix=None):
        ''' Custom usage help menu. '''

        if prefix is None:
            prefix = ''
        return super(HelpFormatter, self).add_usage(
            usage, actions, groups, prefix)


# Argparse - init parser.
parser = argparse.ArgumentParser(formatter_class=HelpFormatter, description='', usage=custom_usage, add_help=False)


# Argparse - custom func.
def group_kwargs(group_title):
  '''
  Argparser func.
  Return arguments:dict for a specific "Argparse Group". 
  arg(s) group_title:str '''

  for group in parser._action_groups:
    if group.title == group_title:
      group_dict = {a.dest: getattr(parser.parse_args(), a.dest, None) for a in group._group_actions}
      kwargs = vars(argparse.Namespace(**group_dict))
      # print(f'\n{group.title.upper()}:\n{kwargs}')

      return kwargs


# Group1 Options.
group1 = parser.add_argument_group('Masscan Arguments')
group1.add_argument('-iL', '--inputlist', dest='-iL', type=str, required=False, help='Input from list of ips/networks. **Enables Masscan.')
group1.add_argument('-eL', '--excludefile', dest='--excludefile', type=str, required=False, default=None, help='Exclude list from file')
group1.add_argument('-i', '--interface', dest='-i', type=str, required=False, default='eth0', help='Network Adapter interface')
group1.add_argument('-r', '--rate', dest='--rate', type=str, required=False, default='250', help="Masscan's rate in kpps")

# Group2 Options.
group2 = parser.add_argument_group('Scanman Arguments')
group2.add_argument('-m', '--msf', dest='msf', action='store_true', help='Enable MSF Vulnscans.')
group2.add_argument('-n', '--nmap', dest='nmap', action='store_true', help='Enable Nmap Vulnscans.')
group2.add_argument('-eg', '--egress', dest='egressscan', action='store_true', help='Enable Egress-scan.')
group2.add_argument('-ew', '--eyewitness', dest='eyewitness', action='store_true', help='Enable Eyewitness /w portscans.')
group2.add_argument('-db', '--database', dest='database', default='.scanman.db', metavar='' , help='Filepath for Scanman database.')
group2.add_argument('--droptables', dest='droptables', action='store_true', help='Drop all database tables.')
group2.add_argument('--ipparse', dest='parse_ip', action='store_true', help='Enable ipaddress parsing.')
group2.add_argument('--smbparse', dest='smbparse', action='store_true', help='Parse out false positives for smb-signing.')
group2.add_argument('--loglevel', dest='loglevel', type=str.upper, default='WARNING', choices=['DEBUG', 'INFO', 'WARNING'], help='Set logging level')

# Group3 Options.
group3 = parser.add_argument_group('Eyewitness Arguments')
group3.add_argument('-ewr', '--ewreport', dest='ew_report', type=str, required=False, metavar='', help='Eyewitness report output directory.')

# Group4 Options.
group4 = parser.add_argument_group('GetDomainController Arguments')
group4.add_argument('-d', '--domain', dest='domain', type=str, help='Provide DomainName(s). **Enables GetDC.', nargs='+')
group4.add_argument('-ns', '--nameserver', dest='nameserver', type=str, required=False, metavar='', help='Nameserver')

# DEV
# Argparse - return kwargs for the specific "Argparse Group".
# masscan_kwargs = group_kwargs('Masscan Arguments')
# Argparse - verify that the required '-iL' arg is used when applicable (I.e -m, -n, -e).
# args = parser.parse_args()
# if args.msf is None or args.nmap is None or args.eyewitness is None:
#   if masscan_kwargs['-iL'] is None:
#     print('The following arguments are required: -iL/--inputlist')
#     sys.exit(1)

# Print 'help' if no options are defined.
if len(sys.argv) == 1:
  parser.print_help(sys.stderr)
  sys.exit(1)

# DEBUG - for deving and troubleshooting purposes.
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
