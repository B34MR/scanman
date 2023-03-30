#!/usr/bin/env python3

import sys
import argparse
from argparse import RawTextHelpFormatter


# Parent Parser, HelpFormatter custom help menu string.
parent_parser_usage = """

Scanman
--------------------------------------------------
Dcscan usage: 
  python3 scanman.py dc -d contoso.local

Vulnscan usage: 
  python3 scanman.py vuln -m -n -iL /path/to/targetfile.txt

Webscan usage: 
  python3 scanman.py web -d /dir/to/write/report/ -iL /path/to/targetfile.txt


For granular mode options, see: configs/config.ini.

"""
# Parser A, HelpFormatter custom help menu string.
parser_a_usage = """
  
Scanman
--------------------------------------------------
Dcscan usage: 
  python3 scanman.py dc -d contoso.local
  python3 scanman.py dc -d contoso.local subdomain.contoso.local -ns 192.168.1.53

"""
# Parser B, HelpFormatter custom help menu string.
parser_b_usage = """
  
Scanman
--------------------------------------------------
Vulnscan usage: 
  python3 scanman.py vuln -m -n -eg -iL /path/to/targetfile.txt
  python3 scanman.py vuln -m -n -eg --ipparse --smbparse --rate 500 -iL /path/to/targetfile.txt 
  
"""
# Parser C, HelpFormatter custom help menu string.
parser_c_usage = """
  
Scanman
--------------------------------------------------
Webscan usage: 
  python3 scanman.py web -d /dir/to/write/report/ -iL /path/to/targetfile.txt
  
"""


class HelpFormatter(argparse.HelpFormatter):
    ''' Custom helpformaater subclass '''
    def add_usage(self, usage, actions, groups, prefix=None):
        ''' Custom usage help menu. '''

        if prefix is None:
            prefix = ''
        return super(HelpFormatter, self).add_usage(
            usage, actions, groups, prefix)


# Argparse - custom func.
def group_kwargs(group_title):
  '''
  Argparser func.
  Return arguments:dict for a specific "Argparse Group". 
  arg(s) group_title:str '''

  for group in  parser_b._action_groups:
    if group.title == group_title:
      group_dict = {a.dest: getattr(parser.parse_args(), a.dest, None) for a in group._group_actions}
      kwargs = vars(argparse.Namespace(**group_dict))
      # print(f'\n{group.title.upper()}:\n{kwargs}')
      return kwargs

# Parent parser with the shared arguments.
parent_parser = argparse.ArgumentParser(description='Global Arguments', add_help=False)
parent_parser.add_argument('-db', '--database', dest='database', default='.scanman.db', metavar='' , help='Database file.')
parent_parser.add_argument('--droptables', dest='droptables', action='store_true', help='Drop all database tables.')
parent_parser.add_argument('--loglevel', dest='loglevel', type=str.upper, default='WARNING', choices=['DEBUG', 'INFO', 'WARNING'], help='Set logging level')

# Main parser
parser = argparse.ArgumentParser(formatter_class=HelpFormatter, description='', usage=parent_parser_usage, add_help=True)
subparsers = parser.add_subparsers(title='Scan Modes', help='Select a Mode with "-h/--help" for specific help options.')

# Subparser A.
parser_a = subparsers.add_parser('dc', parents=[parent_parser], formatter_class=HelpFormatter, description='', usage=parser_a_usage, help='dc -h, --help')
parser_a.set_defaults(subparser='A')
# Group_A1 Options.
group_a1 = parser_a.add_argument_group('Dcscan Arguments')
group_a1.add_argument('-d', dest='domain', type=str, metavar='', help='Use a single Domain name or multiple Domain names seperated by a space.', nargs='+')
group_a1.add_argument('-ns', dest='nameserver', type=str, required=False, metavar='', help='Use custom Nameserver')

# Subparser B.
parser_b = subparsers.add_parser('vuln', parents=[parent_parser],  formatter_class=HelpFormatter, description='', usage=parser_b_usage, help='vuln -h, --help')
parser_b.set_defaults(subparser='B')
# Group_B1 Options.
group_b1 = parser_b.add_argument_group('Masscan Arguments')
group_b1.add_argument('-iL', dest='-iL', type=str, required=False, metavar='', help='Masscan target list, accepts IPs or network ranges, no hostnames.')
group_b1.add_argument('-eL', dest='--excludefile', type=str, required=False, metavar='', default=None, help='Masscan exclude list.')
group_b1.add_argument('-i', dest='-i', type=str, required=False, default='eth0', metavar='', help='Masscan network adapter interface.')
group_b1.add_argument('-r', '--rate', dest='--rate', type=str, required=False, metavar='', default='250', help='Masscan rate in kpps.')
# Group_B2 Options.
group_b2 = parser_b.add_argument_group('Vulnscan Arguments')
group_b2.add_argument('-m', '--msf', dest='msf', action='store_true', help='Enable MSF checks. For more options, see: configs/config.ini.')
group_b2.add_argument('-n', '--nmap', dest='nmap', action='store_true', help='Enable Nmap checks. For more options, see: configs/config.ini.')
group_b2.add_argument('-eg', '--egress', dest='egressscan', action='store_true', help='Enable Egress-scan. For more options, see: configs/config.ini.')
group_b2.add_argument('--ipparse', dest='parse_ip', action='store_true', help='Enable IP address parsing.')
group_b2.add_argument('--smbparse', dest='smbparse', action='store_true', help='Enable smb-signing parsing.')

# Subparser C.
parser_c = subparsers.add_parser('web', parents=[parent_parser], formatter_class=HelpFormatter, description='', usage=parser_c_usage, help='webscan -h, --help')
parser_c.set_defaults(subparser='C')
# Group_C1 Options.
group_c1 = parser_c.add_argument_group('Webscan Arguments')
group_c1.add_argument('-d', dest='ew_report', type=str, required=False, metavar='', help='Eyewitness directory name for report output.')
group_c1.add_argument('-iL', dest='-iL', type=str, required=False, metavar='', help='Masscan target list, accepts IPs or network ranges, no hostnames.')
group_c1.add_argument('-eL', dest='--excludefile', type=str, required=False, metavar='', default=None, help='Masscan exclude list.')
group_c1.add_argument('-i', dest='-i', type=str, required=False, default='eth0', metavar='', help='Masscan network adapter interface.')
group_c1.add_argument('-r', '--rate', dest='--rate', type=str, required=False, metavar='', default='250', help='Masscan rate in kpps.')

# Print 'help' for the specific subparser if no options are defined.
if len(sys.argv) == 1:
  parser.print_help(sys.stderr)
  sys.exit(1)
elif sys.argv[1] == 'dc' and len(sys.argv) <=2:
  parser_a.print_help(sys.stderr)
  sys.exit(1)
elif sys.argv[1] == 'vuln' and len(sys.argv) <=2:
  parser_b.print_help(sys.stderr)
  sys.exit(1)
elif sys.argv[1] == 'web' and len(sys.argv) <=2:
  parser_c.print_help(sys.stderr) 
  sys.exit(1)
