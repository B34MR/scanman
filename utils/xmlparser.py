#!/usr/bin/env python3

import xml.etree.ElementTree as ET
import logging


class NSEParser():
	''' Nmap NSE Script Scan XML Parser. '''
	
	
	def __init__(self):
		self.xmlroot = None


	def read_xml(self, filepath):
		'''
		Parses/reads an xml file and returns the xmlroot. 
		arg(s):xmlfile:str
		'''
	
		xmltree = ET.parse(filepath)
		#<nmaprun></nmaprun>
		self.xmlroot = xmltree.getroot()

		return self.xmlroot

	
	def get_hosts(self):
		''' 
		Return hosts:objlst 
		'''

		# <nmaprun><host></host>
		hosts = self.xmlroot.findall('host') 
		
		return hosts


	def get_addr(self, host):
		'''
		Return IP address
		arg(s):host:objstr
		'''

		# <host><address addr=''/>
		address = host.find('address') 
		ipaddresss = address.get('addr')

		return ipaddresss


	def get_hostscript(self, host):
		''' 
		Return the result from a nse script scan.
		args(s):host:objstr
		'''
		
		# <host><hostscript>
		hostscript = host.find('hostscript')
		try:
			# <host><hostscript><script></script>
			script = hostscript.find('script')
			script_id = script.get('id')
			script_output = script.get('output')
			# <host><hostscript><script><table></table>
			table = script.find('table')
			# <host><hostscript><script><table><elem></elem>
			elem = table.find('elem')
		except AttributeError as e:
			logging.debug(e)
			pass
		else:
			result = script_id, script_output, elem.text

			return result


# DEV - Sample Nmap XML layout with NSE hostscript result.
# <nmaprun>
# 	<host starttime="1621772038" endtime="1621772104">
# 		<status state="up" reason="user-set" reason_ttl="0"/>
# 		<Address addr='127.0.0.1', addrtype='ipv4/>

# 		<ports>
# 			<port protocol="tcp" portid="445">
# 				<state state='open' reason="reset" reason_ttl="128"/>
# 				<service name="microsoft-ds" method="table" conf="3"/>
# 			</port>
# 		</ports>

# 		<hostscript>
#			<script id='smb2-security-mode', output='&#xa;2.02:&#xa;Message signing enabled but not required'>	
#				<table key="2.02">
#					<elem>Message signing enabled but not required</elem>
#				</table>
# 			</script>
#		</hostscript>
#	</host>