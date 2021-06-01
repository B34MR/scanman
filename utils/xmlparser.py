#!/usr/bin/env python3

import xml.etree.ElementTree as ET
import logging


class NseParser:
	''' Nmap NSE Script Scan XML Parser. '''
	xmlroot = None
	
	
	def parse_xml(self, filepath):
		'''
		Parses/read an xml file and return the 'nmaprun' xmlroot. 
		arg(s):xmlfile:str
		'''
	
		xmltree = ET.parse(filepath)
		#<nmaprun></nmaprun>
		self.xmlroot = xmltree.getroot()

		return self.xmlroot

	
	def get_hosts(self):
		''' 
		Return all child 'hosts' elements from 'nmaprun' xmlroot.
		hosts:objlst 
		'''

		# <nmaprun><host></host>
		hosts = self.xmlroot.findall('host') 
		
		return hosts


	def get_addr(self, host):
		'''
		Return 'addr' (ipaddress) element from 'address'.
		arg(s):host:objstr
		'''

		# <host><address addr=''/>
		address = host.find('address') 
		ipaddresss = address.get('addr')

		return ipaddresss


	def get_hostscript(self, host):
		''' 
		Return child elements from 'hostscript'.
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


	def run(self, filepath):
		''' 
		Read Nmap NSE XML (oX) output file and return the final results.
		arg(s):filepath:str
		'''

		results = []
		# XmlParser - read xml file and parse.
		self.parse_xml(filepath)
		# XmlParser - obtain hosts:lst from xml file.
		hosts = self.get_hosts()
		# XmlParser - obtain ipaddress(es) and nsescript scan result(s) from hosts:lst.
		for host in hosts:
			ipaddress = self.get_addr(host)
			result = self.get_hostscript(host)
			# Exclude hossts with no nsescript scan result(s).
			if result is not None:
				i = (ipaddress, result[2], result[0])
				results.append(i)
		
		return results


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