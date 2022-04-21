#!/usr/bin/env python3

import xml.etree.ElementTree as ET
import logging


class NseParser:
	''' Nmap NSE Script Scan XML Parser. '''
	xmlroot = None
	
	
	def parse_xml(self, filepath):
		'''
		Parses/read an xml file and return the 'nmaprun' xmlroot. 
		arg(s):xmlfile:str '''
	
		xmltree = ET.parse(filepath)
		#<nmaprun></nmaprun>
		self.xmlroot = xmltree.getroot()

		return self.xmlroot

	
	def get_hosts(self):
		''' 
		Return all child 'hosts' elements from 'nmaprun' xmlroot.
		hosts:objlst '''

		# <nmaprun><host></host>
		hosts = self.xmlroot.findall('host') 
		
		return hosts


	def get_addr(self, host):
		'''
		Return 'addr' (ipaddress) element from 'address'.
		arg(s):host:objstr '''

		# <host><address addr=''/>
		address = host.find('address') 
		ipaddresss = address.get('addr')

		return ipaddresss


	def get_script(self, host):
		'''
		Return child elements from 'script'.
		args(s):host:objstr '''

		# NSE script 'FTP-ANON' used unconventional format, 
		# which did not include the 'hostscript' root. 
		try:
			ports = host.find('ports')
			port = ports.find('port')
			script = port.find('script')
			script_id = script.get('id')
			script_output = script.get('output')
			logging.info(f'XMLPARSER, GET_SCRIPT(), SCRIPT_OUTPUT: {script_output}')
			
			# FTP anonymous access.
			if script_id == 'ftp-anon':
				pass
			else:
				logging.warning(f'"SCRIPT XMLPARSER template not found: {script_id}"')

		except AttributeError as e:
			logging.debug(f'XMLPARSER, GET_SCRIPT(), ERROR:{e}')
			pass
		else:
			# elem = script_output
			result = script_id, script_output

			return result


	def get_hostscript(self, host):
		''' 
		Return child elements from 'hostscript'.
		args(s):host:objstr
		'''

		# DEV
		elem = ''
		
		# <host><hostscript>
		hostscript = host.find('hostscript')
		try:
			# <host><hostscript><script></script>
			script = hostscript.find('script')
			script_id = script.get('id')
			script_output = script.get('output')
			logging.info(f'XMLPARSER, GET_HOSTSCRIPT(), SCRIPT_OUTPUT: {script_output}')
			# DEV - Consider breaking this ^ out into seperate func.
			
			# DEV - SMBv1
			if script_id == 'smb-security-mode':
				# <host><hostscript><script><elem><elem><elem></elem>
				elemlst = script.findall('elem')
				elem = elemlst[-1]
			
			# DEV - SMBv2
			elif script_id == 'smb2-security-mode':
				# <host><hostscript><script><table></table>
				table = script.find('table')
				# <host><hostscript><script><table><elem></elem>
				elem = table.find('elem')
			
			# DEV - MS17-010 RCESMBv1 
			elif script_id == 'smb-vuln-ms17-010':
				# <host><hostscript><script><table></table>
				table = script.find('table')
				# <host><hostscript><script><table><elem><elem><elem></elem>
				elemlst = table.findall('elem')
				elem = elemlst[1]

			# DEV - MS08-067
			elif script_id == 'smb-vuln-ms08-067':
				# <host><hostscript><script><table></table>
				table = script.find('table')
				# <host><hostscript><script><table><elem><elem><elem></elem>
				elemlst = table.findall('elem')
				elem = elemlst[1]

			# DEV - CVE2009-3103 Server2008/Vista
			elif script_id == 'smb-vuln-cve2009-3103':
				# <host><hostscript><script><table></table>
				table = script.find('table')
				# <host><hostscript><script><table><elem><elem><elem></elem>
				elemlst = table.findall('elem')
				elem = elemlst[1]
			else:
				logging.warning(f'"HOSTSCRIPT XMLPARSER template not found: {script_id}"')

		except AttributeError as e:
			logging.debug(f'XMLPARSER, GET_HOSTSCRIPT(), ERROR: {e}')
			pass
		else:
			if elem == '':
				# DEV
				# result = script_id, script_output, elem
				logging.debug(f'XMLPARSER, GET_HOSTSCRIPT(), ELEMENT-TEXT: {None}')
			else:
				result = script_id, script_output, elem.text
				logging.info(f'XMLPARSER, GET_HOSTSCRIPT(), ELEMENT-TEXT: {elem.text}')

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
			
			# Results from 'hostscript'.
			result_hostscript = self.get_hostscript(host)
			# Results from 'script'.
			result_script = self.get_script(host)
			
			# Exclude hossts with no nsescript scan result(s).
			if result_hostscript is not None:
				i = (ipaddress, result_hostscript[2], result_hostscript[0])
				results.append(i)

			if result_script is not None:
				i = (ipaddress, result_script[1], result_script[0])
				results.append(i)
		
		return results


class EgressParser(NseParser):
	''' Egress Parser subclass. '''


	def get_name(self, host):
		''' 
		Return 'name' element from 'host'.
		arg(s):host:objstr 
		'''

		# <hostnames><hostname name="letmeoutofyour.net" type="user"/>
		hostnames = host.find('hostnames')
		hostname = hostnames.find('hostname')
		name = hostname.get('name')

		return name


	def run(self, filepath):
		''' 
		Read Nmap NSE XML (oX) output file and return the final results.
		arg(s):filepath:str
		'''

		results = []
		# XmlParser - read xml file and parse.
		root = self.parse_xml(filepath)
		# XmlParser - obtain hosts:lst from xml file.
		hosts = self.get_hosts()

		# XmlParser - obtain ipaddress(es) and nsescript scan result(s) from hosts:lst.
		for host in hosts:
			name = self.get_name(host)

			# <host><ports><port protocol="tcp" portid="2">
			ports = host.find('ports')
			for port in ports:
				# Exclude ports with no portid, I.e scan with no results.
				if port.get('portid') is not None:
					# name:letmeoutofyour.net portid:21, portocol:TCP, state:OPEN.
					result = (name, port.get('portid'), \
						port.get('protocol'), port.find('state').get('state'))
					results.append(result)
		
		return results
