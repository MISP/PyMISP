#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

from pymisp import MISPEvent
try:
	from bs4 import BeautifulSoup
	has_bs4 = True
except ImportError:
	has_bs4 = False

unknowMapping = {'category': 'Artifacts dropped', 'type': 'other'},

iocMispMapping = {
	#~ @Link https://wiki.ops.fr/doku.php/manuels:misp:event-guidelines
	
	'CookieHistoryItem/HostName': {'type': 'hostname', 'comment': 'CookieHistory.'},

	'DriverItem/DriverName': {'category': 'Artifacts dropped', 'type': 'other', 'comment': 'DriverName.'},
	'DriverItem/CertificateIssuer' : {'category': 'Artifacts dropped', 'type': 'other', 'comment': 'DriverCertificateIssuer.'},
	'DriverItem/DeviceItem/AttachedDeviceName' : {'category': 'Artifacts dropped','type': 'other', 'comment': 'DriverDeviceName. '},

	'DnsEntryItem/Host': {'type': 'domain'},
	'DnsEntryItem/RecordName' : {'category': 'Network activity','type': 'domain'},

	'Email/To': {'type': 'target-email'},
	'Email/Date': {'type': 'comment', 'comment': 'EmailDate.'},
	'Email/Body': {'type': 'email-subject'},
	'Email/From': {'type': 'email-dst'},
	'Email/Subject': {'type': 'email-subject'},
	'Email/Attachment/Name': {'type': 'email-attachment'},

	'FileItem/Md5sum' : {'category': 'External analysis','type': 'md5'},
	'FileItem/Sha1sum' : {'category': 'External analysis','type': 'sha1'},
	'FileItem/FileName' : {'category': 'External analysis','type': 'filename'},
	'FileItem/FullPath' : {'category': 'External analysis','type': 'filename'},
	'FileItem/FilePath' : {'category': 'External analysis','type': 'filename'},
	'FileItem/Sha256sum' : {'category': 'External analysis','type': 'sha256'},
	'FileItem/DevicePath' : {'category': 'External analysis','type': 'comment', 'comment': 'DevicePath. '},
	'FileItem/SizeInBytes' : {'category': 'Artifacts dropped','type': 'size-in-bytes'},
	'FileItem/PEInfo/Type' : {'category': 'External analysis','type': 'comment','comment': 'Type. '},
	'FileItem/FileExtension' : {'category': 'External analysis','type': 'comment','comment': 'FileExtension. '},
	'FileItem/FilenameCreated' : {'category': 'External analysis','type': 'filename', 'comment': 'FilenameCreated. '},
	'FileItem/StringList/string' : {'category': 'External analysis','type': 'pattern-in-file', 'comment': 'string list. '},
	'FileItem/PEInfo/PETimeStamp' : {'category': 'External analysis','type': 'pattern-in-file', 'comment': 'TimeStamp. '},
	'FileItem/PEInfo/Exports/DllName' : {'category': 'External analysis','type': 'pattern-in-memory', 'comment': 'DllName. '},
	'FileItem/PEInfo/Sections/Section/Name' : {'category': 'External analysis','type': 'pattern-in-memory', 'comment': 'SectionName. '},
	'FileItem/PEInfo/DetectedAnomalies/string' : {'category': 'External analysis','type': 'pattern-in-file', 'comment': 'AnomaliesString. '},
	'FileItem/PEInfo/Exports/NumberOfFunctions' : {'category': 'External analysis','type': 'pattern-in-file', 'comment': 'NumberOfFunctions. '},
	'FileItem/PEInfo/ImportedModules/Module/Name' : {'category': 'External analysis','type': 'pattern-in-file', 'comment': 'ImportedModulesName. '},
	'FileItem/PEInfo/DigitalSignature/Description' : {'category': 'External analysis','type': 'comment', 'comment': 'PEDigitalSignatureDescription. '},
	'FileItem/PEInfo/DigitalSignature/SignatureExists' : {'category': 'External analysis','type': 'comment','comment': 'SignatureExists. '},
	'FileItem/PEInfo/Exports/ExportedFunctions/string' : {'category': 'External analysis','type': 'comment', 'comment': 'ExportedFunctions. '},
	'FileItem/PEInfo/DigitalSignature/CertificateIssuer' : {'category': 'External analysis','type': 'comment', 'comment': 'SignatureCertificateIssuer. '},
	'FileItem/PEInfo/DigitalSignature/SignatureVerified' : {'category': 'External analysis','type': 'comment', 'comment': 'SignatureVerified. '},
	'FileItem/PEInfo/DigitalSignature/CertificateSubject' : {'category': 'External analysis','type': 'other', 'comment': 'CertificateDigitalSignatureSubject. '},
	'FileItem/PEInfo/ResourceInfoList/ResourceInfoItem/Name' : {'category': 'External analysis','type': 'comment', 'comment': 'PEResourceName. '},
	'FileItem/PEInfo/ResourceInfoList/ResourceInfoItem/Type' : {'category': 'External analysis','type': 'comment', 'comment': 'PEResourceType. '},
	'FileItem/PEInfo/VersionInfoList/VersionInfoItem/Language' : {'category': 'External analysis','type': 'pattern-in-file', 'comment': 'PELanguageVersion. '},
	'FileItem/PEInfo/ResourceInfoList/ResourceInfoItem/Language' : {'category': 'External analysis','type': 'pattern-in-file', 'comment': 'PELanguageResource. '},
	'FileItem/PEInfo/VersionInfoList/VersionInfoItem/CompanyName' : {'category': 'External analysis','type': 'pattern-in-file','comment': 'CompanyName. '},
	'FileItem/PEInfo/VersionInfoList/VersionInfoItem/FileVersion' : {'category': 'External analysis','type': 'pattern-in-file', 'comment': 'PEVersion. '},
	'FileItem/PEInfo/VersionInfoList/VersionInfoItem/ProductName' : {'category': 'External analysis','type': 'pattern-in-file', 'comment': 'ProductName. '},
	'FileItem/PEInfo/VersionInfoList/VersionInfoItem/InternalName' : {'category': 'External analysis','type': 'pattern-in-file', 'comment': 'InternalName. '},
	'FileItem/PEInfo/VersionInfoList/VersionInfoItem/LegalCopyright' : {'category': 'External analysis','type': 'pattern-in-file', 'comment': 'LegalCopyright. '},
	'FileItem/PEInfo/VersionInfoList/VersionInfoItem/ProductVersion' : {'category': 'External analysis','type': 'pattern-in-file', 'comment': 'ProductVersion. '},
	'FileItem/PEInfo/VersionInfoList/VersionInfoItem/FileDescription' : {'category': 'External analysis','type': 'comment', 'comment': 'FileDescription .'},
	'FileItem/PEInfo/ImportedModules/Module/ImportedFunctions/string' : {'category': 'External analysis','type': 'pattern-in-file', 'comment': 'ImportedModules. '},
	'FileItem/PEInfo/VersionInfoList/VersionInfoItem/OriginalFilename' : {'category': 'External analysis','type': 'pattern-in-file', 'comment': 'OriginalFilename. '},

	'FormHistoryItem/HostName': {'type': 'hostname', 'comment': 'FormHistory. '},

	'Network/URI' : {'category': 'Network activity','type': 'uri'},
	'Network/DNS' : {'category': 'Network activity','type': 'domain'},
	'Network/String' : {'category': 'Network activity','type': 'url'},
	'Network/IPRange' : {'category': 'Network activity','type': 'ip-dst'},
	'Network/UserAgent' : {'category': 'Network activity','type': 'user-agent'},

	'PortItem/localIP' : {'category': 'Network activity','type': 'ip-src'},
	'PortItem/remoteIP' : {'category': 'Network activity','type': 'ip-dst'},
	'PortItem/remotePort' : {'category': 'Network activity','type': 'pattern-in-traffic', 'comment': 'RemotePort. '},

	'ProcessItem/name' : {'category': 'External analysis','type': 'pattern-in-memory', 'comment': 'ProcessName. '},
	'ProcessItem/path' : {'category': 'External analysis','type': 'pattern-in-memory', 'comment': 'ProcessPath. '},
	'ProcessItem/Mutex' : {'category': 'Artifacts dropped','type': 'mutex', 'comment': 'mutex'},
	'ProcessItem/arguments' : {'category': 'External analysis','type': 'pattern-in-memory', 'comment': 'ProcessArguments. '},
	'ProcessItem/NamedPipe' : {'category': 'Artifacts dropped','type': 'named pipe'},
	'ProcessItem/Pipe/Name' : {'category': 'Artifacts dropped','type': 'named pipe'},
	'ProcessItem/Mutex/Name' : {'category': 'Artifacts dropped','type': 'mutex', 'comment': 'MutexName. '},
	'ProcessItem/Event/Name' : {'category': 'External analysis','type': 'pattern-in-memory', 'comment': 'ProcessName. '},
	'ProcessItem/StringList/string' : {'category': 'External analysis','type': 'pattern-in-memory', 'comment': 'ProcessStringList. '},
	'ProcessItem/HandleList/Handle/Name' : {'category': 'External analysis','type': 'pattern-in-memory', 'comment': 'ProcessHandleListName'},
	'ProcessItem/HandleList/Handle/Type' : {'category': 'External analysis','type': 'pattern-in-memory', 'comment': 'ProcessHandleType'},
	'ProcessItem/SectionList/MemorySection/Name' : {'category': 'External analysis','type': 'pattern-in-memory', 'comment': 'ProcessSectionMemoryName'},
	'ProcessItem/SectionList/MemorySection/PEInfo/Exports/DllName' : {'category': 'External analysis','type': 'pattern-in-memory', 'comment': 'ProcessMemoryPEExportsDllName'},
	'ProcessItem/SectionList/MemorySection/PEInfo/Sections/Section/Name' : {'category': 'External analysis','type': 'pattern-in-memory', 'comment': 'ProcessSectionNameInMemory'},
	
	'RegistryItem/Text' : {'category': 'Artifacts dropped','type': 'regkey', 'comment': 'RegistryText. '},
	'RegistryItem/Path' : {'category': 'Artifacts dropped','type': 'regkey', 'comment': 'RegistryPath. '},
	'RegistryItem/Value' : {'category': 'Artifacts dropped','type': 'regkey', 'comment': 'RegistryValue. '},
	'RegistryItem/KeyPath' : {'category': 'Artifacts dropped','type': 'regkey', 'comment': 'RegistryKeyPath. '},
	'RegistryItem/ValueName' : {'category': 'Artifacts dropped','type': 'regkey', 'comment': 'RegistryValueName. '},
	
	'RouteEntryItem/Destination': {'category': 'Network activity','type': 'ip-dst'},
	'RouteEntryItem/Destination/IP' : {'category': 'Network activity','type': 'ip-dst', 'comment': 'RouteDestination. '},
	'RouteEntryItem/Destination/string' : {'category': 'Network activity','type': 'url', 'comment': 'RouteDestination. '},


	'ServiceItem/name' : {'category': 'Artifacts dropped','type': 'windows-service-name'},
	'ServiceItem/type' : {'category': 'Artifacts dropped','type': 'pattern-in-memory', 'comment': 'ServiceType. '},
	'ServiceItem/startedAs' : {'category': 'Artifacts dropped','type': 'pattern-in-memory', 'comment': 'ServiceStartedAs. '},
	'ServiceItem/serviceDLL' : {'category': 'Artifacts dropped','type': 'pattern-in-memory', 'comment': 'ServiceDll. '},
	'ServiceItem/description' : {'category': 'Artifacts dropped','type': 'comment', 'comment': 'ServiceDescription. '},
	'ServiceItem/descriptiveName' : {'category': 'Artifacts dropped','type': 'windows-service-displayname'},
	'ServiceItem/serviceDLLmd5sum': {'type': 'md5', 'category': 'Payload installation'},
	'ServiceItem/serviceDLLsha1sum': {'type': 'sha1', 'category': 'Payload installation'},
	'ServiceItem/serviceDLLsha256sum': {'type': 'sha256', 'category': 'Payload installation'},
	'ServiceItem/serviceDLLSignatureVerified' : {'category': 'Artifacts dropped','type': 'pattern-in-memory', 'comment': 'ServiceDllSignatureVerified. '},

	'Snort/Snort' : {'category': 'Network activity','type': 'snort'},

	'SystemInfoItem/HostName': {'type': 'hostname', 'comment': 'SystemInfo. '},

	'TaskItem/Name' : {'category': 'Artifacts dropped','type': 'windows-scheduled-task', 'comment': 'TaskName. '},
	'TaskItem/sha1sum' : {'category': 'Artifacts dropped','type': 'windows-scheduled-task', 'comment': 'TashSha1. '},
	'TaskItem/sha256sum' : {'category': 'Artifacts dropped','type': 'windows-scheduled-task', 'comment': 'TashSha256. '},
	'TaskItem/AccountName' : {'category': 'Artifacts dropped','type': 'windows-scheduled-task', 'comment': 'TaskAccountName'},
	'TaskItem/ActionList/Action/ExecProgramPath' : {'category': 'Artifacts dropped','type': 'windows-scheduled-task', 'comment': 'TaskExecProgramPath. '},
	'TaskItem/TriggerList/Trigger/TriggerFrequency' : {'category': 'Artifacts dropped','type': 'windows-scheduled-task', 'comment': 'TaskTriggerFrequency. '},

	'UrlHistoryItem/URL' : {'category': 'Payload delivery','type': 'url','comment': 'UrlHistory. '},
	'UrlHistoryItem/HostName': {'type': 'hostname','comment': 'UrlHistory. '},

	'Yara/Yara' : {'category': 'Artifacts dropped','type': 'yara'},

	# mapping for composite object
	# maybe later filename|sizeinbyte
	'FileItem/FileName|FileItem/Md5sum' : {'category': 'External analysis','type': 'filename|md5'},
	'FileItem/FileName|FileItem/Sha1sum' : {'category': 'External analysis','type': 'filename|sha1'},
	'FileItem/FileName|FileItem/Sha256sum' : {'category': 'External analysis','type': 'filename|sha256'},
	'Network/DNS|PortItem/remoteIP' : {'category': 'Network activity','type': 'domain|ip'},
	'PortItem/remoteIP|PortItem/remotePort' : {'category': 'Network activity', 'comment': 'ip-dst|port'},
	'RegistryItem/Path|RegistryItem/Value' : {'category': 'Artifacts dropped','type': 'regkey|value'},
	'RegistryItem/KeyPath|RegistryItem/Value' : {'category': 'Artifacts dropped','type': 'regkey|value'},
}


def extract_field(report, field_name):
	data = report.find(field_name.lower())
	if data and hasattr(data, 'text'):
		return data.text
	return None


def load_openioc_file(openioc_path):
	if not os.path.exists(openioc_path):
		raise Exception("Path doesn't exists.")
	with open(openioc_path, 'r') as f:
		return load_openioc(f)


def load_openioc(openioc):
	# Takes a opened file, or a string
	if not has_bs4:
		raise Exception('You need to install BeautifulSoup: pip install bs4')
	misp_event = MISPEvent()
	iocreport = BeautifulSoup(openioc, "html.parser")
	# Set event fields
	info = extract_field(iocreport, 'short_description')
	if info:
		misp_event.info = info
	date = extract_field(iocreport, 'authored_date')
	if date:
		misp_event.set_date(date)
	# Set special attributes
	description = extract_field(iocreport, 'description')
	if description:
		if not misp_event.info:
			misp_event.info = description
		else:
			misp_event.add_attribute('comment', description)
	if not misp_event.info:
		misp_event.info = 'OpenIOC import'
	author = extract_field(iocreport, 'authored_by')
	if author:
		misp_event.add_attribute('comment', author)
	misp_event = set_all_attributes(iocreport, misp_event)
	return misp_event


def get_mapping(openioc_type):
	t = openioc_type.lower()
	for k, v in iocMispMapping.items():
		if k.lower() == t:
			return v
	return False

def set_composite_values(value1, value2):
	attribute_values = {'comment': ''}
	
	# construct attribut composite type
	compositeMapping = value1.find('context')['search']+'|'+value2.find('context')['search']
	mapping = get_mapping(compositeMapping)
	if mapping:
		attribute_values.update(mapping)
	else:
		# prevent some mistake error
		attribute_values.update({'category': 'External analysis', 'type': 'other'})

	# construct attribut composite value
	compositeValue = value1.find('content').text + "|" +value2.find('content').text
	if compositeValue:
		attribute_values['value'] = compositeValue

	# construct composite comment
	compositeComment = ""
	if value1.find('comment'):
		compositeComment += value1.find('comment').text
	if value2.find('comment'):
		compositeComment += value2.find('comment').text
	attribute_values["comment"] = compositeComment
	
	return attribute_values

def set_all_attributes(openioc, misp_event):
	processed = set()
	hashName = ["FileItem/Md5sum","FileItem/Sha1sum","FileItem/Sha256sum"]
	
	# check for composite item
	for composite in openioc.find_all("indicator", operator="AND"):

		# check for composite number under
		childs = composite.find_all('indicatoritem')

		if len(childs) == 2:
			childList = [child.find('context')['search'] for child in childs]

			if ('FileItem/FileName' in childList) and\
				(set(hashName) - set(childList) != set(hashName)):
				if childs[0].find('context')['search'] == 'FileItem/FileName':
					value1, value2 = childs[0], childs[1]
				else:
					value1, value2 = childs[1], childs[0]

				attribute_values = set_composite_values(value1, value2)
				misp_event.add_attribute(**attribute_values)
				processed.add(childs[0]['id'])
				processed.add(childs[1]['id'])


			elif ("Network/DNS" and "PortItem/RemoteIP") in childList:
				if childs[0].find('context')['search'] == 'Network/DNS':
					value1, value2 = childs[0], childs[1]
				else:
					value1, value2 = childs[1], childs[0]

				attribute_values = set_composite_values(value1, value2)
				misp_event.add_attribute(**attribute_values)
				processed.add(childs[0]['id'])
				processed.add(childs[1]['id'])


			elif ("PortItem/RemoteIP" and "PortItem/RemotePort") in childList:
				if childs[0].find('context')['search'] == 'PortItem/RemoteIP':
					value1, value2 = childs[0], childs[1]
				else:
					value1, value2 = childs[1], childs[0]
				
				attribute_values = set_composite_values(value1, value2)
				misp_event.add_attribute(**attribute_values)
				processed.add(childs[0]['id'])
				processed.add(childs[1]['id'])


			elif ("RegistryItem/Path" and "RegistryItem/Value") in childList:
				if childs[0].find('context')['search'] == 'RegistryItem/PathP':
					value1, value2 = childs[0], childs[1]
				else:
					value1, value2 = childs[1], childs[0]

				attribute_values = set_composite_values(value1, value2)
				misp_event.add_attribute(**attribute_values)
				processed.add(childs[0]['id'])
				processed.add(childs[1]['id'])

	for item in openioc.find_all("indicatoritem"):
		# check if id in processed list
		if item['id'] in processed:
			continue
		attribute_values = {'comment': ''}
		if item.find('context'):
			mapping = get_mapping(item.find('context')['search'])
			if mapping:
				attribute_values.update(mapping)
			else:
				# Unknown mapping, assign to default
				attribute_values.update({'category': 'External analysis', 'type': 'other'})
				#continue
		else:
			continue
		value = extract_field(item, 'Content')
		if value:
			attribute_values['value'] = value
		else:
			# No value, ignoring
			continue
		comment = extract_field(item, 'Comment')
		if comment:
			attribute_values["comment"] = '{} {}'.format(attribute_values["comment"], comment)

		# change value to composite
		# 127.0.0.1:80 ip-* to 127.0.0.1|80 ip-*|port
		if mapping['type'] in ['ip-src', 'ip-dst'] and value.count(':') == 1:
			attribute_values['type'] = mapping['type'] + '|port'
			attribute_values['value'] = attribute_values['value'].replace(':', '|')
		misp_event.add_attribute(**attribute_values)

	return misp_event

if __name__ == '__main__':
	# test file for composite : https://github.com/fireeye/iocs/blob/master/BlogPosts/9cee306d-5441-4cd3-932d-f3119752634c.ioc
	x = open('test.ioc', 'r')
	mispEvent = load_openioc(x.read())
	print(mispEvent._json_full())
