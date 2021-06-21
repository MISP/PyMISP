#!/usr/bin/env python
# -*- coding: utf-8 -*-

mispUrl = ''
mispKey = ''

###############################
# file use for internal tag
# some sample can be find here : 
#	https://github.com/eset/malware-ioc
#	https://github.com/fireeye/iocs
csvTaxonomyFile = "taxonomy.csv"

# csv delimiter : ";" with quotechar : "

###############################
# link sample
	#~ <links>
		#~ <link rel="threatcategory">APT</link>
		#~ <link rel="threatgroup">APT12</link>
		#~ <link rel="category">Backdoor</link>
		#~ <link rel="license">Apache 2.0</link>
	#~ </links>

#	@link from csv
#		= rel attribut from <link>
#	@value from csv
#		= value 
#	@keep
#		0 : don't create tag
#		1 : tag created
#	@taxonomy
#		define tag for misp
#	@comment
#		litte description but not use


#########################################
# https://www.circl.lu/doc/misp/categories-and-types/index.html
#	/\
#	||
#	||
#	\/
# http://schemas.mandiant.com/

# @index = Context/search form ioc
# @(1, 2, 3)
#	1. categorie mapping
#	2. type mapping
#	3. optionnal comment


iocMispMapping = {
				
				('DriverItem/DriverName') : (u'Artifacts dropped',u'other', u'DriverName. '),
				
				('DnsEntryItem/Host') : (u'Network activity',u'domain'),
				
				('Email/To') : (u'Targeting data',u'target-email'),
				('Email/Date') : (u'Other',u'comment',u'EmailDate. '),
				('Email/Body') : (u'Payload delivery',u'email-subject'),
				('Email/From') : (u'Payload delivery',u'email-dst'),
				('Email/Subject') : (u'Payload delivery',u'email-subject'),
				('Email/Attachment/Name') : (u'Payload delivery',u'email-attachment'),
				  
				('FileItem/Md5sum') : (u'External analysis',u'md5'),
				('FileItem/Sha1sum') : (u'External analysis',u'sha1'),
				('FileItem/FileName') : (u'External analysis',u'filename'),
				('FileItem/FullPath') : (u'External analysis',u'filename'),
				('FileItem/FilePath') : (u'External analysis',u'filename'),
				('FileItem/Sha256sum') : (u'External analysis',u'sha256'),
				
				('Network/URI') : (u'Network activity',u'uri'),
				('Network/DNS') : (u'Network activity',u'domain'),
				('Network/String') : (u'Network activity',u'ip-dst'),
				('Network/UserAgent') : (u'Network activity',u'user-agent'),
				
				('PortItem/localIP') : (u'Network activity',u'ip-dst'),
				
				('ProcessItem/name') : (u'External analysis',u'pattern-in-memory', u'ProcessName. '),
				('ProcessItem/path') : (u'External analysis',u'pattern-in-memory', u'ProcessPath. '),
				('ProcessItem/Mutex') : (u'Artifacts dropped',u'mutex', u'mutex'),
				('ProcessItem/Pipe/Name') : (u'Artifacts dropped',u'named pipe'),
				('ProcessItem/Mutex/Name') : (u'Artifacts dropped',u'mutex', u'MutexName. '),
				
				('RegistryItem/Text') : (u'Artifacts dropped',u'regkey', u'RegistryText. '),
				('RegistryItem/Path') : (u'Artifacts dropped',u'regkey', u'RegistryPath. '),
				
				('ServiceItem/name') : (u'Artifacts dropped',u'windows-service-name'),
				('ServiceItem/type') : (u'Artifacts dropped',u'pattern-in-memory', u'ServiceType. '),
				
				('Snort/Snort') : (u'Network activity',u'snort'),
				
				}
