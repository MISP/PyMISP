
# -*- coding: utf-8 -*-

import os

from .. import MISPEvent
try:
    from bs4 import BeautifulSoup
    has_bs4 = True
except ImportError:
    has_bs4 = False

iocMispMapping = {
    'CookieHistoryItem/HostName': {'type': 'hostname', 'comment': 'CookieHistory.'},

    'DriverItem/DriverName': {'category': 'Artifacts dropped', 'type': 'other', 'comment': 'DriverName.'},
    'DriverItem/CertificateIssuer': {'category': 'Artifacts dropped', 'type': 'other', 'comment': 'DriverCertificateIssuer.'},
    'DriverItem/DeviceItem/AttachedDeviceName': {'category': 'Artifacts dropped', 'type': 'other', 'comment': 'DriverDeviceName. '},

    'DnsEntryItem/Host': {'type': 'domain'},
    'DnsEntryItem/RecordName': {'type': 'domain'},

    'Email/To': {'type': 'target-email'},
    'Email/Date': {'type': 'comment', 'comment': 'EmailDate.'},
    'Email/Body': {'type': 'email-subject'},
    'Email/From': {'type': 'email-dst'},
    'Email/Subject': {'type': 'email-subject'},
    'Email/Attachment/Name': {'type': 'email-attachment'},

    'FileItem/Md5sum': {'type': 'md5'},
    'FileItem/Sha1sum': {'type': 'sha1'},
    'FileItem/FileName': {'type': 'filename'},
    'FileItem/FullPath': {'type': 'filename'},
    'FileItem/FilePath': {'type': 'filename'},
    'FileItem/Sha256sum': {'type': 'sha256'},
    'FileItem/DevicePath': {'type': 'comment', 'comment': 'DevicePath. '},
    'FileItem/SizeInBytes': {'type': 'size-in-bytes'},
    'FileItem/PEInfo/Type': {'type': 'comment', 'comment': 'PE Type. '},
    'FileItem/FileExtension': {'type': 'comment', 'comment': 'FileExtension. '},
    'FileItem/FilenameCreated': {'type': 'filename', 'comment': 'FilenameCreated. '},
    'FileItem/StringList/string': {'type': 'pattern-in-file', 'comment': 'string list. '},
    'FileItem/PEInfo/PETimeStamp': {'type': 'pattern-in-file', 'comment': 'PE TimeStamp. '},
    'FileItem/PEInfo/Exports/DllName': {'type': 'pattern-in-memory', 'comment': 'PE export DllName. '},
    'FileItem/PEInfo/Sections/Section/Name': {'type': 'pattern-in-memory', 'comment': 'PE SectionName. '},
    'FileItem/PEInfo/DetectedAnomalies/string': {'type': 'pattern-in-file', 'comment': 'PE DEtected AnomaliesString. '},
    'FileItem/PEInfo/Exports/NumberOfFunctions': {'type': 'pattern-in-file', 'comment': 'PE Export NumberOfFunctions. '},
    'FileItem/PEInfo/ImportedModules/Module/Name': {'type': 'pattern-in-file', 'comment': 'PE ImportedModulesName. '},
    'FileItem/PEInfo/DigitalSignature/Description': {'type': 'comment', 'comment': 'PE DigitalSignatureDescription. '},
    'FileItem/PEInfo/DigitalSignature/SignatureExists': {'type': 'comment', 'comment': 'PE SignatureExists. '},
    'FileItem/PEInfo/Exports/ExportedFunctions/string': {'type': 'comment', 'comment': 'PE ExportedFunctions. '},
    'FileItem/PEInfo/DigitalSignature/CertificateIssuer': {'type': 'comment', 'comment': 'PE SignatureCertificateIssuer. '},
    'FileItem/PEInfo/DigitalSignature/SignatureVerified': {'type': 'comment', 'comment': 'PE SignatureVerified. '},
    'FileItem/PEInfo/DigitalSignature/CertificateSubject': {'type': 'other', 'comment': 'PE CertificateDigitalSignatureSubject. '},
    'FileItem/PEInfo/ResourceInfoList/ResourceInfoItem/Name': {'type': 'comment', 'comment': 'PE ResourceName. '},
    'FileItem/PEInfo/ResourceInfoList/ResourceInfoItem/Type': {'type': 'comment', 'comment': 'PE ResourceType. '},
    'FileItem/PEInfo/VersionInfoList/VersionInfoItem/Language': {'type': 'pattern-in-file', 'comment': 'PE LanguageVersion. '},
    'FileItem/PEInfo/ResourceInfoList/ResourceInfoItem/Language': {'type': 'pattern-in-file', 'comment': 'PE LanguageResource. '},
    'FileItem/PEInfo/VersionInfoList/VersionInfoItem/CompanyName': {'type': 'pattern-in-file', 'comment': 'PE versionInfo CompanyName. '},
    'FileItem/PEInfo/VersionInfoList/VersionInfoItem/FileVersion': {'type': 'pattern-in-file', 'comment': 'PE Version. '},
    'FileItem/PEInfo/VersionInfoList/VersionInfoItem/ProductName': {'type': 'pattern-in-file', 'comment': 'PE ProductName. '},
    'FileItem/PEInfo/VersionInfoList/VersionInfoItem/InternalName': {'type': 'pattern-in-file', 'comment': 'PE InternalName. '},
    'FileItem/PEInfo/VersionInfoList/VersionInfoItem/LegalCopyright': {'type': 'pattern-in-file', 'comment': 'PE LegalCopyright. '},
    'FileItem/PEInfo/VersionInfoList/VersionInfoItem/ProductVersion': {'type': 'pattern-in-file', 'comment': 'PE ProductVersion. '},
    'FileItem/PEInfo/VersionInfoList/VersionInfoItem/FileDescription': {'type': 'comment', 'comment': 'PE FileDescription .'},
    'FileItem/PEInfo/ImportedModules/Module/ImportedFunctions/string': {'type': 'pattern-in-file', 'comment': 'PE ImportedModules. '},
    'FileItem/PEInfo/VersionInfoList/VersionInfoItem/OriginalFilename': {'type': 'pattern-in-file', 'comment': 'OriginalFilename of PE. '},

    'FormHistoryItem/HostName': {'type': 'hostname', 'comment': 'FormHistory. '},

    'Network/URI': {'type': 'uri'},
    'Network/DNS': {'type': 'domain'},
    'Network/String': {'type': 'url'},
    'Network/IPRange': {'type': 'ip-dst'},
    'Network/UserAgent': {'type': 'user-agent'},

    'PortItem/localIP': {'type': 'ip-src'},
    'PortItem/remoteIP': {'type': 'ip-dst'},
    'PortItem/remotePort': {'type': 'pattern-in-traffic', 'comment': 'RemotePort. '},

    'ProcessItem/name': {'type': 'pattern-in-memory', 'comment': 'ProcessName. '},
    'ProcessItem/path': {'type': 'pattern-in-memory', 'comment': 'ProcessPath. '},
    'ProcessItem/Mutex': {'type': 'mutex', 'comment': 'mutex'},
    'ProcessItem/arguments': {'type': 'pattern-in-memory', 'comment': 'ProcessArguments. '},
    'ProcessItem/NamedPipe': {'type': 'named pipe'},
    'ProcessItem/Pipe/Name': {'type': 'named pipe'},
    'ProcessItem/Mutex/Name': {'type': 'mutex', 'comment': 'MutexName. '},
    'ProcessItem/Event/Name': {'type': 'pattern-in-memory', 'comment': 'ProcessEventName. '},
    'ProcessItem/StringList/string': {'type': 'pattern-in-memory', 'comment': 'StringlistName. '},
    'ProcessItem/HandleList/Handle/Name': {'type': 'pattern-in-memory', 'comment': 'ProcessHandleListName'},
    'ProcessItem/HandleList/Handle/Type': {'type': 'pattern-in-memory', 'comment': 'ProcessHandleType'},
    'ProcessItem/SectionList/MemorySection/Name': {'type': 'pattern-in-memory', 'comment': 'ProcessSectionMemoryName'},
    'ProcessItem/SectionList/MemorySection/PEInfo/Exports/DllName': {'type': 'pattern-in-memory', 'comment': 'ProcessMemoryPEExportsDllName'},
    'ProcessItem/SectionList/MemorySection/PEInfo/Sections/Section/Name': {'type': 'pattern-in-memory', 'comment': 'Section name from PE in process memory section'},

    'RegistryItem/Text': {'type': 'regkey', 'comment': 'RegistryText. '},
    'RegistryItem/Path': {'type': 'regkey', 'comment': 'RegistryPath. '},
    'RegistryItem/Value': {'type': 'regkey', 'comment': 'RegistryValue. '},
    'RegistryItem/KeyPath': {'type': 'regkey', 'comment': 'RegistryKeyPath. '},
    'RegistryItem/ValueName': {'type': 'regkey', 'comment': 'RegistryValueName. '},

    'RouteEntryItem/Destination': {'type': 'ip-dst'},
    'RouteEntryItem/Destination/IP': {'type': 'ip-dst', 'comment': 'RouteDestination. '},
    'RouteEntryItem/Destination/string': {'type': 'url', 'comment': 'RouteDestination. '},


    'ServiceItem/name': {'type': 'windows-service-name'},
    'ServiceItem/type': {'type': 'pattern-in-memory', 'comment': 'ServiceType. '},
    'ServiceItem/startedAs': {'type': 'pattern-in-memory', 'comment': 'ServiceStartedAs. '},
    'ServiceItem/serviceDLL': {'type': 'pattern-in-memory', 'comment': 'ServiceDll. '},
    'ServiceItem/description': {'type': 'comment', 'comment': 'ServiceDescription. '},
    'ServiceItem/descriptiveName': {'type': 'windows-service-displayname'},
    'ServiceItem/serviceDLLmd5sum': {'type': 'md5', 'comment': 'ServiceDLL. '},
    'ServiceItem/serviceDLLsha1sum': {'type': 'sha1', 'comment': 'ServiceDLL. '},
    'ServiceItem/serviceDLLsha256sum': {'type': 'sha256', 'comment': 'ServiceDLL. '},
    'ServiceItem/serviceDLLSignatureVerified': {'type': 'pattern-in-memory', 'comment': 'ServiceDllSignatureVerified. '},

    'Snort/Snort': {'type': 'snort'},

    'SystemInfoItem/HostName': {'type': 'hostname', 'comment': 'SystemInfo. '},

    'TaskItem/Name': {'type': 'windows-scheduled-task', 'comment': 'TaskName. '},
    'TaskItem/sha1sum': {'type': 'windows-scheduled-task', 'comment': 'TashSha1. '},
    'TaskItem/sha256sum': {'type': 'windows-scheduled-task', 'comment': 'TashSha256. '},
    'TaskItem/AccountName': {'type': 'windows-scheduled-task', 'comment': 'TaskAccountName'},
    'TaskItem/ActionList/Action/ExecProgramPath': {'type': 'windows-scheduled-task', 'comment': 'TaskExecProgramPath. '},
    'TaskItem/TriggerList/Trigger/TriggerFrequency': {'type': 'windows-scheduled-task', 'comment': 'TaskTriggerFrequency. '},

    'UrlHistoryItem/URL': {'type': 'url', 'comment': 'UrlHistory. '},
    'UrlHistoryItem/HostName': {'type': 'hostname', 'comment': 'UrlHistory. '},

    'Yara/Yara': {'type': 'yara'}
}

iocMispCompositeMapping = {
    # mapping for composite object
    # maybe later filename|sizeinbyte
    'FileItem/FileName|FileItem/Md5sum': {'type': 'filename|md5'},
    'FileItem/FileName|FileItem/Sha1sum': {'type': 'filename|sha1'},
    'FileItem/FileName|FileItem/Sha256sum': {'type': 'filename|sha256'},
    'Network/DNS|PortItem/remoteIP': {'type': 'domain|ip'},
    'PortItem/remoteIP|PortItem/remotePort': {'type': 'ip-dst|port'},
    'RegistryItem/Path|RegistryItem/Value': {'type': 'regkey|value'},
    'RegistryItem/KeyPath|RegistryItem/Value': {'type': 'regkey|value'},
    'RegistryItem/Path|RegistryItem/Text': {'type': 'regkey|value'}
}


def extract_field(report, field_name):
    if report:
        data = report.find(field_name.lower())
        if data and hasattr(data, 'text'):
            return data.text
    return ''


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


def get_mapping(openioc_type, mappingDict=iocMispMapping):
    t = openioc_type.lower()
    for k, v in mappingDict.items():
        if k.lower() == t:
            return v
    return False


def set_values(value1, value2=None):
    attribute_values = {}

    if value2 is not None:
        # construct attribut composite value
        value = "{}|{}".format(extract_field(value1, 'Content'),
                               extract_field(value2, 'Content')
                               )
    else:
        value = extract_field(value1, 'Content')

    if value:
        attribute_values['value'] = value
    else:
        return None

    if value2 is not None:
        # construct attribut composite type
        compositeMapping = '{}|{}'.format(value1.find('context')['search'], value2.find('context')['search'])
        mapping = get_mapping(compositeMapping, mappingDict=iocMispCompositeMapping)
    else:
        mapping = get_mapping(value1.find('context')['search'])

    if mapping:
        attribute_values.update(mapping)
    else:
        # Unknown mapping, assign to default
        attribute_values['category'] = 'External analysis'
        attribute_values['type'] = 'other'

    # change value to composite
    # 127.0.0.1:80 ip-* to 127.0.0.1|80 ip-*|port
    if attribute_values['type'] in ['ip-src', 'ip-dst'] and attribute_values['value'].count(':') == 1:
        attribute_values['type'] = attribute_values['type'] + '|port'
        attribute_values['value'] = attribute_values['value'].replace(':', '|')

    attribute_values["comment"] = '{}{}'.format(extract_field(value1, 'Comment'),
                                                extract_field(value2, 'Comment')
                                                )

    return attribute_values


def set_all_attributes(openioc, misp_event):
    processed = set()

    # check for composite item
    for composite in openioc.find_all("indicator", operator="AND"):

        # check for composite number under
        childs = composite.find_all('indicatoritem')

        if len(childs) == 2:
            childList = [child.find('context')['search'] for child in childs]

            def check_and_add(value1, value2):
                if (value1 and value2) in childList:
                    if childs[0].find('context')['search'] == value1:
                        attribute_values = set_values(childs[0], childs[1])
                    else:
                        attribute_values = set_values(childs[1], childs[0])

                    misp_event.add_attribute(**attribute_values)
                    processed.add(childs[0]['id'])
                    processed.add(childs[1]['id'])

            for k in iocMispCompositeMapping:
                check_and_add(k.split('|')[0], k.split('|')[1])

    for item in openioc.find_all("indicatoritem"):
        # check if id in processed list
        if item['id'] in processed:
            continue
        attribute_values = set_values(item)

        if attribute_values is None:
            continue

        misp_event.add_attribute(**attribute_values)

    return misp_event
