#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import MISPEvent
try:
    from bs4 import BeautifulSoup
    has_bs4 = True
except ImportError:
    has_bs4 = False


iocMispMapping = {
    'DriverItem/DriverName': {'category': 'Artifacts dropped', 'type': 'other', 'comment': 'DriverName.'},

    'DnsEntryItem/Host': {'type': 'domain'},

    'Email/To': {'type': 'target-email'},
    'Email/Date': {'type': 'comment', 'comment': 'EmailDate.'},
    # 'Email/Body': {'type': 'email-subject'},
    'Email/From': {'type': 'email-dst'},
    'Email/Subject': {'type': 'email-subject'},
    'Email/Attachment/Name': {'type': 'email-attachment'},

    'FileItem/Md5sum': {'type': 'md5'},
    'FileItem/Sha1sum': {'type': 'sha1'},
    'FileItem/Sha256sum': {'type': 'sha256'},

    'ServiceItem/serviceDLLmd5sum': {'type': 'md5', 'category': 'Payload installation'},
    'ServiceItem/serviceDLLsha1sum': {'type': 'sha1', 'category': 'Payload installation'},
    'ServiceItem/serviceDLLsha256sum': {'type': 'sha256', 'category': 'Payload installation'},

    'TaskItem/md5sum': {'type': 'md5'},
    'TaskItem/sha1sum': {'type': 'sha1'},
    'TaskItem/Sha256sum': {'type': 'sha256'},

    'FileItem/FileName': {'type': 'filename'},
    'FileItem/FullPath': {'type': 'filename'},
    'FileItem/FilePath': {'type': 'filename'},
    'DriverItem/DriverName': {'type': 'filename'},

    'Network/URI': {'type': 'uri'},
    'Network/DNS': {'type': 'domain'},
    'Network/String': {'type': 'ip-dst'},
    'RouteEntryItem/Destination': {'type': 'ip-dst'},
    'Network/UserAgent': {'type': 'user-agent'},

    'PortItem/localIP': {'type': 'ip-src'},
    'PortItem/remoteIP': {'type': 'ip-dst'},

    'ProcessItem/name': {'type': 'pattern-in-memory', 'comment': 'ProcessName.'},
    'ProcessItem/path': {'type': 'pattern-in-memory', 'comment': 'ProcessPath.'},
    'ProcessItem/Mutex': {'type': 'mutex'},
    'ProcessItem/Pipe/Name': {'type': 'named pipe'},
    'ProcessItem/Mutex/Name': {'type': 'mutex', 'comment': 'MutexName.'},

    'CookieHistoryItem/HostName': {'type': 'hostname'},
    'FormHistoryItem/HostName': {'type': 'hostname'},
    'SystemInfoItem/HostName': {'type': 'hostname'},
    'UrlHistoryItem/HostName': {'type': 'hostname'},
    'DnsEntryItem/RecordName': {'type': 'hostname'},
    'DnsEntryItem/Host': {'type': 'hostname'},

    # Is it the regkey value?
    # 'RegistryItem/Text': {'type': 'regkey', 'RegistryText. '},
    'RegistryItem/KeyPath': {'type': 'regkey'},
    'RegistryItem/Path': {'type': 'regkey'},

    'ServiceItem/name': {'type': 'windows-service-name'},
    'ServiceItem/type': {'type': 'pattern-in-memory', 'comment': 'ServiceType. '},

    'Snort/Snort': {'type': 'snort'},
}


def extract_field(report, field_name):
    data = report.find(field_name.lower())
    if data and hasattr(data, 'text'):
        return data.text
    return None


def load_openioc(openioc):
    if not has_bs4:
        raise Exception('You need to install BeautifulSoup: pip install bs4')
    misp_event = MISPEvent()
    with open(openioc, "r") as ioc_file:
        iocreport = BeautifulSoup(ioc_file, "lxml")
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
            misp_event.add_attribute('comment', description)
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


def set_all_attributes(openioc, misp_event):
    for item in openioc.find_all("indicatoritem"):
        attribute_values = {'comment': ''}
        if item.find('context'):
            mapping = get_mapping(item.find('context')['search'])
            if mapping:
                attribute_values.update(mapping)
            else:
                # Unknown mapping, ignoring
                # print(item.find('context'))
                continue
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
        misp_event.add_attribute(**attribute_values)
    return misp_event
