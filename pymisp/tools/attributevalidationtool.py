#!/usr/bin/env python3

import ipaddress
import json
import logging
import re
from base64 import b64decode
from datetime import datetime
from dateutil.parser import parse
from pymisp import MISPAttribute, MISPEvent, MISPObject
from typing import Generator
from urllib.parse import urlparse

HASH_HEX_LENGTH = {
    'authentihash': 64,
    'md5': 32,
    'imphash': 32,
    'telfhash': 70,
    'sha1': 40,
    'git-commit-id': 40,
    'x509-fingerprint-md5': 32,
    'x509-fingerprint-sha1': 40,
    'x509-fingerprint-sha256': 64,
    'ja3-fingerprint-md5': 32,
    'jarm-fingerprint': 62,
    'hassh-md5': 32,
    'hasshserver-md5': 32,
    'pehash': 40,
    'sha224': 56,
    'sha256': 64,
    'sha384': 96,
    'sha512': 128,
    'sha512/224': 56,
    'sha512/256': 64,
    'sha3-224': 56,
    'sha3-256': 64,
    'sha3-384': 96,
    'sha3-512': 128,
    'dom-hash': 32,
}
HTTP_METHODS = (
    'OPTIONS', 'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'TRACE', 'CONNECT',
    'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK',
    'VERSION-CONTROL', 'REPORT', 'CHECKOUT', 'CHECKIN', 'UNCHECKOUT',
    'MKWORKSPACE', 'UPDATE', 'LABEL', 'MERGE', 'BASELINE-CONTROL',
    'MKACTIVITY', 'ORDERPATCH', 'ACL', 'PATCH', 'SEARCH'
)
REFANG_REGEX_TABLE = (
    {
        'from': re.compile(r'^(hxxp|hxtp|htxp|meow|h\[tt\]p)', re.IGNORECASE),
        'to': 'http',
        'types': ('link', 'url')
    },
    {
        'from': re.compile(r'(\[\.\]|\[dot\]|\(dot\))', re.IGNORECASE),
        'to': '.',
        'types': (
            'link', 'url', 'ip-dst', 'ip-src', 'domain|ip', 'domain',
            'hostname', 'email', 'email-src', 'email-dst'
        )
    },
    {
        'from': re.compile(r'\[hxxp:\/\/\]', re.IGNORECASE),
        'to': 'http',
        'types': ('link', 'url')
    },
    {
        'from': re.compile(r'\[\@\]|\[at\]', re.IGNORECASE),
        'to': '@',
        'types': ('email', 'email-src', 'email-dst')
    },
    {
        'from': re.compile(r'\[:\]'),
        'to': ':',
        'types': ('link', 'url')
    }
)
VULNERABILITY_REGEXES = (
    r'CVE-\d{4}-\d{4,}',
    r'GCVE-\d+-\d{4}-\d+',
    r'fkie_cve-\d{4}-\d{4,}',
    r'ghsa-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}',
    r'pysec-\d{4}-\d{2,5}',
    r'gsd-\d{4}-\d{4,5}',
    r'mal-\d{4}-\d+',
    r'wid-sec-w-\d{4}-\d{4}',
    r'ncsc-\d{4}-\d{4}',
    r'ssa-\d{6}',
    r'rh(ba|ea|sa)-\d{4}:\d{4,}',
    r'ics(ma|a)-\d{2}-\d{3}-\d{2}',
    r'va-\d{2}-\d{3}-\d{2}',
    r'cisco-sa(-[a-zA-Z0-9_]+)+',
    r'sca-\d{4}-\d{4,}',
    r'nn-\d{4}[:_]\d-\d{2}',
    r'oxas-adv-\d{4}-\d{4}',
    r'msrc_cve-\d{4}-\d{4,}',
    r'var-\d{6}-\d{4}',
    r'jvndb-\d{4}-\d{6}',
    r'ts-\d{4}-\d{4}',
    r'(open)?suse-su-\d{4}:\d{4,}-\d',
    r'cnvd-\d{4}-\d{5}',
    r'certfr-\d{4}-avi-\d{4}',
    r'certfr-\d{4}-ale-\d{3}'
)

CDHASH_RE = re.compile(r'^[0-9a-f]{40,}$')
EMAIL_RE = re.compile(r'^.[^\s]*\@.*\..*$', flags=re.IGNORECASE)
DOMAIN_RE = re.compile(r'^[A-Z0-9.\-_]+\.[A-Z0-9\-]{2,}$', flags=re.IGNORECASE)
HEX_RE = re.compile(r'^[0-9a-fA-F]+$')
MAC_ADDRESS_RE = re.compile(r'^([a-f0-9]{2}:){5}[a-f0-9]{2}$')
MAC_EUI_64_RE = re.compile(r'^([a-f0-9]{2}:){3}ff:fe:(:[a-f0-9]{2}){3}$')
ONION_RE = re.compile(r'^([a-z2-7]{16}|[a-z2-7]{56})\.onion$')
REMOVE_NON_ALPHANUM_CAP_RE = re.compile(r'[^0-9A-Z]+')
REMOVE_NON_ALPHANUM_RE = re.compile(r'[^0-9A-Fa-f]')
REMOVE_NON_NUM_RE = re.compile(r'[^0-9]+')
REMOVE_PHONE_PARENTHESIS_RE = re.compile(r'\(0\)')
SANITISE_PHONE_NUMBER_RE = re.compile(r'[^\+0-9]+')
SSDEEP_RE = re.compile(r'^([0-9]+):([0-9a-zA-Z/+]*):([0-9a-zA-Z/+]*)$')
UUID_RE = re.compile(r'[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$')
VULNERABILITY_RE = re.compile(
    r'^(?:' + '|'.join(VULNERABILITY_REGEXES) + r')$', flags=re.IGNORECASE
)
WEAKNESS_RE = re.compile(r"^CWE-[0-9]+$", flags=re.IGNORECASE)

logger = logging.getLogger('pymisp')


class AttributeValidationTool:
    @classmethod
    def modifyBeforeValidation(cls, attribute_type, value):
        if isinstance(value, str):
            value = cls._refang_value(attribute_type, value.strip())
        match attribute_type:
            case ('ip-src' | 'ip-dst'):
                return cls._normalise_ip(value)
            case ('md5' | 'sha1' | 'sha224' | 'sha256' | 'sha384' | 'sha512' |
                  'sha512/224' | 'sha512/256' | 'sha3-224' | 'sha3-256' |
                  'sha3-384' | 'sha3-512' | 'ja3-fingerprint-md5' |
                  'jarm-fingerprint' | 'hassh-md5' | 'hasshserver-md5' |
                  'hostname' | 'pehash' | 'authentihash' | 'vhash' | 'imphash' |
                  'telfhash' | 'tlsh' | 'anonymised' | 'cdhash' | 'email' |
                  'email-src' | 'email-dst' | 'target-email' |
                  'whois-registrant-email' | 'dom-hash' | 'onion-address'):
                return value.lower()
            case 'domain':
                value = value.lower().strip('.')
                # Domain is not valid, try to convert to punycode
                if not cls._is_domain_valid(value):
                    return value.encode('idna').decode('ascii')
                return value
            case 'domain|ip':
                parts = value.lower().split('|')
                if len(parts) != 2:
                    return value # not a composite
                domain, ip = parts
                domain = domain.strip('.')
                # Domain is not valid, try to convert to punycode
                if not cls._is_domain_valid(domain):
                    domain = domain.encode('idna').decode('ascii')
                return f'{domain}|{cls._normalise_ip(ip)}'
            case ('filename|md5' | 'filename|sha1' | 'filename|imphash' |
                  'filename|sha224' | 'filename|sha256' | 'filename|sha384' |
                  'filename|sha512' | 'filename|sha512/224' |
                  'filename|sha512/256' | 'filename|sha3-224' |
                  'filename|sha3-256' | 'filename|sha3-384' |
                  'filename|sha3-512' | 'filename|authentihash' |
                  'filename|vhash' | 'filename|pehash' | 'filename|tlsh'):
                # Convert hash to lowercase
                composite = value.split('|')
                if len(composite) != 2:
                    return value # not a composite
                filename, _hash = composite
                return f'{filename}|{_hash.lower()}'
            case 'http-method' | 'hex':
                return value.upper()
            case 'vulnerability':
                value = value.replace('–', '-')
                source = value.split('-')[0]
                if source in ('cve', 'gcve'):
                    return value.upper()
                return value
            case 'weakness':
                return value.replace('–', '-').upper()
            case 'cc-number' | 'bin':
                return re.sub(REMOVE_NON_NUM_RE, '', value)
            case 'iban' | 'bic':
                return re.sub(REMOVE_NON_ALPHANUM_CAP_RE, '', value.upper())
            case 'prtn' | 'whois-registrant-phone' | 'phone-number':
                if value.startswith('00'):
                    value = f'+{value[2:]}'       
                value = re.sub(REMOVE_PHONE_PARENTHESIS_RE, '', value)
                return re.sub(SANITISE_PHONE_NUMBER_RE, '', value)
            case 'x509-fingerprint-md5' | 'x509-fingerprint-sha256' | 'x509-fingerprint-sha1':
                return value.replace(':', '').lower()
            case 'ip-dst|port' | 'ip-src|port':
                if value.count(':') >= 2: # (ipv6|port) - tokenize ip and port
                    if '|' in value: # 2001:db8::1|80
                        ip, port = value.split('|', 1)
                        return f'{cls._normalise_ip(ip)}|{port}'
                    if value.startswith('[') and ']' in value: # [2001:db8::1]:80
                        ip, port = value[1:].split(']', 1)
                        return f'{cls._normalise_ip(ip)}|{port.lstrip(":")}'
                    for separator in ('.', ' port ', 'p', '#'):
                        if separator in value:
                            ip, port = value.split(separator, 1)
                            return f'{cls._normalise_ip(ip)}|{port}'
                    # 2001:db8::1:80 this one is ambiguous
                    *parts, port = value.split(':')
                    return f'{cls._normalise_ip(":".join(parts))}|{port}'
                for separator in (':', '|'):
                    if separator in value: # ipv4:port or ipv4|port
                        ip, port = value.split(separator, 1)
                        return f'{cls._normalise_ip(ip)}|{port}'
                return value
            case 'mac-address' | 'mac-eui-64':
                value = re.sub(REMOVE_NON_ALPHANUM_RE, '', value).lower()
                return ':'.join(value[i:i+2] for i in range(0, 12, 2))
            case 'hostname|port':
                return value.replace(':', '|').lower()
            case 'boolean':
                if isinstance(value, int):
                    return bool(value)
                if isinstance(value, str):
                    value = value.lower()
                    if value == 'true':
                        return True
                    if value == 'false':
                        return False
                return value
            case 'datetime':
                if isinstance(value, str):
                    try:
                        return datetime.fromisoformat(value)
                    except ValueError:
                        try:
                            return parse(value)
                        except Exception:
                            return value
                return value
            case 'AS':
                if value.upper().startswith('AS'):
                    value = value[2:] # remove 'AS'
                if '.' in value: # maybe value is in asdot notation
                    multiplier, remainder = value.split('.', 1)
                    if cls._is_positive_integer(multiplier) and cls._is_positive_integer(remainder):
                        return int(multiplier) * 65536 + int(remainder)
                return value
            case _:
                return value

    @classmethod
    def validate(cls, attribute_type, value):
        match attribute_type:
            case ('md5' | 'imphash' | 'sha1' | 'sha224' | 'sha256' | 'sha384' |
                  'sha512' | 'sha512/224' | 'sha512/256' | 'sha3-224' |
                  'sha3-256' | 'sha3-384' | 'sha3-512' | 'authentihash' |
                  'ja3-fingerprint-md5' | 'jarm-fingerprint' | 'hassh-md5' |
                  'hasshserver-md5' | 'x509-fingerprint-md5' |
                  'x509-fingerprint-sha256' | 'x509-fingerprint-sha1' |
                  'git-commit-id' | 'dom-hash'):
                if cls._is_hash_valid(attribute_type, value):
                    return True
                length = HASH_HEX_LENGTH[attribute_type]
                return (
                    'Checksum has an invalid length or format (expected: '
                    f'{length} hexadecimal characters). Please double check '
                    'the value or select type "other".'
                )
            case 'tlsh':
                if cls._is_tlsh_valid(value):
                    return True
                return (
                    'Checksum has an invalid length or format (expected: at '
                    'least 35 hexadecimal characters, optionally starting '
                    'with t1 instead of hexadecimal characters). Please '
                    'double check the value or select type "other".'
                )
            case 'telfhash':
                if cls._is_telfhash_valid(value):
                    return True
                return (
                    'Checksum has an invalid length or format (expected: '
                    '70 or 72 hexadecimal characters). Please double check '
                    'the value or select type "other".'
                )
            case 'pehash':
                if cls._is_hash_valid('pehash', value):
                    return True
                return (
                    "The input doesn't match the expected sha1 format "
                    '(expected: 40 hexadecimal characters). Keep in mind that '
                    'MISP currently only supports SHA1 for PEhashes, if you '
                    'would like to get the support extended to other hash '
                    'types, make sure to create a github ticket about it at '
                    'https://github.com/MISP/MISP!'
                )
            case 'ssdeep':
                if cls._is_ssdeep(value):
                    return True
                return 'Invalid SSDeep hash. The format has to be blocksize:hash:hash'
            case 'impfuzzy':
                if value.count(':') == 2:
                    imports, *_ = value.split(':')
                    if cls._is_positive_integer(imports):
                        return True
                return 'Invalid impfuzzy format. The format has to be imports:hash:hash'
            case 'cdhash':
                if CDHASH_RE.fullmatch(value):
                    return True
                return (
                    "The input doesn't match the expected format "
                    '(expected: 40 or more hexadecimal characters)'
                )
            case 'http-method':
                if value in HTTP_METHODS:
                    return True
                return 'Unknown HTTP method.'
            case 'filename|pehash':
                if re.fullmatch(r'^.+\|[0-9a-f]{40}$#', value):
                    return True
                return (
                    "The input doesn't match the expected filename|sha1 format "
                    '(expected: filename|40 hexadecimal characters). Keep in '
                    'mind that MISP currently only supports SHA1 for PEhashes, '
                    'if you would like to get the support extended to other '
                    'hash types, make sure to create a github ticket about it '
                    'at https://github.com/MISP/MISP!'
                )
            case ('filename|md5' | 'filename|sha1' | 'filename|imphash' |
                  'filename|sha224' | 'filename|sha256' | 'filename|sha384' |
                  'filename|sha512' | 'filename|sha512/224' |
                  'filename|sha512/256' | 'filename|sha3-224' |
                  'filename|sha3-256' | 'filename|sha3-384' |
                  'filename|sha3-512' | 'filename|authentihash'):
                length = HASH_HEX_LENGTH[attribute_type[9:]] # strip `filename|`]
                if re.fullmatch(r'^.+\|[0-9a-f]{' + str(length) + r'}$', value):
                    return True
                return (
                    'Checksum has an invalid length or format (expected:'
                    f'filename|{length} hexadecimal characters). Please'
                    'double check the value or select type "other".'
                )
            case 'filename|ssdeep':
                composite = value.split('|')
                if len(composite) == 2:
                    filename, ssdeep = composite
                    if '\n' in filename:
                        return 'Filename must not contain new line character.'
                    if cls._is_ssdeep(ssdeep):
                        return True
                return 'Invalid ssdeep hash (expected: blocksize:hash:hash).'
            case 'filename|tlsh':
                composite = value.split('|')
                if len(composite) == 2:
                    filename, tlsh = composite
                    if '\n' in filename:
                        return 'Filename must not contain new line character.'
                    if cls._is_tlsh_valid(tlsh):
                        return True
                return (
                    'TLSH hash has an invalid length or format (expected: '
                    'filename|at least 35 hexadecimal characters, optionally '
                    'starting with t1 instead of hexadecimal characters). '
                    'Please double check the value or select type "other".'
                )
            case 'filename|vhash':
                if re.fullmatch(r'^.+\|.+$', value):
                    return True
                return (
                    'Checksum has an invalid length or format (expected: '
                    'filename|string characters). Please double check the '
                    'value or select type "other".'
                )
            case 'ip-src' | 'ip-dst':
                return cls._validate_ip(value)
            case 'port':
                if cls._is_port_valid(value):
                    return True
                return 'Port numbers have to be integers between 1 and 65535.'
            case 'ip-dst|port' | 'ip-src|port':
                composite = value.split('|')
                if len(composite) != 2:
                    return 'Invalid ip-dst|port format.'
                ip, port = composite
                if not cls._is_port_valid(port):
                    return 'Port numbers have to be integers between 1 and 65535.'
                return cls._validate_ip(ip)
            case 'onion-address':
                if ONION_RE.fullmatch(value):
                    return True
                return 'Onion address has an invalid format.'
            case 'mac-address':
                if MAC_ADDRESS_RE.fullmatch(value):
                    return True
                return 'MAC address has an invalid format.'
            case 'mac-eui-64':
                if MAC_EUI_64_RE.fullmatch(value):
                    return True
                return 'MAC EUI-64 address has an invalid format.'
            case 'hostname' | 'domain':
                if cls._is_domain_valid(value):
                    return True
                return (
                    f'{attribute_type.capitalize()} has an invalid format. '
                    'Please double check the value or select type "other".'
                )
            case 'hostname|port':
                composite = value.split('|')
                if len(composite) != 2:
                    return 'Invalid hostname|port format.'
                hostname, port = composite
                if not cls._is_domain_valid(hostname):
                    return 'Hostname has an invalid format.'
                if not cls._is_port_valid(port):
                    return 'Port numbers have to be integers between 1 and 65535.'
                return True
            case 'domain|ip':
                composite = value.split('|')
                if len(composite) != 2:
                    return 'Invalid domain|ip format.'
                domain, ip = composite
                if not cls._is_domain_valid(domain):
                    return 'Domain has an invalid format.'
                return cls._validate_ip(ip)
            case ('email' | 'email-src' | 'eppn' | 'email-dst' | 'target-email' |
                  'whois-registrant-email' | 'dns-soa-email' | 'jabber-id'):
                # we don't use the native function to prevent issues with partial email addresses
                if EMAIL_RE.fullmatch(value):
                    return True
                return (
                    'Email address has an invalid format. Please double '
                    'check the value or select type "other".'
                )
            case 'vulnerability':
                if VULNERABILITY_RE.fullmatch(value):
                    return True
                return 'Invalid vulnerability ID format.'
            case 'weakness':
                if WEAKNESS_RE.fullmatch(value):
                    return True
                return 'Invalid format. Expected: CWE-x...'
            case 'windows-service-name' | 'windows-service-displayname':
                if len(value) > 256 or re.search(r'[\\/]', value):
                    return (
                        'Invalid format. Only values shorter than 256 characters '
                        "that don't include any forward or backward slashes are allowed."
                    )
                return True
            case ('mutex' | 'process-state' | 'snort' | 'bro' | 'zeek' |
                  'community-id' | 'anonymised' | 'pattern-in-file' |
                  'pattern-in-traffic' | 'pattern-in-memory' | 'filename-pattern' |
                  'pgp-public-key' | 'pgp-private-key' | 'yara' | 'stix2-pattern' |
                  'sigma' | 'gene' | 'kusto-query' | 'mime-type' |
                  'identity-card-number' | 'cookie' | 'attachment' |
                  'malware-sample' | 'comment' | 'text' | 'other' | 'cpe' |
                  'email-attachment' | 'email-body' | 'email-header' |
                  'first-name' | 'middle-name' | 'last-name' | 'full-name'):
                return True
            case 'link':
                parsed = urlparse(value)
                if all([parsed.scheme, parsed.netloc]):
                    return True
                return 'Link has to be a valid URL.'
            case 'hex':
                if HEX_RE.fullmatch(value):
                    return True
                return 'Value has to be a hexadecimal string.'
            case ('target-user' | 'campaign-name' | 'campaign-id' |
                  'threat-actor' | 'target-machine' | 'target-org' |
                  'target-location' | 'target-external' | 'email-subject' |
                  'malware-type' | 'url' | 'uri' | 'user-agent' | 'regkey' |
                  'regkey|value' | 'filename' | 'pdb' | 'windows-scheduled-task' |
                  'whois-registrant-name' | 'whois-registrant-org' |
                  'whois-registrar' | 'whois-creation-date' | 'date-of-birth' |
                  'place-of-birth' | 'gender' | 'passport-number' |
                  'passport-country' | 'passport-expiration' | 'redress-number' |
                  'nationality' | 'visa-number' | 'issue-date-of-the-visa' |
                  'primary-residence' | 'country-of-residence' |
                  'special-service-request' | 'frequent-flyer-number' |
                  'travel-details' | 'payment-details' |
                  'place-port-of-original-embarkation' | 'place-port-of-clearance' |
                  'place-port-of-onward-foreign-destination' |
                  'passenger-name-record-locator-number' |
                  'email-dst-display-name' | 'email-src-display-name' |
                  'email-reply-to' | 'email-x-mailer' | 'email-mime-boundary' |
                  'email-thread-index' | 'email-message-id' | 'github-username' |
                  'github-repository' | 'github-organisation' | 'twitter-id' |
                  'dkim' | 'dkim-signature' | 'favicon-mmh3' |
                  'chrome-extension-id' | 'mobile-application-id' |
                  'azure-application-id' | 'named pipe'):
                if '\n' in value:
                    return 'Value must not contain new line character.'
                return True
            case 'ssh-fingerprint':
                if cls._is_ssh_fingerprint(value):
                    return True
                return 'SSH fingerprint must be in MD5 or SHA256 format.'
            case 'datetime':
                try:
                    parse(value)
                    return True
                except Exception:
                    return 'Datetime has to be in the ISO 8601 format.'
            case 'size-in-bytes' | 'counter':
                if cls._is_positive_integer(value):
                    return True
                return 'The value has to be a whole number greater or equal 0.'
            # case 'targeted-threat-index':
            #     if (!is_numeric($value) || $value < 0 || $value > 10) {
            #         return __('The value has to be a number between 0 and 10.');
            #     }
            #     return True
            case 'integer':
                try:
                    int(value)
                    return True
                except ValueError:
                    return 'The value has to be an integer value.'
            case 'iban' | 'bic' | 'btc' | 'dash' | 'xmr':
                if value.isalnum():
                    return True
                return f'{attribute_type.upper()} has to be alphanumeric.'
            case 'vhash':
                if len(value) > 0:
                    return True
                return 'Vhash must not be an empty string.'
            case ('bin' | 'cc-number' | 'bank-account-nr' | 'aba-rtn' | 'prtn' |
                  'phone-number' | 'whois-registrant-phone' | 'float'):
                try:
                    float(value)
                    return True
                except ValueError:
                    return f'The value has to be a valid {attribute_type}'
            case 'cortex':
                try:
                    json.loads(value)
                    return True
                except json.JSONDecodeError:
                    return 'The Cortex analysis result has to be a valid JSON string.'
            case 'boolean':
                if isinstance(value, bool):
                    return True
                return 'The value has to be either true or false.'
            case 'AS':
                if cls._is_positive_integer(value) and int(value) <= 4294967295:
                    return True
                return 'AS number have to be integer between 1 and 4294967295'
            case 'uuid':
                if UUID_RE.fullmatch(value):
                    return True
                return 'The value has to be a valid UUID format.'
            case _:
                return value

    @staticmethod
    def _handle_4byte_unicode(value):
        # Replace 4-byte UTF-8 characters with '?'
        return ''.join(ch if ord(ch) <= 0xFFFF else '?' for ch in value)

    @staticmethod
    def _is_domain_valid(value):
        return DOMAIN_RE.fullmatch(value)

    @staticmethod
    def _is_hash_valid(attribute_type, value):
        return len(value) == HASH_HEX_LENGTH[attribute_type] and HEX_RE.fullmatch(value)

    @classmethod
    def _is_port_valid(cls, value):
        return cls._is_positive_integer(value) and int(value) in range(1, 65536)

    @staticmethod
    def _is_positive_integer(value: int | str) -> bool:
        if isinstance(value, int):
            return value >= 0
        return value.isdigit() and int(value) >= 0

    @staticmethod
    def _is_ssdeep(value):
        return SSDEEP_RE.fullmatch(value)

    @classmethod
    def _is_ssh_fingerprint(cls, value):
        if value.startswith('SHA256:'):
            try:
                decoded = b64decode(value[7:])
            except Exception:
                return False
            return decoded is not None and len(decoded) == 32
        if value.startswith('MD5:'):
            return cls._is_hash_valid('md5', value[3:].replace(':', ''))
        return cls._is_hash_valid('md5', value.replace(':', ''))

    @staticmethod
    def _is_tlsh_valid(value):
        if value.startswith('t'):
            value = value.lstrip('t')
        return len(value) > 35 and HEX_RE.fullmatch(value)

    @staticmethod
    def _is_telfhash_valid(value):
        return len(value) in (70, 72) and HEX_RE.fullmatch(value)

    @staticmethod
    def _normalise_ip(value):
        # If IP is a CIDR
        if '/' in value:
            address, length = value.split('/', 2)
            if ':' in address:
                try:
                    address = str(ipaddress.IPv6Address(address))
                except ipaddress.AddressValueError:
                    return value
                if length == '128':
                    return address
            else:
                try:
                    address = str(ipaddress.IPv4Address(address))
                except ipaddress.AddressValueError:
                    return value
                if length == '32':
                    return address
            return f'{address}/{length}'
        try:
            return (
                str(ipaddress.IPv6Address(value))
                if ':' in value
                else str(ipaddress.IPv4Address(value))
            )
        except ipaddress.AddressValueError:
            return value

    @classmethod
    def _refang_value(cls, attribute_type, value):
        for rule in REFANG_REGEX_TABLE:
            if attribute_type in rule['types']:  # type: ignore
                value = rule['from'].sub(rule['to'], value)  # type: ignore
        return cls._handle_4byte_unicode(value)

    @classmethod
    def _validate_ip(cls, value):
        if '/' in value:
            composite = value.split('/')
            if len(composite) != 2 or not cls._is_positive_integer(composite[1]):
                return ('Invalid CIDR notation value found.')
            address, length = composite
            try:
                ip_obj = ipaddress.ip_address(address)
                if isinstance(ip_obj, ipaddress.IPv4Address):
                    if int(length) > 32:
                        return (
                            'Invalid CIDR notation value found, for '
                            'IPv4 must be lower or equal 32.'
                        )
                    return True
                if isinstance(ip_obj, ipaddress.IPv6Address):
                    if int(length) > 128:
                        return (
                            'Invalid CIDR notation value found, for '
                            'IPv6 must be lower or equal 128.'
                        )
                    return True
            except ValueError:
                return 'IP address has an invalid format.'
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return 'IP address has an invalid format.'
        return True


def validate_event(event: dict | MISPEvent,
                   errors: dict[str, list[str]]) -> MISPEvent:  # type: ignore
    """
    Validate event attributes and skip/remove any that don't validate.
    Replicates MISP server-side validation behavior.

    :param event: MISPEvent object or dict representing an event
    :return: MISPEvent with only valid attributes
    """
    try:
        if isinstance(event, dict):
            event = _load_misp_event(event)
        # Validation of Attributes
        event.attributes = list(_validate_attributes(event.attributes, errors))
        # Validation of Objects
        for misp_object in event.objects:
            misp_object.attributes = list(_validate_object_attributes(misp_object, errors))
    except Exception as e:
        message = f'Failed to validate event: {e}'
        logger.error(message)
        _populate_error_message(errors, 'errors', message)
    return event


def _load_misp_event(event: dict) -> MISPEvent:  # type: ignore
    misp_event = MISPEvent()
    misp_event.from_dict(**event)
    return misp_event


def _message_logging(validated: str, attribute: MISPAttribute, misp_object: MISPObject | None = None) -> str:
    message = f'Failed validation for {attribute.type} Attribute <{attribute.uuid}>'
    if misp_object is not None:
        message = f'{message} in {misp_object.name} Object <{misp_object.uuid}>'
    return f'{message}:\n{attribute.value} - {validated}'


def _populate_error_message(errors: dict[str, list[str]], key: str, message: str) -> None:
    try:
        errors[key].append(message)
    except KeyError:
        errors[key] = [message]


def _validate_attributes(attributes: list, errors: dict[str, list[str]]) -> Generator:  # type: ignore
    for attribute in attributes:
        value = AttributeValidationTool.modifyBeforeValidation(attribute.type, attribute.value)
        validated = AttributeValidationTool.validate(attribute.type, value)
        if validated is not True:
            message = _message_logging(validated, attribute)
            logger.warning(message)
            _populate_error_message(errors, 'warnings', message)
            continue
        attribute.value = value
        yield attribute


def _validate_object_attributes(misp_object: MISPObject, errors: dict[str, list[str]]) -> Generator:  # type: ignore
    for attribute in misp_object.attributes:
        value = AttributeValidationTool.modifyBeforeValidation(attribute.type, attribute.value)
        validated = AttributeValidationTool.validate(attribute.type, value)
        if validated is not True:
            message = _message_logging(validated, attribute, misp_object)
            logger.warning(message)
            _populate_error_message(errors, 'warnings', message)
            continue
        attribute.value = value
        yield attribute
