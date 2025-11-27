import unittest
from collections import defaultdict
from datetime import datetime
from pymisp import MISPAttribute, MISPObject
from pymisp.tools import (
    AttributeValidationTool, validate_attribute, validate_attributes,
    validate_event, validate_object, validate_objects, ValidationError
)

class TestAttributeValidationTool(unittest.TestCase):

    def _should_be_valid(self, type_, *values):
        for value in values:
            self.assertTrue(AttributeValidationTool.validate(type_, value))

    def _should_be_invalid(self, type_, *values):
        for value in values:
            self.assertNotEqual(
                AttributeValidationTool.validate(type_, value), True
            )

    def test_modify_before_validation_as(self):
        self.assertEqual('123', AttributeValidationTool.modifyBeforeValidation('AS', 'AS123'))
        self.assertEqual(65537, AttributeValidationTool.modifyBeforeValidation('AS', '1.1'))

    def test_modify_before_validation_boolean(self):
        self.assertEqual(True, AttributeValidationTool.modifyBeforeValidation('boolean', 'True'))
        self.assertEqual(False, AttributeValidationTool.modifyBeforeValidation('boolean', 'False'))
        self.assertEqual(True, AttributeValidationTool.modifyBeforeValidation('boolean', 1))
        self.assertEqual(False, AttributeValidationTool.modifyBeforeValidation('boolean', 0))

    def test_modify_before_validation_domain(self):
        self.assertEqual('example.com', AttributeValidationTool.modifyBeforeValidation('domain', 'example.com'))
        self.assertEqual('example.com', AttributeValidationTool.modifyBeforeValidation('domain', 'EXAMPLE.COM'))
        self.assertEqual('example.com|127.0.0.1', AttributeValidationTool.modifyBeforeValidation('domain|ip', 'example.com|127.0.0.1'))
        self.assertEqual('example.com|127.0.0.1', AttributeValidationTool.modifyBeforeValidation('domain|ip', 'EXAMPLE.COM|127.0.0.1'))
        self.assertEqual('xn--hkyrky-ptac70bc.cz', AttributeValidationTool.modifyBeforeValidation('domain', 'háčkyčárky.cz'))
        self.assertEqual('xn--hkyrky-ptac70bc.cz', AttributeValidationTool.modifyBeforeValidation('domain', 'HÁČKYČÁRKY.CZ'))
        self.assertEqual('xn--hkyrky-ptac70bc.cz|127.0.0.1', AttributeValidationTool.modifyBeforeValidation('domain|ip', 'háčkyčárky.cz|127.0.0.1'))
        self.assertEqual('xn--hkyrky-ptac70bc.cz|127.0.0.1', AttributeValidationTool.modifyBeforeValidation('domain|ip', 'HÁČKYČÁRKY.CZ|127.0.0.1'))

    def test_modify_before_validation_filename_hash(self):
        self.assertEqual('CMD.EXE|0cc175b9c0f1b6a831c399e269772661', AttributeValidationTool.modifyBeforeValidation('filename|md5', 'CMD.EXE|0CC175B9C0F1B6A831C399E269772661'))

    def test_modify_before_validation_financial(self):
        self.assertEqual('123456', AttributeValidationTool.modifyBeforeValidation('cc-number', '1234-56'))
        self.assertEqual('123456', AttributeValidationTool.modifyBeforeValidation('bin', '1234 56'))
        self.assertEqual('ABC12', AttributeValidationTool.modifyBeforeValidation('iban', 'abc-12'))
        self.assertEqual('ABC12', AttributeValidationTool.modifyBeforeValidation('bic', 'abc 12'))

    def test_modify_before_validation_hostname(self):
        self.assertEqual('example.com|80', AttributeValidationTool.modifyBeforeValidation('hostname|port', 'example.com:80'))
        self.assertEqual('example.com|80', AttributeValidationTool.modifyBeforeValidation('hostname|port', 'EXAMPLE.COM:80'))

    def test_modify_before_validation_ip(self):
        self.assertEqual('127.0.0.1', AttributeValidationTool.modifyBeforeValidation('ip-src', '127.0.0.1/32'))
        self.assertEqual('127.0.0.1/31', AttributeValidationTool.modifyBeforeValidation('ip-src', '127.0.0.1/31'))
        self.assertEqual('example.com|1234:fd2:5621:1:89::4500', AttributeValidationTool.modifyBeforeValidation('domain|ip', 'example.com|1234:0fd2:5621:0001:0089:0000:0000:4500/128'))
        self.assertEqual('1234:fd2:5621:1:89::4500|80', AttributeValidationTool.modifyBeforeValidation('ip-src|port', '1234:0fd2:5621:0001:0089:0000:0000:4500/128|80'))
        self.assertEqual('1234:fd2:5621:1:89::4500/127|80', AttributeValidationTool.modifyBeforeValidation('ip-src|port', '1234:0fd2:5621:0001:0089:0000:0000:4500/127|80'))
        self.assertEqual('127.0.0.1', AttributeValidationTool.modifyBeforeValidation('ip-src', '127.0.0.1'))

    def test_modify_before_validation_ipv6(self):
        self.assertEqual('1234:fd2:5621:1:89::4500', AttributeValidationTool.modifyBeforeValidation('ip-src', '1234:0fd2:5621:0001:0089:0000:0000:4500'))
        self.assertEqual('example.com|1234:fd2:5621:1:89::4500', AttributeValidationTool.modifyBeforeValidation('domain|ip', 'example.com|1234:0fd2:5621:0001:0089:0000:0000:4500'))
        self.assertEqual('1234:fd2:5621:1:89::4500|80', AttributeValidationTool.modifyBeforeValidation('ip-src|port', '1234:0fd2:5621:0001:0089:0000:0000:4500|80'))
        self.assertEqual('127.0.0.1', AttributeValidationTool.modifyBeforeValidation('ip-src', '127.0.0.1'))

    def test_modify_before_validation_hashes(self):
        # Hashes should be lowercased
        for type_ in ['md5', 'sha1', 'sha256', 'email', 'hostname']:
            self.assertEqual('abc', AttributeValidationTool.modifyBeforeValidation(type_, 'ABC'))
            self.assertEqual('abc', AttributeValidationTool.modifyBeforeValidation(type_, ' AbC '))

    def test_modify_before_validation_mac(self):
        self.assertEqual('aa:bb:cc:dd:ee:ff', AttributeValidationTool.modifyBeforeValidation('mac-address', 'AA-BB-CC-DD-EE-FF'))
        self.assertEqual('aa:bb:cc:dd:ee:ff', AttributeValidationTool.modifyBeforeValidation('mac-address', 'aabbccddeeff'))

    def test_modify_before_validation_phone(self):
        self.assertEqual('+123456', AttributeValidationTool.modifyBeforeValidation('phone-number', '00123456'))
        self.assertEqual('+123456', AttributeValidationTool.modifyBeforeValidation('phone-number', '+1 (23) 456'))
        self.assertEqual('+123456', AttributeValidationTool.modifyBeforeValidation('prtn', '00123456'))

    def test_modify_before_validation_uppercase(self):
        # HTTP methods and hex should be uppercased
        self.assertEqual('POST', AttributeValidationTool.modifyBeforeValidation('http-method', 'post'))
        self.assertEqual('AABB', AttributeValidationTool.modifyBeforeValidation('hex', 'aabb'))

    def test_modify_before_validation_vulnerability(self):
        self.assertEqual('CVE-2020-1234', AttributeValidationTool.modifyBeforeValidation('vulnerability', 'CVE-2020-1234'))
        self.assertEqual('CVE-2020-1234', AttributeValidationTool.modifyBeforeValidation('vulnerability', 'cve-2020-1234'))
        self.assertEqual('CVE-2020-1234', AttributeValidationTool.modifyBeforeValidation('vulnerability', 'CVE–2020–1234')) # en-dash

    def test_modify_before_validation_weakness(self):
        self.assertEqual('CWE-89', AttributeValidationTool.modifyBeforeValidation('weakness', 'cwe-89'))
        self.assertEqual('CWE-89', AttributeValidationTool.modifyBeforeValidation('weakness', 'CWE–89'))

    def test_modify_before_validation_x509(self):
        self.assertEqual('aa6fc83f37787abea6be2c5126163fd3', AttributeValidationTool.modifyBeforeValidation('x509-fingerprint-md5', 'AA:6F:C8:3F:37:78:7A:BE:A6:BE:2C:51:26:16:3F:D3'))

    def test_validate_as(self):
        self._should_be_valid('AS', '0', 0, 1, '1', 4294967295, '1.1')
        self._should_be_invalid('AS', '1.2.3.4')

    def test_validate_domain_ip(self):
        self._should_be_valid(
            'domain|ip', 'example.com|127.0.0.1', 'example.com|::1'
        )
        self._should_be_invalid(
            'domain|ip', 'example.com|127', 'example.com|1',
        )

    def test_validate_filename(self):
        self._should_be_valid('filename', 'cmd.exe', 'cmd.com')
        self._should_be_invalid('filename', 'cmd.exe\ncmd.com')
        self._should_be_valid(
            'filename|md5', 'cmd.exe|0cc175b9c0f1b6a831c399e269772661',
            'cmd.com|0cc175b9c0f1b6a831c399e269772661'
        )
        self._should_be_invalid('filename|md5', 'cmd.exe\ncmd.com|0cc175b9c0f1b6a831c399e269772661')

    def test_validate_hashes(self):
        self._should_be_valid('filename|md5', 'cmd.exe|0cc175b9c0f1b6a831c399e269772661')
        self._should_be_invalid('filename|md5', 'cmd.exe|86f7e437faa5a7fce15d1ddcb9eaeaea377667b8')
        self._should_be_valid(
            'tlsh',
            'b2317c38fac0333c8ff7d3ff31fcf3b7fb3f9a3ef3bf3c880cfc43ebf97f3cc73fbfc',
            't1fdd4e000b6a1c034f1f612f849b6a3a4b53f7ea1677481cf12d916ea4a79af1ed31317'
        )
        self._should_be_valid(
            'filename|tlsh',
            'cmd.exe|b2317c38fac0333c8ff7d3ff31fcf3b7fb3f9a3ef3bf3c880cfc43ebf97f3cc73fbfc',
            'cmd.exe|t1fdd4e000b6a1c034f1f612f849b6a3a4b53f7ea1677481cf12d916ea4a79af1ed31317'
        )
        self._should_be_valid(
            'ssdeep',
            '96:s4Ud1Lj96tHHlZDrwciQmA+4uy1I0G4HYuL8N3TzS8QsO/wqWXLcMSx:sF1LjEtHHlZDrJzrhuyZvHYm8tKp/RWO',
            '384:EWo4X1WaPW9ZWhWzLo+lWpct/fWbkWsWIwW0/S7dZhgG8:EWo4X1WmW9ZWhWH/WpchfWgWsWTWtf8',
            '6144:3wSQSlrBHFjOvwYAU/Fsgi/2WDg5+YaNk5xcHrYw+Zg+XrZsGEREYRGAFU25ttR/:ctM7E0L4q'
        )
        self._should_be_valid(
            'filename|ssdeep',
            'ahoj.txt|96:s4Ud1Lj96tHHlZDrwciQmA+4uy1I0G4HYuL8N3TzS8QsO/wqWXLcMSx:sF1LjEtHHlZDrJzrhuyZvHYm8tKp/RWO'
        )
        self._should_be_valid('dom-hash', '0cc175b9c0f1b6a831c399e269772661')

        self._should_be_valid('telfhash', 'a' * 70, 'a' * 72)
        self._should_be_invalid('telfhash', 'a' * 69, 'z' * 70) # z is not hex

        self._should_be_valid('pehash', 'a' * 40)
        self._should_be_invalid('pehash', 'a' * 39, 'z' * 40)

        self._should_be_valid('impfuzzy', '3:aabbcc:ddeeff')
        self._should_be_invalid('impfuzzy', '3:aabbcc', 'x:aabbcc:ddeeff')

        self._should_be_valid('cdhash', 'a' * 40)
        self._should_be_invalid('cdhash', 'a' * 39, 'z' * 40)

        self._should_be_valid('filename|vhash', 'file.txt|vhash123')
        self._should_be_invalid('filename|vhash', 'file.txt')

    def test_validate_identifiers(self):
        self._should_be_valid('vulnerability', 'CVE-2020-1234', 'GHSA-1234-1234-1234')
        self._should_be_invalid('vulnerability', 'CVE-2020', 'invalid')

        self._should_be_valid('weakness', 'CWE-89')
        self._should_be_invalid('weakness', 'CWE-ABC', 'invalid')

        self._should_be_valid('uuid', '123e4567-e89b-12d3-a456-426614174000')
        self._should_be_invalid('uuid', '123e4567-e89b-12d3-a456-42661417400g', '123e4567-e89b-12d3-a456-42661417400')

        self._should_be_valid('target-user', 'user1')
        self._should_be_invalid('target-user', 'user1\nuser2')

    def test_validate_ip(self):
        for type_ in ['ip-src', 'ip-dst']:
            self._should_be_valid(
                type_, '127.0.0.1', '127.0.0.1/32', '::1', '::1/128'
            )
            self._should_be_invalid(
                type_, '127','127.0.0.', '127.0.0.1/', '127.0.0.1/32/1',
                '127.0.0.1/128', '::1/257', '::1/257', '::1/128/1'
            )

    def test_validate_misc(self):
        self._should_be_valid('windows-service-name', 'service1')
        self._should_be_invalid('windows-service-name', 'service/1', 'service\\1', 'a' * 257)

        self._should_be_valid('link', 'http://example.com', 'ftp://example.com')
        self._should_be_invalid('link', 'example.com')

        self._should_be_valid('hex', 'aabbcc')
        self._should_be_invalid('hex', 'zz')

        self._should_be_valid('datetime', '2020-01-01T00:00:00')
        self._should_be_invalid('datetime', '2020:01:01 00-00-00')

        self._should_be_valid('size-in-bytes', '1024', 1024)
        self._should_be_invalid('size-in-bytes', '-1', 'abc')
        self._should_be_valid('integer', '123', '-123')
        self._should_be_invalid('integer', 'abc')
        self._should_be_valid('float', '1.23', '-1.23')
        self._should_be_invalid('float', 'abc')

        self._should_be_valid('iban', 'ALPHANUM123')
        self._should_be_invalid('iban', 'invalid-char!')
        self._should_be_valid('btc', '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2')
        self._should_be_invalid('btc', 'invalid!')

        self._should_be_valid('cortex', '{"a": 1}')
        self._should_be_invalid('cortex', '{a: 1}')

        self._should_be_valid('boolean', True, False)
        self._should_be_invalid('boolean', 'maybe')

    def test_validate_networking(self):
        self._should_be_valid('ip-dst|port', '127.0.0.1|80', '::1|80')
        self._should_be_invalid('ip-dst|port', '127.0.0.1', '127.0.0.1|99999')

        self._should_be_valid('onion-address', 'abcdefghijklmnop.onion', 'abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz23.onion')
        self._should_be_invalid('onion-address', 'invalid.onion', 'abc.onion')

        self._should_be_valid('mac-address', 'aa:bb:cc:dd:ee:ff')
        self._should_be_invalid('mac-address', 'aa:bb:cc:dd:ee:gg', 'aabbccddeeff')

        self._should_be_valid('mac-eui-64', 'aa:bb:cc:ff:fe:dd:ee:11')
        self._should_be_invalid('mac-eui-64', 'aa:bb:cc:dd:ee:ff:00:11', 'aa:bb:cc:dd:ee:ff:00:gg')

        self._should_be_valid('hostname|port', 'example.com|80')
        self._should_be_invalid('hostname|port', 'example.com', 'example.com|99999', 'invalid_domain|80')

        self._should_be_valid('email', 'test@example.com', 'a.b@c.d')
        self._should_be_invalid('email', 'test@example', 'test.com')

        self._should_be_valid('http-method', 'GET', 'POST')
        self._should_be_invalid('http-method', 'get', 'FIND')

    def test_validate_port(self):
        self.assertTrue(AttributeValidationTool.validate('port', '1'))
        self.assertTrue(AttributeValidationTool.validate('port', 1))
        self.assertTrue(AttributeValidationTool.validate('port', 80))
        self.assertNotEqual(AttributeValidationTool.validate('port', -80), True)
        self.assertNotEqual(AttributeValidationTool.validate('port', '-80'), True)

    def test_validate_ssdeep(self):
        self._should_be_valid('ssdeep', "768:+OFu8Q3w6QzfR5Jni6SQD7qSFDs6P93/q0XIc/UB5EPABWX:RFu8QAFzffJui79f13/AnB5EPAkX")
        self._should_be_invalid('ssdeep', "768:+OFu8Q3w6QzfR5Jni6SQD7qSFDs6P93/q0XIc/UB5EPABWX\n\n:RFu8QAFzffJui79f13/AnB5EPAkX")

    def test_validate_ssh_fingerprint(self):
        self._should_be_valid(
            'ssh-fingerprint',
            '7b:e5:6f:a7:f4:f9:81:62:5c:e3:1f:bf:8b:57:6c:5a',
            'MD5:7b:e5:6f:a7:f4:f9:81:62:5c:e3:1f:bf:8b:57:6c:5a',
            'SHA256:mVPwvezndPv/ARoIadVY98vAC0g+P/5633yTC4d/wXE',
        )

    def test_validate_event(self):
        event_dict = {
            'Event': {
                'info': 'Test Event',
                'Attribute': [
                    {'type': 'ip-src', 'value': '1.1.1.1'},  # Valid
                    {'type': 'ip-src', 'value': '999.999.999.999'},  # Invalid
                    {'type': 'domain', 'value': 'google.com'},  # Valid
                    {'type': 'md5', 'value': 'invalid_md5'},  # Invalid
                    {'type': 'AS', 'value': '1.1'}  # modified and valid
                ],
                'Object': [
                    {
                        'name': 'file',
                        'Attribute': [
                            {'type': 'filename', 'object_relation': 'filename', 'value': 'test.txt'},  # Valid
                            {'type': 'md5', 'object_relation': 'md5', 'value': '0cc175b9c0f1b6a831c399e269772661'},  # Valid
                            {'type': 'md5', 'object_relation': 'md5', 'value': 'invalid_md5'},  # Invalid
                        ]
                    }
                ]
            }
        }
        
        # Run validation
        validated_event = validate_event(event_dict, errors := defaultdict(list))  # type: ignore
        
        # Check Attributes
        self.assertEqual(len(validated_event.attributes), 3)
        ip_attribute, domain_attribute, as_attribute = validated_event.attributes
        self.assertEqual(ip_attribute.value, '1.1.1.1')
        self.assertEqual(domain_attribute.value, 'google.com')
        self.assertEqual(as_attribute.value, 65537)
        
        # Check Objects
        self.assertEqual(len(validated_event.objects), 1)
        file_object = validated_event.objects[0]
        self.assertEqual(file_object.name, 'file')
        self.assertEqual(len(file_object.attributes), 2)
        filename_attribute, md5_attribute = file_object.attributes
        self.assertEqual(filename_attribute.value, 'test.txt')
        self.assertEqual(md5_attribute.value, '0cc175b9c0f1b6a831c399e269772661')

        # Check Errors
        self.assertEqual(len(errors['warnings']), 3)
        ip_error, *md5_errors = errors['warnings']
        self.assertIn('IP address has an invalid format.', ip_error)
        for md5_error in md5_errors:
            self.assertIn(
                'Checksum has an invalid length or format (expected: 32 hexadecimal characters).',
                md5_error
            )

    def test_validate_attribute(self):
        # Test with valid dict
        attribute_dict = {'type': 'ip-src', 'value': '1.1.1.1'}
        validated = validate_attribute(attribute_dict)
        self.assertIsInstance(validated, MISPAttribute)
        self.assertEqual(validated.value, '1.1.1.1')

        # Test with valid MISPAttribute
        attribute = MISPAttribute()
        attribute.from_dict(**attribute_dict)
        validated = validate_attribute(attribute)
        self.assertIsInstance(validated, MISPAttribute)
        self.assertEqual(validated.value, '1.1.1.1')

        # Test with invalid dict
        invalid_dict = {'type': 'ip-src', 'value': '999.999.999.999'}
        with self.assertRaises(ValidationError) as cm:
            validate_attribute(invalid_dict)
        self.assertIn('IP address has an invalid format.', str(cm.exception))

        # Test with invalid MISPAttribute
        invalid_attribute = MISPAttribute()
        invalid_attribute.from_dict(**invalid_dict)
        with self.assertRaises(ValidationError) as cm:
            validate_attribute(invalid_attribute)
        self.assertIn('IP address has an invalid format.', str(cm.exception))

        # Test modification
        modified_dict = {'type': 'AS', 'value': 'AS123'}
        validated = validate_attribute(modified_dict)
        self.assertEqual(validated.value, '123')

    def test_validate_attributes(self):
        attributes = [
            {'type': 'ip-src', 'value': '1.1.1.1'},  # Valid
            {'type': 'ip-src', 'value': '999.999.999.999'},  # Invalid
            {'type': 'domain', 'value': 'google.com'}  # Valid
        ]

        valid_attributes = list(validate_attributes(attributes, errors := defaultdict(list)))  # type: ignore

        self.assertEqual(len(valid_attributes), 2)
        self.assertEqual(valid_attributes[0].value, '1.1.1.1')
        self.assertEqual(valid_attributes[1].value, 'google.com')

        self.assertEqual(len(errors['warnings']), 1)
        self.assertIn('IP address has an invalid format.', errors['warnings'][0])

    def test_validate_object(self):
        object_dict = {
            'name': 'file',
            'Attribute': [
                {'type': 'filename', 'object_relation': 'filename', 'value': 'test.txt'},  # Valid
                {'type': 'md5', 'object_relation': 'md5', 'value': 'invalid_md5'}  # Invalid
            ]
        }

        # Test with dict
        validated_object = validate_object(object_dict, errors := {})  # type: ignore
        self.assertIsInstance(validated_object, MISPObject)
        self.assertEqual(len(validated_object.attributes), 1)
        self.assertEqual(validated_object.attributes[0].value, 'test.txt')
        self.assertEqual(len(errors['warnings']), 1)
        self.assertIn('Checksum has an invalid length or format', errors['warnings'][0])

        # Test with MISPObject
        misp_object = MISPObject('file')
        misp_object.from_dict(**object_dict)
        validated_object = validate_object(misp_object, errors := {})
        self.assertEqual(len(validated_object.attributes), 1)
        self.assertEqual(validated_object.attributes[0].value, 'test.txt')
        self.assertIn('Checksum has an invalid length or format', errors['warnings'][0])

    def test_validate_objects(self):
        objects = [
            {
                'name': 'file',
                'Attribute': [
                    {'type': 'filename', 'object_relation': 'filename', 'value': 'test.txt'},
                    {'type': 'md5', 'object_relation': 'md5', 'value': 'invalid_md5'}
                ]
            },
            {
                'name': 'x509',
                'Attribute': [
                    {'type': 'x509-fingerprint-md5', 'object_relation': 'x509-fingerprint-md5', 'value': 'b2a5abfeef9e36964281a31e17b57c97'},
                    {'type': 'datetime', 'object_relation': 'validity-not-before', 'value': '2022-01-01T00:00:00'}
                ]
            }
        ]

        valid_objects = list(validate_objects(objects, errors := defaultdict(list)))  # type: ignore

        self.assertEqual(len(valid_objects), 2)
        file_object, x509_object = valid_objects
        # First object should have 1 attribute (1 filtered out)
        self.assertEqual(len(file_object.attributes), 1)
        self.assertEqual(file_object.attributes[0].value, 'test.txt')
        self.assertEqual(len(errors['warnings']), 1)
        self.assertIn('Checksum has an invalid length or format', errors['warnings'][0])

        # Second object should have 2 attributes
        self.assertEqual(len(x509_object.attributes), 2)
        self.assertEqual(x509_object.attributes[0].value, 'b2a5abfeef9e36964281a31e17b57c97')
        validity = x509_object.attributes[1].value
        self.assertEqual(x509_object.attributes[1].value, datetime(2022, 1, 1, 0, 0, 0))
