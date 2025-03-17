from __future__ import annotations

# import json
import unittest

from email.message import EmailMessage
from io import BytesIO
from os import urandom
from pathlib import Path
from typing import TypeVar
from zipfile import ZipFile

from pymisp.tools import EMailObject
from pymisp.exceptions import InvalidMISPObject

T = TypeVar('T', bound='TestEmailObject')


class TestEmailObject(unittest.TestCase):

    eml_1: BytesIO
    msg_1: BytesIO

    @classmethod
    def setUpClass(cls: type[T]) -> None:
        with ZipFile(Path("tests/email_testfiles/mail_1.msg.zip"), 'r') as myzip:
            with myzip.open('mail_1.msg', pwd=b'AVs are dumb') as myfile:
                cls.msg_1 = BytesIO(myfile.read())
        with ZipFile(Path("tests/email_testfiles/mail_1.eml.zip"), 'r') as myzip:
            with myzip.open('mail_1.eml', pwd=b'AVs are dumb') as myfile:
                cls.eml_1 = BytesIO(myfile.read())

    def test_mail_1(self) -> None:
        email_object = EMailObject(pseudofile=self.eml_1)
        self.assertEqual(self._get_values(email_object, "subject")[0], "письмо уведом-е")
        self.assertEqual(self._get_values(email_object, "to")[0], "kinney@noth.com")
        self.assertEqual(self._get_values(email_object, "from")[0], "suvorov.s@nalg.ru")
        self.assertEqual(self._get_values(email_object, "from-display-name")[0], "служба ФНС Даниил Суворов")
        self.assertEqual(len(self._get_values(email_object, "email-body")), 1)

        self.assertEqual(self._get_values(email_object, "received-header-ip"),
                         ['64.98.42.207', '2603:10b6:207:3d::31',
                          '2a01:111:f400:7e49::205', '43.230.105.145'])

        self.assertIsInstance(email_object.email, EmailMessage)
        for file_name, file_content in email_object.attachments:
            self.assertIsInstance(file_name, str)
            self.assertIsInstance(file_content, BytesIO)

    def test_mail_1_headers_only(self) -> None:
        email_object = EMailObject(Path("tests/email_testfiles/mail_1_headers_only.eml"))
        self.assertEqual(self._get_values(email_object, "subject")[0], "письмо уведом-е")
        self.assertEqual(self._get_values(email_object, "to")[0], "kinney@noth.com")
        self.assertEqual(self._get_values(email_object, "from")[0], "suvorov.s@nalg.ru")

        self.assertEqual(len(self._get_values(email_object, "email-body")), 0)

        self.assertIsInstance(email_object.email, EmailMessage)
        self.assertEqual(len(email_object.attachments), 0)

    def test_mail_multiple_to(self) -> None:
        email_object = EMailObject(Path("tests/email_testfiles/mail_multiple_to.eml"))

        to = self._get_values(email_object, "to")
        to_display_name = self._get_values(email_object, "to-display-name")
        self.assertEqual(to[0], "jan.novak@example.com")
        self.assertEqual(to_display_name[0], "Novak, Jan")
        self.assertEqual(to[1], "jan.marek@example.com")
        self.assertEqual(to_display_name[1], "Marek, Jan")

    def test_msg(self) -> None:
        # Test result of eml converted to msg is the same
        eml_email_object = EMailObject(pseudofile=self.eml_1)
        email_object = EMailObject(pseudofile=self.msg_1)

        self.assertIsInstance(email_object.email, EmailMessage)
        for file_name, file_content in email_object.attachments:
            self.assertIsInstance(file_name, str)
            self.assertIsInstance(file_content, BytesIO)

        self.assertEqual(self._get_values(email_object, "subject")[0],
                         self._get_values(eml_email_object, "subject")[0])
        self.assertEqual(self._get_values(email_object, "to")[0],
                         self._get_values(eml_email_object, "to")[0])
        self.assertEqual(self._get_values(email_object, "from")[0],
                         self._get_values(eml_email_object, "from")[0])
        self.assertEqual(self._get_values(email_object, "from-display-name")[0],
                         self._get_values(eml_email_object, "from-display-name")[0])
        self.assertEqual(len(self._get_values(email_object, "email-body")), 2)

        self.assertEqual(self._get_values(email_object, "received-header-ip"),
                         self._get_values(eml_email_object, "received-header-ip"))

    def test_bom_encoded(self) -> None:
        """Test utf-8-sig encoded email"""
        bom_email_object = EMailObject(Path("tests/email_testfiles/mail_1_bom.eml"))
        eml_email_object = EMailObject(pseudofile=self.eml_1)

        self.assertIsInstance(bom_email_object.email, EmailMessage)
        for file_name, file_content in bom_email_object.attachments:
            self.assertIsInstance(file_name, str)
            self.assertIsInstance(file_content, BytesIO)

        self.assertEqual(self._get_values(bom_email_object, "subject")[0],
                         self._get_values(eml_email_object, "subject")[0])
        self.assertEqual(self._get_values(bom_email_object, "to")[0],
                         self._get_values(eml_email_object, "to")[0])
        self.assertEqual(self._get_values(bom_email_object, "from")[0],
                         self._get_values(eml_email_object, "from")[0])
        self.assertEqual(self._get_values(bom_email_object, "from-display-name")[0],
                         self._get_values(eml_email_object, "from-display-name")[0])
        self.assertEqual(len(self._get_values(bom_email_object, "email-body")), 1)

        self.assertEqual(self._get_values(bom_email_object, "received-header-ip"),
                         self._get_values(eml_email_object, "received-header-ip"))

    def test_handling_of_various_email_types(self) -> None:
        self._does_not_fail(Path("tests/email_testfiles/mail_2.eml"),
                            "ensuring all headers work")
        self._does_not_fail(Path('tests/email_testfiles/mail_3.eml'),
                            "Check for related content in emails emls")
        self._does_not_fail(Path('tests/email_testfiles/mail_3.msg'),
                            "Check for related content in emails msgs")
        self._does_not_fail(Path('tests/email_testfiles/mail_4.msg'),
                            "Check that HTML without specific encoding")
        self._does_not_fail(Path('tests/email_testfiles/mail_5.msg'),
                            "Check encapsulated HTML works")

    def _does_not_fail(self, path: Path, test_type: str="test") -> None:
        found_error = None
        try:
            EMailObject(path)
        except Exception as _e:
            found_error = _e
        if found_error is not None:
            self.fail('Error {} raised when parsing test email {} which tests against {}. It should not have raised an error.'.format(
                type(found_error),
                path,
                test_type))

    def test_random_binary_blob(self) -> None:
        """Email parser fails correctly on random binary blob."""
        random_data = urandom(1024)
        random_blob = BytesIO(random_data)
        found_error = None
        try:
            broken_obj = EMailObject(pseudofile=random_data)
        except Exception as _e:
            found_error = _e
        if not isinstance(found_error, InvalidMISPObject):
            self.fail("Expected InvalidMISPObject when EmailObject receives completely unknown binary input data. But, did not get that exception.")
        try:
            broken_obj = EMailObject(pseudofile=random_blob)
        except Exception as _e:
            found_error = _e
        if not isinstance(found_error, InvalidMISPObject):
            self.fail("Expected InvalidMISPObject when EmailObject receives completely unknown binary input data in a pseudofile. But, did not get that exception.")

    @staticmethod
    def _get_values(obj: EMailObject, relation: str) -> list[str]:
        return [attr.value for attr in obj.attributes if attr['object_relation'] == relation]
