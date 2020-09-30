from email.message import EmailMessage
import unittest
from io import BytesIO
from typing import List
from pymisp.tools import EMailObject
from pathlib import Path


class TestEmailObject(unittest.TestCase):
    def test_mail_1(self):
        email_object = EMailObject(Path("tests/email_testfiles/mail_1.eml"))
        self.assertEqual(self._get_values(email_object, "subject")[0], "письмо уведом-е")
        self.assertEqual(self._get_values(email_object, "to")[0], "kinney@noth.com")
        self.assertEqual(self._get_values(email_object, "from")[0], "suvorov.s@nalg.ru")
        self.assertEqual(self._get_values(email_object, "from-display-name")[0], "служба ФНС Даниил Суворов")

        self.assertEqual(self._get_values(email_object, "received-header-ip")[0], "43.230.105.145")
        self.assertEqual(self._get_values(email_object, "received-header-ip")[1], "2a01:111:f400:7e49::205")

        self.assertIsInstance(email_object.email, EmailMessage)
        for file_name, file_content in email_object.attachments:
            self.assertIsInstance(file_name, str)
            self.assertIsInstance(file_content, BytesIO)

    def _get_values(self, obj: EMailObject, relation: str) -> List[str]:
        return [attr.value for attr in obj.attributes if attr['object_relation'] == relation]