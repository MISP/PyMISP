import os
from email import policy
from email.message import EmailMessage
from io import BytesIO
from pathlib import Path
from typing import Union, List, Tuple
import email.utils
import ipaddress
import logging
import mailparser  # type: ignore
from mailparser.utils import msgconvert  # type: ignore
from ..exceptions import InvalidMISPObject
from .abstractgenerator import AbstractMISPObjectGenerator

try:
    import magic  # type: ignore
    import tempfile
except ImportError:
    magic = None

logger = logging.getLogger('pymisp')


class EMailObject(AbstractMISPObjectGenerator):
    def __init__(self, filepath: Union[Path, str] = None, pseudofile: BytesIO = None,
                 attach_original_email: bool = True, **kwargs):
        super().__init__("email", **kwargs)

        converted = False
        if filepath:
            if str(filepath).endswith(".msg"):
                pseudofile = self.__convert_outlook_msg_format(str(filepath))
                converted = True
            else:
                with open(filepath, "rb") as f:
                    pseudofile = BytesIO(f.read())

        elif pseudofile and isinstance(pseudofile, BytesIO):
            if magic:
                # if python-magic is installed, we can autodetect MS Outlook format
                mime = magic.from_buffer(pseudofile.read(2048), mime=True)
                pseudofile.seek(0)
                if mime == "application/CDFV2":
                    # save outlook msg file to temporary file
                    temph, temp = tempfile.mkstemp(prefix="outlook_")
                    with os.fdopen(temph, "wb") as fdfile:
                        fdfile.write(pseudofile.getvalue())
                        fdfile.close()
                    pseudofile = self.__convert_outlook_msg_format(temp)
                    os.unlink(temp)  # remove temporary file necessary to convert formats
                    converted = True

        else:
            raise InvalidMISPObject("File buffer (BytesIO) or a path is required.")

        if attach_original_email:
            self.add_attribute("eml", value="Full email.eml", data=pseudofile,
                               comment="Converted from MSG format" if converted else None)

        message = self.attempt_decoding(pseudofile)
        self.__parser = mailparser.MailParser(message)
        self.__generate_attributes()

    @staticmethod
    def __convert_outlook_msg_format(filepath: str) -> BytesIO:
        converted_file, _ = msgconvert(filepath)
        with open(converted_file, "rb") as f:
            pseudofile = BytesIO(f.read())
        os.remove(converted_file)  # delete temporary file
        return pseudofile

    @staticmethod
    def attempt_decoding(bytes_io: BytesIO) -> EmailMessage:
        """Attempt to decode different king of emails, for example non-ascii encoded emails."""
        bytes = bytes_io.getvalue()

        message: EmailMessage = email.message_from_bytes(bytes, policy=policy.default)  # type: ignore

        if len(message) != 0:
            return message

        # Improperly encoded emails (utf-8-sig) fail silently. An empty email indicates this might be the case.
        try:
            bytes.decode("ASCII")
            raise Exception("EmailObject failed to decode ASCII encoded email.")
        except UnicodeDecodeError:
            logger.debug("EmailObject was passed a non-ASCII encoded binary blob.")
        try:
            if bytes[:3] == b'\xef\xbb\xbf':  # utf-8-sig byte-order mark (BOM)
                # Set Pseudofile to correctly encoded email in case it is used at some later point.
                bytes = bytes.decode("utf_8_sig").encode("ASCII")
                message = email.message_from_bytes(bytes, policy=policy.default)  # type: ignore
                return message
        except UnicodeDecodeError:
            pass

        raise Exception(
            "EmailObject does not know how to decode binary blob passed to it. Object may not be an email. If this is an email please submit it as an issue to PyMISP so we can add support.")

    @property
    def email(self) -> EmailMessage:
        return self.__parser.message

    @property
    def attachments(self) -> List[Tuple[str, BytesIO]]:
        to_return = []
        for attachment in self.email.iter_attachments():
            content = attachment.get_content()  # type: ignore
            if isinstance(content, str):
                content = content.encode()
            to_return.append((attachment.get_filename(), BytesIO(content)))
        return to_return

    def __generate_attributes(self):
        message = self.email

        body = message.get_body(preferencelist=("html", "plain"))
        if body:
            self.add_attribute("email-body", body.get_payload(decode=True).decode('utf8', 'surrogateescape'))

        headers = ["{}: {}".format(k, v) for k, v in message.items()]
        if headers:
            self.add_attribute("header", "\n".join(headers))

        message_date = self.__parser.date
        if message_date:
            self.add_attribute("send-date", message_date)

        if "To" in message:
            self.__add_emails("to", message["To"])

        if "From" in message:
            self.__add_emails("from", message["From"])

        if "Return-Path" in message:
            realname, address = email.utils.parseaddr(message["Return-Path"])
            self.add_attribute("return-path", address)

        if "Reply-To" in message:
            realname, address = self.__parser.reply_to[0]
            if address and realname:
                self.add_attribute("reply-to", value=address, comment=message["Reply-To"])
            elif address:
                self.add_attribute("reply-to", address)
            else:  # invalid format, insert original value
                self.add_attribute("reply-to", message["Reply-To"])

        if "Cc" in message:
            self.__add_emails("cc", message["Cc"], insert_display_names=False)

        if "Subject" in message:
            self.add_attribute("subject", message["Subject"])

        if "Message-ID" in message:
            self.add_attribute("message-id", message["Message-ID"])

        if "User-Agent" in message:
            self.add_attribute("user-agent", message["User-Agent"])

        boundary = message.get_boundary()
        if boundary:
            self.add_attribute("mime-boundary", boundary)

        if "X-Mailer" in message:
            self.add_attribute("x-mailer", message["X-Mailer"])

        if "Thread-Index" in message:
            self.add_attribute("thread-index", message["Thread-Index"])

        self.__generate_received()

    def __add_emails(self, typ: str, data: str, insert_display_names: bool = True):
        parts = [part.strip() for part in data.split(",")]
        addresses = []
        display_names = []

        for part in parts:
            realname, address = email.utils.parseaddr(part)
            if address and realname:
                addresses.append({"value": address, "comment": part})
            elif address:
                addresses.append({"value": address})
            else:  # parsing failed, insert original value
                addresses.append({"value": part})

            if realname:
                display_names.append({"value": realname, "comment": part})

        if addresses:
            self.add_attributes(typ, *addresses)
        if insert_display_names and display_names:
            self.add_attributes("{}-display-name".format(typ), *display_names)

    def __generate_received(self):
        """
        Extract IP addresses from received headers that are not private.
        """
        for received in self.__parser.received:
            tokens = received["from"].split(" ")
            ip = None
            for token in tokens:
                try:
                    ip = ipaddress.ip_address(token)
                    break
                except ValueError:
                    pass  # token is not IP address

            if not ip or ip.is_private:
                continue  # skip header if IP not found or is private

            self.add_attribute("received-header-ip", value=str(ip), comment=received["from"])
