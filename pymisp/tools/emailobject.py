import os
from email import policy
from email.message import EmailMessage
from io import BytesIO
from pathlib import Path
from typing import Union, List, Tuple
import email.utils
import ipaddress
import logging
try:
    import mailparser  # type: ignore
    from mailparser.utils import msgconvert  # type: ignore
except ImportError:
    mailparser = None
from ..exceptions import InvalidMISPObject
from .abstractgenerator import AbstractMISPObjectGenerator

try:
    import magic  # type: ignore
    import tempfile
except ImportError:
    magic = None

logger = logging.getLogger('pymisp')


class MISPMailObjectOutlookException(InvalidMISPObject):
    pass


class EMailObject(AbstractMISPObjectGenerator):
    def __init__(self, filepath: Union[Path, str] = None, pseudofile: BytesIO = None,
                 attach_original_email: bool = True, **kwargs):
        super().__init__("email", **kwargs)
        if not mailparser:
            raise MISPMailObjectOutlookException('mail-parser is required to use this module, you can install it by running pip3 install pymisp[email]')

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
        try:
            converted_file, stdout = msgconvert(filepath)
        except mailparser.exceptions.MailParserOSError as e:
            logger.critical(e)
            raise MISPMailObjectOutlookException('In order to process parse emails in Outlook format (.msg) you need the package "libemail-outlook-message-perl" and "libemail-address-perl" (on a debian system)')

        with open(converted_file, "rb") as f:
            pseudofile = BytesIO(f.read())
        os.remove(converted_file)  # delete temporary file
        if pseudofile.getbuffer().nbytes == 0:
            logger.critical('msgconvert created an empty file.')
            if stdout:
                # Probably empty, but in case it's not, let's show it
                logger.critical(stdout)
            raise MISPMailObjectOutlookException('You probably miss the package libemail-address-perl (on a debian system)')
        return pseudofile

    @staticmethod
    def attempt_decoding(bytes_io: BytesIO) -> EmailMessage:
        """Attempt to decode different king of emails, for example non-ascii encoded emails."""
        content_in_bytes = bytes_io.getvalue()

        message: EmailMessage = email.message_from_bytes(content_in_bytes, policy=policy.default)  # type: ignore

        if len(message) != 0:
            return message

        # Improperly encoded emails (utf-8-sig) fail silently. An empty email indicates this might be the case.
        try:
            content_in_bytes.decode("ASCII")
            raise Exception("EmailObject failed to decode ASCII encoded email.")
        except UnicodeDecodeError:
            logger.debug("EmailObject was passed a non-ASCII encoded binary blob.")
        try:
            if content_in_bytes[:3] == b'\xef\xbb\xbf':  # utf-8-sig byte-order mark (BOM)
                content_in_bytes = content_in_bytes.decode("utf_8_sig").encode("ASCII")
                message = email.message_from_bytes(content_in_bytes, policy=policy.default)  # type: ignore
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
        try:
            for attachment in self.email.iter_attachments():
                content = attachment.get_content()  # type: ignore
                if isinstance(content, str):
                    content = content.encode()
                to_return.append((attachment.get_filename(), BytesIO(content)))
        except AttributeError:
            # ignore bug in Python3.6, that cause exception for empty email body,
            # see https://stackoverflow.com/questions/56391306/attributeerror-str-object-has-no-attribute-copy-when-parsing-multipart-emai
            pass
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
        addresses = []
        display_names = []

        for realname, address in email.utils.getaddresses([data]):
            if address and realname:
                addresses.append({"value": address, "comment": "{} <{}>".format(realname, address)})
            elif address:
                addresses.append({"value": address})
            else:  # parsing failed, skip
                continue

            if realname:
                display_names.append({"value": realname, "comment": "{} <{}>".format(realname, address)})

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
