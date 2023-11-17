#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import logging
import ipaddress
import email.utils
from email import policy, message_from_bytes
from email.message import EmailMessage
from io import BytesIO
from pathlib import Path
from typing import Union, List, Tuple, Dict, cast, Any, Optional

from extract_msg import openMsg
from extract_msg.msg_classes import MessageBase
from extract_msg.properties import FixedLengthProp
from RTFDE.exceptions import MalformedEncapsulatedRtf, NotEncapsulatedRtf  # type: ignore
from RTFDE.deencapsulate import DeEncapsulator  # type: ignore
from oletools.common.codepages import codepage2codec  # type: ignore

from ..exceptions import InvalidMISPObject, PyMISPNotImplementedYet, MISPObjectException, NewAttributeError
from .abstractgenerator import AbstractMISPObjectGenerator

logger = logging.getLogger('pymisp')


class MISPMsgConverstionError(MISPObjectException):
    pass


class EMailObject(AbstractMISPObjectGenerator):
    def __init__(self, filepath: Optional[Union[Path, str]]=None, pseudofile: Optional[BytesIO]=None,
                 attach_original_email: bool = True, **kwargs):
        super().__init__('email', **kwargs)

        self.attach_original_email = attach_original_email
        self.encapsulated_body: Union[str, None] = None
        self.eml_from_msg: Union[bool, None] = None
        self.raw_emails: Dict[str, Union[BytesIO, None]] = {'msg': None,
                                                            'eml': None}

        self.__pseudofile = self.create_pseudofile(filepath, pseudofile)
        self.email = self.parse_email()
        self.generate_attributes()

    def parse_email(self) -> EmailMessage:
        """Convert email into EmailMessage."""
        content_in_bytes = self.__pseudofile.getvalue().strip()
        eml = message_from_bytes(content_in_bytes,
                                 _class=EmailMessage,
                                 policy=policy.default)
        eml = cast(EmailMessage, eml)  # Only needed to quiet mypy
        if len(eml) != 0:
            self.raw_emails['eml'] = self.__pseudofile
            return eml
        else:
            logger.debug("Email not in standard .eml format. Attempting to decode email from other formats.")
        try:  # Check for .msg formatted emails.
            # Msg files have the same header signature as the CFB format
            if content_in_bytes[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
                message = self._msg_to_eml(content_in_bytes)
                if len(message) != 0:
                    self.eml_from_msg = True
                    self.raw_emails['msg'] = self.__pseudofile
                    self.raw_emails['msg'] = BytesIO(message.as_bytes())
                    return message
        except ValueError as _e:  # Exception
            logger.debug("Email not in .msg format or is a corrupted .msg. Attempting to decode email from other formats.")
            logger.debug("Error: {} ".format(_e))
        try:
            if content_in_bytes[:3] == b'\xef\xbb\xbf':  # utf-8-sig byte-order mark (BOM)
                eml_bytes = content_in_bytes.decode("utf_8_sig").encode("utf-8")
                eml = email.message_from_bytes(eml_bytes,
                                               policy=policy.default)
                eml = cast(EmailMessage, eml)  # Only needed to quiet mypy
                if len(eml) != 0:
                    self.raw_emails['eml'] = BytesIO(eml_bytes)
                    return eml
        except UnicodeDecodeError:
            pass
        raise PyMISPNotImplementedYet("EmailObject does not know how to decode data passed to it. Object may not be an email. If this is an email please submit it as an issue to PyMISP so we can add support.")

    @staticmethod
    def create_pseudofile(filepath: Optional[Union[Path, str]] = None,
                          pseudofile: Optional[BytesIO] = None) -> BytesIO:
        """Creates a pseudofile using directly passed data or data loaded from file path.
        """
        if filepath:
            with open(filepath, 'rb') as f:
                return BytesIO(f.read())
        elif pseudofile and isinstance(pseudofile, BytesIO):
            return pseudofile
        else:
            raise InvalidMISPObject('File buffer (BytesIO) or a path is required.')

    def _msg_to_eml(self, msg_bytes: bytes) -> EmailMessage:
        """Converts a msg into an eml."""
        # NOTE: openMsg returns a MessageBase, not a MSGFile
        msg_obj: MessageBase = openMsg(msg_bytes)  # type: ignore
        # msg obj stores the original raw header here
        message, body, attachments = self._extract_msg_objects(msg_obj)
        eml = self._build_eml(message, body, attachments)
        return eml

    def _extract_msg_objects(self, msg_obj: MessageBase) -> Tuple[EmailMessage, Dict, List[Any]]:
        """Extracts email objects needed to construct an eml from a msg."""
        message: EmailMessage = email.message_from_string(msg_obj.header.as_string(), policy=policy.default)  # type: ignore
        body = {}
        if msg_obj.body is not None:
            body['text'] = {"obj": msg_obj.body,
                            "subtype": 'plain',
                            "charset": "utf-8",
                            "cte": "base64"}
        if msg_obj.htmlBody is not None:
            try:
                if isinstance(msg_obj.props['3FDE0003'], FixedLengthProp):
                    _html_encoding_raw = msg_obj.props['3FDE0003'].value
                    _html_encoding = codepage2codec(_html_encoding_raw)
                else:
                    _html_encoding = msg_obj.stringEncoding
            except KeyError:
                _html_encoding = msg_obj.stringEncoding
            body['html'] = {'obj': msg_obj.htmlBody.decode(),
                            "subtype": 'html',
                            "charset": _html_encoding,
                            "cte": "base64"}
        if msg_obj.rtfBody is not None:
            body['rtf'] = {"obj": msg_obj.rtfBody.decode(),
                           "subtype": 'rtf',
                           "charset": 'ascii',
                           "cte": "base64"}
            try:
                rtf_obj = DeEncapsulator(msg_obj.rtfBody)
                rtf_obj.deencapsulate()
                if (rtf_obj.content_type == "html") and (msg_obj.htmlBody is None):
                    self.encapsulated_body = 'text/html'
                    body['html'] = {"obj": rtf_obj.html,
                                    "subtype": 'html',
                                    "charset": rtf_obj.text_codec,
                                    "cte": "base64"}
                elif (rtf_obj.content_type == "text") and (msg_obj.body is None):
                    self.encapsulated_body = 'text/plain'
                    body['text'] = {"obj": rtf_obj.plain_text,
                                    "subtype": 'plain',
                                    "charset": rtf_obj.text_codec}
            except NotEncapsulatedRtf:
                logger.debug("RTF body in Msg object is not encapsualted.")
            except MalformedEncapsulatedRtf:
                logger.info("RTF body in Msg object contains encapsulated content, but it is malformed and can't be converted.")
        attachments = msg_obj.attachments
        return message, body, attachments

    def _build_eml(self, message: EmailMessage, body: dict, attachments: list) -> EmailMessage:
        """Constructs an eml file from objects extracted from a msg."""
        # Order the body objects by increasing complexity and toss any missing objects
        body_objects: List[dict] = [body.get('text', {}),
                                    body.get('html', {}),
                                    body.get('rtf', {})]
        body_objects = [i for i in body_objects if i != {}]
        # If this a non-multipart email then we only need to attach the payload
        if message.get_content_maintype() != 'multipart':
            for _body in body_objects:
                if "text/{0}".format(_body['subtype']) == message.get_content_type():
                    message.set_content(**_body)
                    return message
            raise MISPMsgConverstionError("Unable to find appropriate eml payload in message body.")
        # If multipart we are going to have to set the content type to null and build it back up.
        _orig_boundry = message.get_boundary()
        message.clear_content()
        # See if we are dealing with `related` inline content
        related_content = {}
        if isinstance(body.get('html', None), dict):
            _html = body.get('html', {}).get('obj')
            for attch in attachments:
                if _html.find("cid:{0}".format(attch.cid)) != -1:
                    _content_type = attch.getStringStream('__substg1.0_370E')
                    maintype, subtype = _content_type.split("/", 1)
                    related_content[attch.cid] = (attch,
                                                  {'obj': attch.data,
                                                   "maintype": maintype,
                                                   "subtype": subtype,
                                                   "cid": attch.cid,
                                                   "filename": attch.longFilename})
        if len(related_content) > 0:
            if body.get('text', None) is not None:
                # Text always goes first in an alternative, but we need the related object first
                body_text = body.get('text')
                if isinstance(body_text, dict):
                    message.add_related(**body_text)
            else:
                body_html = body.get('html')
                if isinstance(body_html, dict):
                    message.add_related(**body_html)
            for mime_items in related_content.values():
                if isinstance(mime_items[1], dict):
                    message.add_related(**mime_items[1])
                cur_attach = message.get_payload()[-1]
                self._update_content_disp_properties(mime_items[0], cur_attach)
            if body.get('text', None):
                # Now add the HTML as an alternative within the related obj
                related = message.get_payload()[0]
                related.add_alternative(**body.get('html'))
        else:
            for mime_dict in body_objects:
                # If encapsulated then don't attach RTF
                if self.encapsulated_body is not None:
                    if mime_dict.get('subtype', "") == "rtf":
                        continue
                if isinstance(mime_dict, dict):
                    message.add_alternative(**mime_dict)
        for attch in attachments:  # Add attachments at the end.
            if attch.cid not in related_content.keys():
                _content_type = attch.getStringStream('__substg1.0_370E')
                maintype, subtype = _content_type.split("/", 1)
                message.add_attachment(attch.data,
                                       maintype=maintype,
                                       subtype=subtype,
                                       cid=attch.cid,
                                       filename=attch.longFilename)
                cur_attach = message.get_payload()[-1]
                self._update_content_disp_properties(attch, cur_attach)
        if _orig_boundry is not None:
            message.set_boundary(_orig_boundry)  # Set back original boundary
        return message

    @staticmethod
    def _update_content_disp_properties(msg_attch, eml_attch):
        """Set Content-Disposition params on binary eml objects

        You currently have to set non-filename content-disp params by hand in python.
        """
        attch_cont_disp_props = {'30070040': "creation-date",
                                 '30080040': "modification-date"}
        for num, name in attch_cont_disp_props.items():
            try:
                eml_attch.set_param(name,
                                    email.utils.format_datetime(msg_attch.props[num].value),
                                    header='Content-Disposition')
            except KeyError:
                # It's fine if they don't have those values
                pass

    @property
    def attachments(self) -> List[Tuple[Optional[str], BytesIO]]:
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

    def generate_attributes(self):

        # Attach original & Converted
        if self.attach_original_email is not None:
            self.add_attribute("eml", value="Full email.eml",
                               data=self.raw_emails.get('eml'),
                               comment="Converted from MSG format" if self.eml_from_msg else None)
            if self.raw_emails.get('msg', None) is not None:
                self.add_attribute("msg", value="Full email.msg",
                                   data=self.raw_emails.get('msg'))

        message = self.email

        for _pref, body in message._find_body(message, preferencelist=['plain', 'html']):
            comment = "{0} body".format(body.get_content_type())
            if self.encapsulated_body == body.get_content_type():
                comment += " De-Encapsulated from RTF in original msg."
            self.add_attribute("email-body",
                               body.get_content(),
                               comment=comment)

        headers = ["{}: {}".format(k, v) for k, v in message.items()]
        if headers:
            self.add_attribute("header", "\n".join(headers))

        if "Date" in message and message.get('date').datetime is not None:
            self.add_attribute("send-date", message.get('date').datetime)

        if "To" in message:
            self.__add_emails("to", message["To"])
        if "Delivered-To" in message:
            self.__add_emails("to", message["Delivered-To"])

        if "From" in message:
            self.__add_emails("from", message["From"])

        if "Return-Path" in message:
            realname, address = email.utils.parseaddr(message["Return-Path"])
            self.add_attribute("return-path", address)

        if "Reply-To" in message:
            self.__add_emails("reply-to", message["reply-to"])

        if "Bcc" in message:
            self.__add_emails("bcc", message["Bcc"])

        if "Cc" in message:
            self.__add_emails("cc", message["Cc"])

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
            try:
                self.add_attributes("{}-display-name".format(typ), *display_names)
            except NewAttributeError:
                # email object doesn't support display name for all email addrs
                pass

    def __generate_received(self):
        """
        Extract IP addresses from received headers that are not private. Also extract hostnames or domains.
        """
        received_items = self.email.get_all("received")
        if received_items is None:
            return
        for received in received_items:
            fromstr = re.split(r"\sby\s", received)[0].strip()
            if fromstr.startswith('from') is not True:
                continue
            for i in ['(', ')', '[', ']']:
                fromstr = fromstr.replace(i, " ")
            tokens = fromstr.split(" ")
            ip = None
            for token in tokens:
                try:
                    ip = ipaddress.ip_address(token)
                    break
                except ValueError:
                    pass  # token is not IP address

            if not ip or ip.is_private:
                continue  # skip header if IP not found or is private

            self.add_attribute("received-header-ip", value=str(ip), comment=fromstr)

        # The hostnames and/or domains always come after the "Received: from"
        # part so we can use regex to pick up those attributes.
        received_from = re.findall(r'(?<=from\s)[\w\d\.\-]+\.\w{2,24}', str(received_items))
        try:
            [self.add_attribute("received-header-hostname", i) for i in received_from]
        except Exception:
            pass
