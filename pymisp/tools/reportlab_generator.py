#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Standard imports
import base64
import logging
import pprint
from io import BytesIO
from functools import partial

import sys

if sys.version_info.major >= 3:
    from html import escape
else:
    print(
        "ExportPDF running with Python < 3 : stability and output not guaranteed. Please run exportPDF with at least Python3")

logger = logging.getLogger('pymisp')

# Potentially not installed imports
try:
    from reportlab.pdfgen import canvas
    from reportlab.pdfbase.pdfmetrics import stringWidth
    from reportlab.pdfbase.pdfdoc import PDFDictionary, PDFInfo
    from reportlab.lib import colors

    from reportlab.platypus import SimpleDocTemplate, Paragraph, PageBreak, Spacer, Table, TableStyle, Flowable

    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.lib.enums import TA_RIGHT, TA_CENTER, TA_JUSTIFY, TA_LEFT

    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False
    print("ReportLab cannot be imported. Please verify that ReportLab is installed on the system.")


########################################################################
def create_flowable_tag(misp_tag):
    '''
    Returns a Flowable tag linked to one tag.
    :param misp_tag: A misp tag of a misp event or a misp event's attribute
    :return: one flowable representing a tag (with style)
    '''
    col1_style, col2_style = get_table_styles()

    return [Flowable_Tag(text=misp_tag.name, color=misp_tag.colour, custom_style=col1_style)]


class Flowable_Tag(Flowable):
    """
    Custom flowable to handle tags. Draw one Tag with the webview formatting
    Modified from : http://two.pairlist.net/pipermail/reportlab-users/2005-February/003695.html
    and : http://www.blog.pythonlibrary.org/2014/03/10/reportlab-how-to-create-custom-flowables/
    """

    # ----------------------------------------------------------------------
    def __init__(self, x=0, y=0, width=40, height=15, text="", color="#ffffff", custom_style=None):
        Flowable.__init__(self)
        self.x = x
        self.y = y
        self.width = width
        self.height = height
        self.text = text
        self.colour = color
        if custom_style is not None:
            self.custom_style = custom_style
        else:
            self.custom_style = getSampleStyleSheet()["Normal"]

    # ----------------------------------------------------------------------

    def coord(self, x, y, unit=1):
        """
        http://stackoverflow.com/questions/4726011/wrap-text-in-a-table-reportlab
        Helper class to help position flowables in Canvas objects
        """
        x, y = x * unit, self.height - y * unit
        return x, y

    # ----------------------------------------------------------------------
    def __repr__(self):
        return "Tag(w=" + str(self.width) + ")"

    # ----------------------------------------------------------------------
    def choose_good_text_color(self):
        # See : http://trendct.org/2016/01/22/how-to-choose-a-label-color-to-contrast-with-background/
        r, g, b = colors.HexColor(self.colour).rgb()

        brightness = r * 299 + g * 587 + b * 114 / 1000

        if brightness < 500:  # Standard treeshold for human vision : 123 instead of 500
            text_color = "#ffffff"  # Black
        else:
            text_color = "#000000"  # White

        return text_color

    # ----------------------------------------------------------------------
    def draw(self):
        '''
        Draw the shape, text, etc to show a Tag
        Honestely, constant are totally ad-hoc. Feels free to change it, but be sure to test the visual result of it.
        '''
        RADIUS = 1 * mm
        LEFT_INTERNAL_PADDING = 2
        ELONGATION = LEFT_INTERNAL_PADDING * 2

        p = Paragraph("<font color='" + self.choose_good_text_color() + "'>" + self.text + "</font>",
                      style=self.custom_style)
        string_width = stringWidth(self.text, self.custom_style.fontName, self.custom_style.fontSize)

        self.width = string_width + ELONGATION
        self.height = self.custom_style.fontSize

        self.canv.setFillColor(colors.HexColor(self.colour))
        self.canv.roundRect(self.x, self.y + LEFT_INTERNAL_PADDING, self.width, self.height + 2, RADIUS, fill=1)

        p.wrapOn(self.canv, self.width, self.height)
        p.drawOn(self.canv, *self.coord(self.x, self.y + 0.5 * LEFT_INTERNAL_PADDING, mm))


# Copy of pdfexport.py moduleconfig
moduleconfig = ["MISP_base_url_for_dynamic_link", "MISP_name_for_metadata"]

# == Row colors of the table (alternating) ==
EVEN_COLOR = colors.whitesmoke
ODD_COLOR = colors.lightgrey

# == Lines parameters of the table ==
LINE_COLOR = colors.lightslategray
LINE_THICKNESS = 0.75

# == Columns colors, aligment, fonts, space, size, width, heights ==
# FIRST_COL_FONT_COLOR = colors.darkslateblue # Test purposes
FIRST_COL_FONT_COLOR = colors.HexColor("#333333")  # Same as GUI
FIRST_COL_FONT = 'Helvetica-Bold'
FIRST_COL_ALIGNEMENT = TA_CENTER

SECOND_COL_FONT_COLOR = colors.black
SECOND_COL_FONT = 'Helvetica'
SECOND_COL_ALIGNEMENT = TA_LEFT

TEXT_FONT_SIZE = 8
LEADING_SPACE = 7
EXPORT_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
COL_WIDTHS = ['30%', '75%']  # colWidths='*' # Not documented but does exist
ROW_HEIGHT = 5 * mm  # 4.5 * mm (a bit too short to allow vertical align TODO : Fix it)
ROW_HEIGHT_FOR_TAGS = 4 * mm  # 4.5 * mm (a bit too short to allow vertical align TODO : Fix it)

# == Whole document margins and size ==
PAGESIZE = (140 * mm, 216 * mm)  # width, height
BASE_MARGIN = 5 * mm  # Create a list here to specify each row separately

# == Parameters for error handling for content too long to fit on a page ==
FRAME_MAX_HEIGHT = 500  # 650 # Ad hoc value for a A4 page
FRAME_MAX_WIDTH = 356
STR_TOO_LONG_WARNING = "<br/><b><font color=red>[Too long to fit on a single page. Cropped]</font></b>"

# == Parameters for links management ==
LINK_TYPE = "link"  # Name of the type that define 'good' links
URL_TYPE = "url"  # Name of the type that define 'bad' links
WARNING_MESSAGE_URL = "'https://Please_consider_that_this_may_be_a_harmful_link'"
GOOD_LINK_COLOR = 'blue'
BAD_LINK_COLOR = 'red'


########################################################################
# "UTILITIES" METHODS. Not meant to be used except for development purposes

def get_sample_fonts():
    '''
    Get fonts available on the current system, usable in pdf generation
    :return: None. Print on std output the list of available fonts
    '''

    # Create a dummy canvas
    c = canvas.Canvas("hello.pdf")

    # Print list of usable fonts
    pprint.pprint(c.getAvailableFonts())


def get_sample_styles():
    '''
    Get styles available in reportLab (Paragraph, Heading1, ...)
    :return: None. Print on std output the list of available styles
    '''

    # Get styles, as for example sample_style_sheet['Heading1'], sample_style_sheet['BodyText'] ...
    sample_style_sheet = getSampleStyleSheet()

    # if you want to see all the sample styles, this prints them
    sample_style_sheet.list()


# "INTERNAL" METHODS. Not meant to be used outside of this class.

def alternate_colors_style_generator(data):
    '''
    Create a style, applicable on a table that will be built with parameter's data, with alternated
    background color for each line.
    Modified from : https://gist.github.com/chadcooper/5798392
    :param data: list of list of items (2D table) to be displayed in the pdf
    :return: A list of 'BACKGROUND' properties, usable in a TableStyle, with alternated colours
    '''

    data_len = len(data)
    color_list = []

    # For each line, generate a tuple giving to a line a color
    for each in range(data_len):
        if each % 2 == 0:
            bg_color = EVEN_COLOR
        else:
            bg_color = ODD_COLOR
        color_list.append(('BACKGROUND', (0, each), (-1, each), bg_color))

    return color_list


def lines_style_generator(data):
    '''
    Create a style, applicable on a table that will be built with parameter's data,
    that draw colored lines above and below each line of the table
    :param data:  list of list of items (2D table) to be displayed in the pdf
    :return: A list of 'LINE****' properties, usable in a TableStyle, that are drawing lines
    '''
    data_len = len(data)
    lines_list = []

    # For each line, generate a tuple giving to a line a color
    for each in range(data_len):
        lines_list.append(('LINEABOVE', (0, each), (-1, each), LINE_THICKNESS, LINE_COLOR))

    # Last line
    lines_list.append(('LINEBELOW', (0, len(data) - 1), (-1, len(data) - 1), LINE_THICKNESS, LINE_COLOR))

    return lines_list


def general_style_generator():
    '''
    Create the general style (alignement, padding ...) of the table, copying the MISP'event's web_view.
    :return: a list of properties, usable in a TableStyle
    '''
    lines_list = []

    lines_list.append(('VALIGN', (0, 0), (-1, -1), 'MIDDLE'))
    lines_list.append(('LEFTPADDING', (0, 0), (-1, -1), 0))
    lines_list.append(('RIGHTPADDING', (0, 0), (-1, -1), 0))

    # VERTICAL_PADDING = 2
    # lines_list.append(('TOPPADDING', (0, 0), (-1, -1), VERTICAL_PADDING))
    # lines_list.append(('BOTTOMPADDING', (0, 0), (-1, -1), VERTICAL_PADDING))

    return lines_list


def get_table_styles():
    '''
    Create and returns the two mains styles for the columns of the document.
    :return: two styles, one for each columns of the document, describing the MISP object.
    '''
    sample_style_sheet = getSampleStyleSheet()

    custom_body_style_col_1 = ParagraphStyle(name='Column_1',
                                             parent=sample_style_sheet['Normal'],
                                             fontName=FIRST_COL_FONT,
                                             textColor=FIRST_COL_FONT_COLOR,
                                             fontSize=TEXT_FONT_SIZE,
                                             leading=LEADING_SPACE,
                                             alignment=FIRST_COL_ALIGNEMENT)

    custom_body_style_col_2 = ParagraphStyle(name='Column_2',
                                             parent=sample_style_sheet['Normal'],
                                             fontName=SECOND_COL_FONT,
                                             textColor=SECOND_COL_FONT_COLOR,
                                             fontSize=TEXT_FONT_SIZE,
                                             leading=LEADING_SPACE,
                                             alignment=SECOND_COL_ALIGNEMENT)

    return custom_body_style_col_1, custom_body_style_col_2


########################################################################
# Specific attribute formater

def get_value_link_to_event(misp_event, item, col2_style, config=None, color=True):
    '''
    Returns a flowable paragraph to add to the pdf given the misp_event uuid, with or without link
    :param config: Config dictionnary provided by MISP instance, via misp-modules (with baseurl)
    :param misp_event: A misp event with or without "uuid" attributes
    :param item: a list of name, in order :
    ["Name to be print in the pdf", "json property access name",
    " Name to be display if no values found in the misp_event"]
    :param col2_style: style to be applied on the returned paragraph
    :return: a Paragraph to add in the pdf, regarding the values of "uuid"
    '''

    # Does MispEven has the attribute ?
    if hasattr(misp_event, item[1]):
        # It has the requested attribute .. building upon it.

        # Does misp_object has an uuid and do we know the baseurl ?
        if hasattr(misp_event, "uuid") and config is not None and moduleconfig[0] in config:
            # We can build links
            curr_uuid = str(getattr(misp_event, "uuid"))
            curr_baseurl = config[moduleconfig[0]]
            curr_url = uuid_to_url(curr_baseurl, curr_uuid)
            html_url = "<a href=" + curr_url + ">" + safe_string(getattr(misp_event, item[1])) + "</a>"

            if color:
                # They want fancy colors
                html_url = "<font color=" + GOOD_LINK_COLOR + ">" + html_url + "</font>"

            # Construct final paragraph
            answer = get_unoverflowable_paragraph(html_url, col2_style, False)

        else:
            # We can't build links
            answer = get_unoverflowable_paragraph(getattr(misp_event, item[1]), col2_style)

    else:
        # No it doesn't, so we directly give the default answer
        answer = Paragraph(item[2], col2_style)

    return answer


def get_timestamp_value(misp_event, item, col2_style):
    '''
    Returns a flowable paragraph to add to the pdf given the misp_event timestamp
    :param misp_event: A misp event with or without "timestamp" attributes
    :param item: a list of name, in order :
    ["Name to be print in the pdf", "json property access name",
    " Name to be display if no values found in the misp_event"]
    :param col2_style: style to be applied on the returned paragraph
    :return: a Paragraph to add in the pdf, regarding the values of "timestamp"
    '''
    if hasattr(misp_event, item[1]):
        return Paragraph(str(getattr(misp_event, item[1]).strftime(EXPORT_DATE_FORMAT)), col2_style)
    return Paragraph(item[2], col2_style)


def get_creator_organisation_value(misp_event, item, col2_style):
    '''
    Returns a flowable paragraph to add to the pdf given the misp_event creator organisation
    :param misp_event: A misp event with or without "timestamp" attributes
    :param item: a list of name, in order :
    ["Name to be print in the pdf", "json property access name",
    " Name to be display if no values found in the misp_event", "json property access name (second level)"]
    :param col2_style: style to be applied on the returned paragraph
    :return: a Paragraph to add in the pdf, regarding the values of "creator organisation"
    '''
    if hasattr(misp_event, item[1]):
        return Paragraph(safe_string(getattr(getattr(misp_event, item[1]), item[3])), col2_style)
    return Paragraph(item[2], col2_style)


def get_attributes_number_value(misp_event, item, col2_style):
    '''
    Returns a flowable paragraph to add to the pdf given the misp_event attributes
    :param misp_event: A misp event with or without "attributes" attributes
    :param item: a list of name, in order :
    ["Name to be print in the pdf", "json property access name",
    " Name to be display if no values found in the misp_event"]
    :param col2_style: style to be applied on the returned paragraph
    :return: a Paragraph to add in the pdf, regarding the values of "attributes"
    '''
    if hasattr(misp_event, item[1]):
        return Paragraph(str(len(getattr(misp_event, item[1]))), col2_style)
    return Paragraph(item[2], col2_style)


def get_tag_value(misp_event, item, col2_style):
    '''
    Returns a flowable paragraph to add to the pdf given the misp_event tags
    :param misp_event: A misp event with or without "tags" attributes
    :param item: a list of name, in order :
    ["Name to be print in the pdf", "json property access name",
    " Name to be display if no values found in the misp_event"]
    :param col2_style: style to be applied on the returned paragraph
    :return: a Paragraph to add in the pdf, regarding the values of "tags"
    '''
    if hasattr(misp_event, item[1]):
        table_event_tags = create_flowable_table_from_tags(misp_event)
        return table_event_tags
    return Paragraph(item[2], col2_style)


def get_published_value(misp_event, item, col2_style):
    '''
    Returns a flowable paragraph to add to the pdf given the misp_event published/published_time
    More information on how to play with paragraph into reportlab cells :
    https://stackoverflow.com/questions/11810008/reportlab-add-two-paragraphs-into-one-table-cell
    :param misp_event: A misp event with or without "published"/"publish_timestamp" attributes
    :param item: a list of name, in order :
    ["Name to be print in the pdf", "json property access name",
    " Name to be display if no values found in the misp_event", json property access name (for timestamp")]
    e.g. item = ["Published", 'published', "None", "publish_timestamp"]
    :param col2_style: style to be applied on the returned paragraph
    :return: a Paragraph to add in the pdf, regarding the values of "published"/"publish_timestamp"
    '''

    RED_COLOR = '#ff0000'
    GREEN_COLOR = '#008000'
    YES_ANSWER = "<font color=" + GREEN_COLOR + "><b> Yes </b></font> ("
    NO_ANSWER = "<font color=" + RED_COLOR + "><b>No</b></font>"

    answer = ""

    # Formatting similar to MISP Event web view
    if hasattr(misp_event, item[1]):
        if getattr(misp_event, item[1]):  # == True
            if hasattr(misp_event, item[3]):
                # Published and have published date
                answer = Paragraph(YES_ANSWER + getattr(misp_event, item[3]).strftime(EXPORT_DATE_FORMAT) + ")",
                                   col2_style)
            else:
                # Published without published date
                answer = YES_ANSWER + "no date)"
        else:
            # Not published
            answer = NO_ANSWER
    else:
        # Does not have a published attribute
        answer = item[2]

    return answer


def is_safe_attribute(curr_object, attribute_name):
    return hasattr(curr_object, attribute_name) and getattr(curr_object, attribute_name) is not None and getattr(
        curr_object, attribute_name) != ""


def create_flowable_table_from_one_attribute(misp_attribute):
    '''
    Returns a table (flowalbe) representing the attribute
    :param misp_attribute: A misp attribute
    :return: a table representing this misp's attribute's attributes, to add to the pdf as a flowable
    '''
    data = []
    col1_style, col2_style = get_table_styles()

    # To reduce code size, and automate it a bit, triplet (Displayed Name, object_attribute_name,
    # to_display_if_not_present) are store in the following list
    list_attr_automated = [["UUID", 'uuid', "None"],
                           ["Category", 'category', "None"],
                           ["Comment", 'comment', "None"],
                           ["Type", 'type', "None"],
                           ["Value", 'value', "None"]]

    # Handle the special case of links
    STANDARD_TYPE = True
    if hasattr(misp_attribute, 'type') and (
            getattr(misp_attribute, 'type') == LINK_TYPE or getattr(misp_attribute, 'type') == URL_TYPE):
        # Special case for links
        STANDARD_TYPE = False

    # Automated adding of standard (python) attributes of the misp event
    for item in list_attr_automated:
        if is_safe_attribute(misp_attribute, item[1]) and (STANDARD_TYPE or item[1] != 'value'):
            # The attribute exists, we fetch it and create the row
            data.append([Paragraph(item[0], col1_style),
                         get_unoverflowable_paragraph(getattr(misp_attribute, item[1]), col2_style)])

        # The attribute does not exist, you may want to print a default text on the row. Then use as a else case :
        # data.append([Paragraph(item[0], col1_style), Paragraph(item[2], col2_style)])

    # Handle Special case for links (Value)
    if not STANDARD_TYPE:
        item = ["Value", 'value', "None"]

        if is_safe_attribute(misp_attribute, item[1]):
            if getattr(misp_attribute, 'type') == LINK_TYPE:
                data.append([Paragraph(item[0], col1_style), get_unoverflowable_paragraph(
                    "<font color=" + GOOD_LINK_COLOR + "><a href=" + getattr(misp_attribute, item[1]) + ">" + getattr(
                        misp_attribute, item[1]) + "</a></font>", col2_style, False)])
            elif getattr(misp_attribute, 'type') == URL_TYPE:
                data.append([Paragraph(item[0], col1_style), get_unoverflowable_paragraph(
                    "<font color=" + BAD_LINK_COLOR + "><a href=" + WARNING_MESSAGE_URL + ">" + getattr(misp_attribute,
                                                                                                        item[
                                                                                                            1]) + "</a></font>",
                    col2_style, False)])

    # Tags
    item = ["Tags", 'Tag', "None"]
    if hasattr(misp_attribute, item[1]):
        data.append([Paragraph(item[0], col1_style), get_tag_value(misp_attribute, item, col2_style)])

    return create_flowable_table_from_data(data)


def create_tags_table_from_data(data):
    '''
    Given a list of flowables tags (2D/list of list), creates a Table with styles adapted to tags.
    :param data: list of list of tags (flowables)
    :return: a Table - with styles - to add to another table
    '''

    # Create the table
    curr_table = Table(data, COL_WIDTHS, rowHeights=ROW_HEIGHT_FOR_TAGS)

    # Create styles and set parameters
    general_style = general_style_generator()

    # Make the table nicer
    curr_table.setStyle(TableStyle(general_style))

    return curr_table


########################################################################
# General attribut formater

def safe_string(bad_str):
    return escape(str(bad_str))


def get_unoverflowable_paragraph(dirty_string, curr_style, do_escape_string=True):
    '''
    Create a paragraph that can fit on a cell of one page. Mostly hardcoded values.
    This method can be improved (get the exact size of the current frame, and limit the paragraph to this size.)
    This might be worst look at KeepInFrame (which hasn't went well so far)
    :param do_escape_string: Activate the escaping (may be useful to add inline HTML, e.g. hyperlinks)
    :param dirty_string: String to transform
    :param curr_style: Style to apply to the returned paragraph
    :return:
    '''
    if do_escape_string:
        sanitized_str = str(escape(str(dirty_string)))
    else:
        sanitized_str = dirty_string

    # Get the space that the paragraph needs to be printed
    w, h = Paragraph(sanitized_str, curr_style).wrap(FRAME_MAX_WIDTH, FRAME_MAX_HEIGHT)

    # If there is enough space, directly send back the sanitized paragraph
    if w <= FRAME_MAX_WIDTH and h <= FRAME_MAX_HEIGHT:
        answer_paragraph = Paragraph(sanitized_str, curr_style)
    else:
        # Otherwise, cut the content to fit the paragraph (Dichotomy)
        max_carac_amount = int((FRAME_MAX_HEIGHT / (h * 1.0)) * len(sanitized_str))

        i = 0
        MAX_ITERATION = 10
        limited_string = ""
        while (w > FRAME_MAX_WIDTH or h > FRAME_MAX_HEIGHT) and i < MAX_ITERATION:
            i += 1
            limited_string = sanitized_str[:max_carac_amount]  # .replace("\n", "").replace("\r", "")
            w, h = Paragraph(limited_string + STR_TOO_LONG_WARNING, curr_style).wrap(FRAME_MAX_WIDTH, FRAME_MAX_HEIGHT)
            max_carac_amount = int(max_carac_amount / 2)

        if w <= FRAME_MAX_WIDTH and h <= FRAME_MAX_HEIGHT:
            answer_paragraph = Paragraph(limited_string + STR_TOO_LONG_WARNING, curr_style)
        else:
            # We may still end with a not short enough string
            answer_paragraph = Paragraph(STR_TOO_LONG_WARNING, curr_style)

    return answer_paragraph


########################################################################
# General Event's Attributes formater tools

def uuid_to_url(baseurl, uuid):
    '''
    Return an url constructed from the MISP baseurl and the uuid of the event, to go to this event on this MISP
    :param baseurl: the baseurl of the MISP instnce e.g. http://localhost:8080 or http://localhost:8080/
    :param uuid: the uuid of the event that we want to have a link to
    :return: the complete URL to go to this event on this MISP instance
    '''
    if baseurl[len(baseurl) - 1] != "/":
        baseurl += "/"
    return baseurl + "events/view/" + uuid


def create_flowable_table_from_data(data):
    '''
    Given a list of flowables items (2D/list of list), creates a Table with styles.
    :param data: list of list of items (flowables is better)
    :return: a Table - with styles - to add to the pdf
    '''
    # Create the table
    curr_table = Table(data, COL_WIDTHS)

    # Aside notes :
    #   colWidths='*' does a 100% and share the space automatically
    #   rowHeights=ROW_HEIGHT if you want a fixed height. /!\ Problems with paragraphs that are spreading everywhere

    # Create styles and set parameters
    alternate_colors_style = alternate_colors_style_generator(data)
    lines_style = lines_style_generator(data)
    general_style = general_style_generator()

    # Make the table nicer
    curr_table.setStyle(TableStyle(general_style + alternate_colors_style + lines_style))

    return curr_table


########################################################################
# General Event's Attributes formater

def create_flowable_table_from_event(misp_event, config=None):
    '''
    Returns Table presenting a MISP event
    :param misp_event: A misp event (complete or not)
    :return: a table that can be added to a pdf
    '''

    # To reduce code size, and automate it a bit, triplet (Displayed Name, object_attribute_name,
    # to_display_if_not_present) are store in the following list
    list_attr_automated = [
        # ["Event ID", 'id', "None"],
        ["Date", 'date', "None"],
        ["Owner org", 'owner', "None"],
        ["Threat level", 'threat_level_id', "None"],  # TODO : improve design
        ["Analysis", 'analysis', "None"],  # TODO : improve design + Ask where the enum is !
        # TODO : Not present ["Email", 'email', "None"],
        # TODO : ["Distribution", 'distribution', "None"],
        # TODO : ["First recorded change", 'TODO', "None"],
        # TODO : ["Last change", 'TODO', "None"],
        # TODO : ["Modification map", 'TODO', "None"],
        # TODO : ["Sightings", 'TODO', "None"]
    ]

    data = []
    col1_style, col2_style = get_table_styles()

    # Manual addition
    # UUID
    item = ["UUID", 'uuid', "None"]
    data.append([Paragraph(item[0], col1_style), get_value_link_to_event(misp_event, item, col2_style, config)])

    # Automated adding of standard (python) attributes of the misp event
    # Note that PEP 0363 may change the syntax in future release : https://www.python.org/dev/peps/pep-0363/
    for item in list_attr_automated:
        if hasattr(misp_event, item[1]):
            # The attribute exist, we fetch it and create the row
            data.append(
                [Paragraph(item[0], col1_style),
                 get_unoverflowable_paragraph(getattr(misp_event, item[1]), col2_style)])
        else:
            # The attribute does not exist ,we print a default text on the row
            data.append([Paragraph(item[0], col1_style), Paragraph(item[2], col2_style)])

    # Manual addition
    # Info
    item = ["Info", 'info', "None"]
    data.append([Paragraph(item[0], col1_style), get_value_link_to_event(misp_event, item, col2_style, config)])

    # Timestamp
    item = ["Event date", 'timestamp', "None"]
    data.append([Paragraph(item[0], col1_style), get_timestamp_value(misp_event, item, col2_style)])

    # Published
    item = ["Published", 'published', "None", "publish_timestamp"]
    data.append([Paragraph(item[0], col1_style), get_published_value(misp_event, item, col2_style)])

    # Creator organisation
    item = ["Creator Org", 'Orgc', "None", "name"]
    data.append([Paragraph(item[0], col1_style), get_creator_organisation_value(misp_event, item, col2_style)])

    # Number of Attributes
    item = ["# Attributes", 'Attribute', "None"]
    data.append([Paragraph(item[0], col1_style), get_attributes_number_value(misp_event, item, col2_style)])

    # Tags
    item = ["Tags", 'Tag', "None"]
    data.append([Paragraph(item[0], col1_style), get_tag_value(misp_event, item, col2_style)])

    return create_flowable_table_from_data(data)


def create_flowable_table_from_attributes(misp_event):
    '''
    Returns a list of flowables representing the list of attributes of a misp event.
    The list is composed alternatively of headers and tables, to add to the pdf
    :param misp_event: A misp event
    :return: a table of flowables
    '''

    flowable_table = []
    sample_style_sheet = getSampleStyleSheet()
    i = 0

    if hasattr(misp_event, "Attribute"):
        # There is some attributes for this object
        for item in getattr(misp_event, "Attribute"):
            # you can use a spacer instead of title to separate paragraph: flowable_table.append(Spacer(1, 5 * mm))
            flowable_table.append(Paragraph("Attribute #" + str(i), sample_style_sheet['Heading3']))
            flowable_table.append(create_flowable_table_from_one_attribute(item))
            i += 1
    else:
        # No attributes for this object
        flowable_table.append(Paragraph("No attributes", sample_style_sheet['Heading2']))

    return flowable_table


def create_flowable_table_from_tags(misp_event):
    '''
    Returns a Table (flowable) to add to a pdf, representing the list of tags of an event or a misp event
    :param misp_event: A misp event
    :return: a table of flowable to add to the pdf
    '''

    flowable_table = []
    col1_style, col2_style = get_table_styles()
    i = 0

    if hasattr(misp_event, "Tag") and len(getattr(misp_event, "Tag")) > 1:  # 'Tag' can exist and be empty
        # There is some tags for this object
        for item in getattr(misp_event, "Tag"):
            flowable_table.append(create_flowable_tag(item))
            i += 1
        answer_tags = create_tags_table_from_data(flowable_table)
    else:
        # No tags for this object
        answer_tags = [Paragraph("No tags", col2_style)]

    return answer_tags


########################################################################
# Handling static parts drawn on the upper layer

def set_template(canvas, doc, misp_event, config=None):
    add_page_number(canvas, doc)
    add_metadata(canvas, doc, misp_event, config)
    # TODO : add_header()
    # TODO : add_footer()


def add_metadata(canvas, doc, misp_event, config=None):
    '''
    Allow to add metadata to the pdf. Would need deeper digging to change other metadata.
    :param canvas: / Automatically filled during pdf compilation
    :param doc: / Automatically filled during pdf compilation
    :param misp_event: To send trough "partial", to get information to complete metadaa
    :return: / Automatically filled during pdf compilation
    '''

    if hasattr(misp_event, 'info'):
        canvas.setTitle(getattr(misp_event, 'info'))

    if hasattr(misp_event, 'info'):
        canvas.setSubject(getattr(misp_event, 'info'))

    if hasattr(misp_event, 'Orgc'):
        if hasattr(getattr(misp_event, 'Orgc'), 'name'):
            canvas.setAuthor(getattr(getattr(misp_event, 'Orgc'), 'name'))

            if config is not None and moduleconfig[1] in config:
                canvas.setCreator(config[moduleconfig[1]])
            else:
                canvas.setCreator(getattr(getattr(misp_event, 'Orgc'), 'name'))

    if hasattr(misp_event, 'uuid'):
        canvas.setKeywords(getattr(misp_event, 'uuid'))


def add_page_number(canvas, doc):
    '''
    Draw the page number on each page
    :param canvas: / Automatically filled during pdf compilation
    :param doc: / Automatically filled during pdf compilation
    :return: / Automatically filled during pdf compilation
    '''
    canvas.saveState()
    canvas.setFont('Times-Roman', 10)
    page_number_text = "%d" % (doc.page)

    curr_spacing = 4 * mm  # 0.75 * inch

    canvas.drawCentredString(
        curr_spacing,
        curr_spacing,
        page_number_text
    )

    canvas.restoreState()


########################################################################
# Main part of the script, handling the global formatting of the pdf

def collect_parts(misp_event, config=None):
    '''
    Main part of the PDF creation, it creates a ready-to-compile-as-pdf list of flowables from a MISP Event, calling subfunctions to handle the printing of each element
    :param misp_event: a misp event
    :return: a list of flowables to compile as pdf
    '''
    # List of elements/content we want to add
    flowables = []
    # Get the list of available styles
    sample_style_sheet = getSampleStyleSheet()

    # Create stuff
    title = get_value_link_to_event(misp_event, ["Info", 'info', "None"], sample_style_sheet['Heading1'], config, False)
    subtitle = Paragraph("General information", sample_style_sheet['Heading2'])
    attributes = Paragraph("Attributes", sample_style_sheet['Heading2'])

    table_event_general = create_flowable_table_from_event(misp_event, config)
    table_event_attribute = create_flowable_table_from_attributes(misp_event)

    # If you want to output the full json (as debug), just add next line
    # paragraph_2 = Paragraph(str(misp_event.to_json()), sample_style_sheet['Code'])

    # Add all parts to final PDF
    flowables.append(title)
    flowables.append(subtitle)
    flowables.append(table_event_general)

    flowables.append(PageBreak())

    flowables.append(attributes)
    flowables += table_event_attribute

    return flowables


def export_flowables_to_pdf(document, misp_event, flowables, config=None):
    '''
    Export function : creates a pdf from a list of flowables, adding page numbers, etc.
    :param document: A document template
    :param pdf_buffer: / not used
    :param flowables: list of flowables to compile as pdf
    :return:
    '''

    document.build(
        flowables,
        # Partial used to set the metadata
        onFirstPage=partial(set_template, misp_event=misp_event, config=config),  # Pagination for first page
        onLaterPages=partial(set_template, misp_event=misp_event, config=config),  # Pagination for all other page
    )


########################################################################
# "EXTERNAL" exposed METHODS. Meant to be used outside of this class.

def convert_event_in_pdf_buffer(misp_event, config=None):
    '''
    Externally callable function that create a full pdf from a Misp Event
    :param misp_event: a misp event
    :return: a pdf buffer (BytesIO) that contains the pdf
    '''
    # Create a document buffer
    pdf_buffer = BytesIO()

    # DEBUG / TO DELETE : curr_document = SimpleDocTemplate('myfile.pdf')
    curr_document = SimpleDocTemplate(pdf_buffer,
                                      pagesize=PAGESIZE,
                                      topMargin=BASE_MARGIN,
                                      leftMargin=BASE_MARGIN,
                                      rightMargin=BASE_MARGIN,
                                      bottomMargin=BASE_MARGIN)

    # Collect already accessible event's parts to be shown
    flowables = collect_parts(misp_event, config)

    # Export
    export_flowables_to_pdf(curr_document, misp_event, flowables, config)
    pdf_value = pdf_buffer.getvalue()

    # Not sure what to give back ? Buffer ? Buffer.value() ? Base64(buffer.value()) ? ... So far only buffer.value()
    pdf_buffer.close()

    return pdf_value


def get_values_from_buffer(pdf_buffer):
    return pdf_buffer.value()


def get_base64_from_buffer(pdf_buffer):
    return base64.b64encode(pdf_buffer.value())


def get_base64_from_value(pdf_value):
    return base64.b64encode(pdf_value)


def register_to_file(pdf_buffer, file_name):
    # Used for testing purposes only
    pdf_buffer.seek(0)

    with open(file_name, 'wb') as f:
        f.write(pdf_buffer.read())


def register_value_to_file(pdf_value, file_name):
    with open(file_name, 'wb') as f:
        f.write(pdf_value)
