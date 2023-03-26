#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Standard imports
import base64
import logging
import pprint
from io import BytesIO
from pathlib import Path

import sys
import os

if sys.version_info.major >= 3:
    from html import escape
else:
    print("ExportPDF running with Python < 3 : stability and output not guaranteed. Please run exportPDF with at least Python3")

logger = logging.getLogger('pymisp')

# Potentially not installed imports
try:
    from reportlab.pdfgen import canvas  # type: ignore
    from reportlab.pdfbase.pdfmetrics import stringWidth, registerFont  # type: ignore
    from reportlab.pdfbase.ttfonts import TTFont  # type: ignore
    from reportlab.lib import colors  # type: ignore
    from reportlab.lib.pagesizes import A4  # type: ignore

    from reportlab.platypus import SimpleDocTemplate, Paragraph, PageBreak, Table, TableStyle, Flowable, Image, Indenter  # type: ignore

    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle  # type: ignore
    from reportlab.lib.units import mm  # type: ignore
    from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT  # type: ignore

    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False


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

        p = Paragraph("<font color='{}'>{}</font>".format(self.choose_good_text_color(), self.text), style=self.custom_style)
        string_width = stringWidth(self.text, self.custom_style.fontName, self.custom_style.fontSize)

        self.width = string_width + ELONGATION
        self.height = self.custom_style.fontSize

        self.canv.setFillColor(colors.HexColor(self.colour))
        self.canv.roundRect(self.x, self.y + LEFT_INTERNAL_PADDING, self.width, self.height + 2, RADIUS, fill=1)

        p.wrapOn(self.canv, self.width, self.height)
        p.drawOn(self.canv, *self.coord(self.x, self.y + 0.5 * LEFT_INTERNAL_PADDING, mm))


# Copy of pdfexport.py moduleconfig
moduleconfig = ["MISP_base_url_for_dynamic_link", "MISP_name_for_metadata", "Activate_textual_description",
                "Activate_galaxy_description", "Activate_related_events", "Activate_internationalization_fonts",
                "Custom_fonts_path"]

# == Row colors of the table (alternating) ==
EVEN_COLOR = colors.whitesmoke
ODD_COLOR = colors.lightgrey
EVEN_COLOR_GALAXY = colors.powderblue
ODD_COLOR_GALAXY = colors.lavenderblush

# == Lines parameters of the table ==
LINE_COLOR = colors.lightslategray
LINE_THICKNESS = 0.75

# == Columns colors, aligment, fonts, space, size, width, heights ==
FIRST_COL_FONT_COLOR = colors.HexColor("#333333")  # Same as GUI
FIRST_COL_FONT = 'Helvetica-Bold'
FIRST_COL_ALIGNEMENT = TA_CENTER

SECOND_COL_FONT_COLOR = colors.black
SECOND_COL_FONT = 'Helvetica'
SECOND_COL_ALIGNEMENT = TA_LEFT

TEXT_FONT_SIZE = 8
LEADING_SPACE = 7

# Small clusters fonts
SMALL_FONT_SIZE = TEXT_FONT_SIZE - 1
SMALL_LEADING_SPACE = LEADING_SPACE
SMALL_COL1_ALIGMENT = FIRST_COL_ALIGNEMENT
SMALL_COL2_ALIGMENT = TA_JUSTIFY

EXPORT_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
COL_WIDTHS = ['25%', '75%']  # colWidths='*' # Not documented but does exist
ROW_HEIGHT = 5 * mm  # 4.5 * mm (a bit too short to allow vertical align TODO : Fix it)
ROW_HEIGHT_FOR_TAGS = 4 * mm  # 4.5 * mm (a bit too short to allow vertical align TODO : Fix it)

# == Whole document margins and size ==
PAGESIZE = A4  # (140 * mm, 216 * mm)  # width, height
BASE_MARGIN = 5 * mm  # Create a list here to specify each row separately
INDENT_SIZE = 6 * mm  # The Indentation of attribute from object, etc.
INDENT_SIZE_HEADING = 3 * mm  # The Indentation of attribute from object, etc.

# == Parameters for error handling for content too long to fit on a page ==
FRAME_MAX_HEIGHT = 200 * mm  # 500  # Ad hoc value for a A4 page
FRAME_MAX_WIDTH = 145 * mm - INDENT_SIZE  # 356
STR_TOO_LONG_WARNING = "<br/><b><font color=red>[Too long to fit on a single page. Cropped]</font></b>"

# == Parameters for error handling for image too big to fit on a page ==
FRAME_PICTURE_MAX_HEIGHT = 200 * mm  # 195 * mm
FRAME_PICTURE_MAX_WIDTH = 145 * mm - INDENT_SIZE  # 88 * mm

# == Parameters for links management ==
LINK_TYPE = "link"  # Name of the type that define 'good' links
URL_TYPE = "url"  # Name of the type that define 'bad' links
IMAGE_TYPE = "attachment"  # /!\ Not only pictures ! Can be PDF, ...
WARNING_MESSAGE_URL = "'https://Please_consider_that_this_may_be_a_harmful_link'"
NOT_A_PICTURE_MESSAGE = "This attachment is not recognized as an image. Please access this attachment directly from your MISP instance."
GOOD_LINK_COLOR = 'blue'
BAD_LINK_COLOR = 'red'

# == Parameters for description ==
LOW_THREAT_COLOR = 'green'
MEDIUM_THREAT_COLOR = 'orange'
HIGH_THREAT_COLOR = 'red'
EXTERNAL_ANALYSIS_PREFIX = "<i>External analysis from an attribute : </i>"

DEFAULT_VALUE = "No value specified."

# == Parameters for improvement of event's metadata ==

threat_map = {"0": f"<font color ={MEDIUM_THREAT_COLOR}>   undefined (0)</font>",
              "3": f"<font color ={LOW_THREAT_COLOR}>      Low (3)</font>",
              "2": f"<font color ={MEDIUM_THREAT_COLOR}>   Medium (2)</font>",
              "1": f"<font color ={HIGH_THREAT_COLOR}>     High (1)</font>"}

analysis_map = {"0": f"<font color ={HIGH_THREAT_COLOR}>   Initial (0)</font>",
                "1": f"<font color ={MEDIUM_THREAT_COLOR}> Ongoing (1)</font>",
                "2": f"<font color ={LOW_THREAT_COLOR}>    Completed (2)</font>"}

# == Parameters for Sightings ==
POSITIVE_SIGHT_COLOR = 'green'
NEGATIVE_SIGHT_COLOR = 'red'
MISC_SIGHT_COLOR = 'orange'

# == Parameters for galaxies ==
DO_SMALL_GALAXIES = True
FIRST_LEVEL_GALAXY_WIDTHS = ["15%", "85%"]
SECOND_LEVEL_GALAXY_WIDTHS = ["20%", "80%"]
CLUSTER_COLORS = [0]  # or 1
OFFSET = 1

# == Parameters of published value ==
RED_COLOR = '#ff0000'
GREEN_COLOR = '#008000'
YES_ANSWER = f"<font color={GREEN_COLOR}><b> Yes </b></font>"
NO_ANSWER = f"<font color={RED_COLOR}><b> No </b></font>"


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
    return f"{baseurl}events/view/{uuid}"


def create_flowable_table_from_data(data, col_w=COL_WIDTHS, color_alternation=None,
                                    line_alternation=None, galaxy_colors=False):
    '''
    Given a list of flowables items (2D/list of list), creates a Table with styles.
    :param data: list of list of items (flowables is better)
    :return: a Table - with styles - to add to the pdf
    '''
    # Create the table
    curr_table = Table(data, col_w)

    # Aside notes :
    #   colWidths='*' does a 100% and share the space automatically
    #   rowHeights=ROW_HEIGHT if you want a fixed height. /!\ Problems with paragraphs that are spreading everywhere

    # Create styles and set parameters
    alternate_colors_style = alternate_colors_style_generator(data, color_alternation, galaxy_colors)
    lines_style = lines_style_generator(data, line_alternation)
    general_style = general_style_generator()

    # Make the table nicer
    curr_table.setStyle(TableStyle(general_style + alternate_colors_style + lines_style))

    return curr_table


def alternate_colors_style_generator(data, color_alternation, galaxy_colors=True):
    '''
    Create a style, applicable on a table that will be built with parameter's data, with alternated
    background color for each line.
    Modified from : https://gist.github.com/chadcooper/5798392
    :param color_alternation: Allow to control the color scheme. e.g. [0,0,0,1,1,0 ... will produce 3 lines of a color,
    2 lines of another, 1 of the first one ...
    :param data: list of list of items (2D table) to be displayed in the pdf
    :return: A list of 'BACKGROUND' properties, usable in a TableStyle, with alternated colours
    '''

    data_len = len(data)
    color_list = []

    if color_alternation is None:
        # For each line, generate a tuple giving to a line a color
        for each in range(data_len):
            if each % 2 == 0:
                bg_color = EVEN_COLOR if not galaxy_colors else EVEN_COLOR_GALAXY
            else:
                bg_color = ODD_COLOR if not galaxy_colors else ODD_COLOR_GALAXY
            color_list.append(('BACKGROUND', (0, each), (-1, each), bg_color))
    else:
        # if data_len > len(color_alternation) :
        #    logger.warning("Line alternation for PDF display isn't correctly set. Looping on given values only.")

        # For each line, generate a tuple giving to a line a color
        for each in range(data_len):
            if color_alternation[each % len(color_alternation)] % 2 == 0:
                bg_color = EVEN_COLOR if not galaxy_colors else EVEN_COLOR_GALAXY
            else:
                bg_color = ODD_COLOR if not galaxy_colors else ODD_COLOR_GALAXY
            color_list.append(('BACKGROUND', (0, each), (-1, each), bg_color))

    return color_list


def lines_style_generator(data, line_alternation):
    '''
    Create a style, applicable on a table that will be built with parameter's data,
    that draw colored lines above and below each line of the table
    :param line_alternation: Allow to control the color scheme. e.g. [0,0,0,1,1,0 ... will produce with a line up it,
    2 lines without, 1 of the first one ...
    :param data:  list of list of items (2D table) to be displayed in the pdf
    :return: A list of 'LINE****' properties, usable in a TableStyle, that are drawing lines
    '''
    data_len = len(data)
    lines_list = []

    if line_alternation is None:
        # For each line, generate a tuple giving to a line a color
        for each in range(data_len):
            lines_list.append(('LINEABOVE', (0, each), (-1, each), LINE_THICKNESS, LINE_COLOR))

        # Last line
        lines_list.append(('LINEBELOW', (0, len(data) - 1), (-1, len(data) - 1), LINE_THICKNESS, LINE_COLOR))
    elif line_alternation == []:
        # Do nothing
        return lines_list
    else:
        # if data_len > len(line_alternation) :
        #    logger.warning("Line alternation for PDF display isn't correctly set. Looping on given values only.")

        # For each line, generate a tuple giving to a line a color
        for each in range(data_len):
            if each == 0 or line_alternation[each % len(line_alternation)] != line_alternation[(each - 1) % len(line_alternation)]:
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


def internationalize_font(config=None):
    global FIRST_COL_FONT
    global SECOND_COL_FONT

    if is_in_config(config, 6) and config[moduleconfig[6]] != "":
        # Handle custom fonts. Has to be TrueType = one TTF only
        fonts_path_custom = config[moduleconfig[6]]

        if fonts_path_custom and os.path.isfile(fonts_path_custom):
            registerFont(TTFont("custom_font", fonts_path_custom))
            FIRST_COL_FONT = 'custom_font'
            SECOND_COL_FONT = 'custom_font'

        else:
            logger.error(f"Trying to load a custom font, unable to access the file. Path: {fonts_path_custom}")
    else:
        ''' Handle provided NOTO fonts (CJK only for now)
            # Available fonts :
            NotoSansCJKtc - DemiLight.ttf
            NotoSansCJKtc - Regular.ttf
            NotoSansCJKtc - Black.ttf
            NotoSansCJKtc - Light.ttf
            NotoSansCJKtc - Thin.ttf
            NotoSansCJKtc - Bold.ttf
            NotoSansCJKtc - Medium.ttf
        '''
        font_path = Path(sys.modules['pymisp'].__file__).parent / 'tools' / 'pdf_fonts' / 'Noto_TTF'

        noto_bold = font_path / "NotoSansCJKtc-Bold.ttf"
        noto = font_path / "NotoSansCJKtc-DemiLight.ttf"

        if noto_bold.is_file() and noto.is_file():
            registerFont(TTFont("Noto", noto))
            registerFont(TTFont("Noto-bold", noto_bold))

            FIRST_COL_FONT = 'Noto-bold'
            SECOND_COL_FONT = 'Noto'
        else:
            logger.error(f"Trying to load a custom (internationalization) font, unable to access the file: {noto_bold}")


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


def get_clusters_table_styles():
    '''
    Create and returns the two mains styles for the columns of a table describing a cluster.
    :return: two styles, one for each columns of the document, describing the MISP object.
    '''
    col1, col2 = get_table_styles()

    custom_body_style_col_1 = ParagraphStyle(name='Column_1_small',
                                             parent=col1,
                                             fontName=FIRST_COL_FONT,
                                             textColor=FIRST_COL_FONT_COLOR,
                                             fontSize=SMALL_FONT_SIZE,
                                             leading=SMALL_LEADING_SPACE,
                                             alignment=SMALL_COL1_ALIGMENT)

    custom_body_style_col_2 = ParagraphStyle(name='Column_2_small',
                                             parent=col2,
                                             fontName=SECOND_COL_FONT,
                                             textColor=SECOND_COL_FONT_COLOR,
                                             fontSize=SMALL_FONT_SIZE,
                                             leading=SMALL_LEADING_SPACE,
                                             alignment=SMALL_COL2_ALIGMENT)

    return custom_body_style_col_1, custom_body_style_col_2


########################################################################
# Checks

def safe_string(bad_str):
    return escape(str(bad_str))


def is_safe_value(value):
    return (value is not None
            and value != "")


def is_safe_table(value):
    return (value is not None
            and value != [])


def is_safe_attribute(curr_object, attribute_name):
    return (hasattr(curr_object, attribute_name)
            and getattr(curr_object, attribute_name) is not None
            and getattr(curr_object, attribute_name) != "")


def is_safe_dict_attribute(curr_object, attribute_name):
    return (attribute_name in curr_object
            and curr_object[attribute_name] is not None
            and curr_object[attribute_name] != "")


def is_safe_attribute_table(curr_object, attribute_name):
    return (hasattr(curr_object, attribute_name)
            and getattr(curr_object, attribute_name) is not None
            and getattr(curr_object, attribute_name) != [])


def is_in_config(config, index):
    return config is not None and moduleconfig[index] in config


########################################################################
# Functions grouped by misp object type


class Value_Formatter():
    '''
    "item" parameter should be as follow, a list of name, in order :
        ["Name to be print in the pdf", "json property access name",
        " Name to be display if no values found in the misp_event"]
    '''

    # ----------------------------------------------------------------------
    def __init__(self, config, col1_style, col2_style, col1_small_style, col2_small_style):
        self.config = config
        self.col1_style = col1_style
        self.col2_style = col2_style
        self.col1_small_style = col1_small_style
        self.col2_small_style = col2_small_style

    # ----------------------------------------------------------------------
    ########################################################################
    # General attribut formater
    def get_col1_paragraph(self, dirty_string, do_small=False):
        if do_small:
            return self.get_unoverflowable_paragraph(dirty_string, self.col1_small_style, do_small=do_small)
        return self.get_unoverflowable_paragraph(dirty_string, self.col1_style, do_small=do_small)

    def get_unoverflowable_paragraph(self, dirty_string, curr_style=None, do_escape_string=True, do_small=False):
        '''
        Create a paragraph that can fit on a cell displayed one page maximum.
        This method can be improved (get the exact size of the current frame, and limit the paragraph to this size.)
        KeepInFrame may give a nicer solution (not for me so far)
        :param do_escape_string: Activate the escaping (may be useful to add inline HTML, e.g. hyperlinks)
        :param dirty_string: String to transform
        :param curr_style: Style to apply to the returned paragraph
        :return:
        '''
        if do_escape_string:
            sanitized_str = safe_string(dirty_string)
        else:
            sanitized_str = dirty_string

        if curr_style is None:
            if do_small:
                curr_style = self.col2_small_style
            else:
                curr_style = self.col2_style

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
                w, h = Paragraph(limited_string + STR_TOO_LONG_WARNING, curr_style).wrap(FRAME_MAX_WIDTH,
                                                                                         FRAME_MAX_HEIGHT)
                max_carac_amount = int(max_carac_amount / 2)

            if w <= FRAME_MAX_WIDTH and h <= FRAME_MAX_HEIGHT:
                answer_paragraph = Paragraph(limited_string + STR_TOO_LONG_WARNING, curr_style)
            else:
                # We may still end with a not short enough string
                answer_paragraph = Paragraph(STR_TOO_LONG_WARNING, curr_style)

        return answer_paragraph

    def get_value_link_to_event(self, uuid=None, text=None, curr_style=None, color=True):
        '''
        Returns a flowable paragraph to add to the pdf given the misp_event uuid, with or without link
        :param curr_style: style to apply to the returned paragraph
        :param text: text to which the link will be anchored
        :param uuid: used to construct the link
        :param color: Boolean to give a color or not to the generate link (good link color)
        :return: a Paragraph to add in the pdf, regarding the values of "uuid"
        '''

        if curr_style is None:
            curr_style = self.col2_style

        escape = True
        # Does MispEvent has the attribute ?
        if is_safe_value(text):
            # It has the requested attribute .. building upon it.

            # Does misp_object has an uuid and do we know the baseurl ?
            if is_safe_value(uuid) and is_in_config(self.config, 0):
                # We can build links
                escape = False
                curr_uuid = str(is_safe_value(uuid))
                curr_baseurl = self.config[moduleconfig[0]]
                curr_url = uuid_to_url(curr_baseurl, curr_uuid)
                html_url = "<a href={}>{}</a>".format(curr_url, safe_string(text))

                if color:
                    # They want fancy colors
                    html_url = f"<font color={GOOD_LINK_COLOR}>{html_url}</font>"
                # Construct final paragraph
                answer = html_url

            else:
                # We can't build links
                answer = text

        else:
            # No it doesn't, so we directly give the default answer
            answer = DEFAULT_VALUE

        if not escape:
            return self.get_unoverflowable_paragraph(answer, curr_style=curr_style, do_escape_string=False)
        return self.get_unoverflowable_paragraph(answer, curr_style=curr_style)

    ########################################################################
    # Specific attribute formater

    def get_date_value(self, date=None):
        '''
        Returns a flowable paragraph to add to the pdf given the misp_event date
        :param date: MISP_EVENT date to be formatted
        :return: a Paragraph to add in the pdf, regarding the values of "date"
        '''
        answer = DEFAULT_VALUE
        if is_safe_value(date):
            answer = safe_string(date)

        return self.get_unoverflowable_paragraph(answer)

    def get_owner_value(self, owner=None):
        '''
        Returns a flowable paragraph to add to the pdf given the misp_event owner
        :param owner: MISP_EVENT owner to be formatted
        :return: a Paragraph to add in the pdf, regarding the values of "owner"
        '''
        answer = DEFAULT_VALUE

        if is_safe_value(owner):
            answer = safe_string(owner)

        return self.get_unoverflowable_paragraph(answer)

    def get_threat_value(self, threat_level=None):
        '''
        Returns a flowable paragraph to add to the pdf given the misp_event threat
        :param threat_level: MISP_EVENT threat level (int) to be formatted
        :return: a Paragraph to add in the pdf, regarding the values of "threat"
        '''
        answer = "No threat level specified."

        if is_safe_value(threat_level) and str(threat_level) in threat_map:
            answer = threat_map[safe_string(threat_level)]

        return self.get_unoverflowable_paragraph(answer, do_escape_string=False)

    def get_analysis_value(self, analysis_level=None):
        '''
        Returns a flowable paragraph to add to the pdf given the misp_event analysis
        :param analysis_level: MISP_EVENT analysis level (int) to be formatted
        :return: a Paragraph to add in the pdf, regarding the values of "analysis"
        '''
        answer = "No analysis status specified."

        if is_safe_value(analysis_level) and str(analysis_level) in analysis_map:
            answer = analysis_map[safe_string(analysis_level)]

        return self.get_unoverflowable_paragraph(answer, do_escape_string=False)

    def get_timestamp_value(self, timestamp=None):
        '''
        Returns a flowable paragraph to add to the pdf given the misp_event timestamp
        :param timestamp: MISP_EVENT timestamp (int) to be formatted
        :return: a Paragraph to add in the pdf, regarding the values of "timestamp"
        '''
        answer = "No timestamp specified."

        if is_safe_value(timestamp):
            answer = safe_string(timestamp.strftime(EXPORT_DATE_FORMAT))

        return self.get_unoverflowable_paragraph(answer)

    def get_creator_organisation_value(self, creator=None):
        '''
        Returns a flowable paragraph to add to the pdf given the misp_event creator organisation
        :param creator: MISP_EVENT creator (not the name directly) to be formatted
        :return: a Paragraph to add in the pdf, regarding the values of "creator organisation"
        '''
        answer = DEFAULT_VALUE

        if is_safe_value(creator) and is_safe_value(creator.get('name', None)):
            answer = safe_string(creator.get('name', None))

        return self.get_unoverflowable_paragraph(answer)

    def get_attributes_number_value(self, attributes=None):
        '''
        Returns a flowable paragraph to add to the pdf given the misp_event attributes
        :param attributes: MISP_EVENT attributes list to be formatted
        :return: a Paragraph to add in the pdf, regarding the values of "attributes"
        '''
        answer = "0 - no attribute"

        if is_safe_table(attributes):
            answer = safe_string(len(attributes))

        return self.get_unoverflowable_paragraph(answer)

    def get_published_value(self, published_bool=None, published_timestamp=None):
        '''
        Returns a flowable paragraph to add to the pdf given the misp_event published/published_time
        More information on how to play with paragraph into reportlab cells :
        https://stackoverflow.com/questions/11810008/reportlab-add-two-paragraphs-into-one-table-cell
        :param published_timestamp: MISP_EVENT published_timestamp to be formatted
        :param published_bool: MISP_EVENT published boolean value
        :return: a Paragraph to add in the pdf, regarding the values of "published"/"publish_timestamp"
        '''

        # Formatting similar to MISP Event web view
        if is_safe_value(published_bool):
            if published_bool:  # == True
                answer = YES_ANSWER
                if is_safe_value(published_timestamp):
                    # Published and have published date
                    answer += '({})'.format(published_timestamp.strftime(EXPORT_DATE_FORMAT))
                else:
                    # Published without published date
                    answer += "(no date)"

            else:
                # Not published
                answer = NO_ANSWER
        else:
            # Does not have a published attribute
            answer = DEFAULT_VALUE

        return self.get_unoverflowable_paragraph(answer, do_escape_string=False)

    def get_image_value(self, image_buffer=None):
        '''
        Returns a flowable image to add to the pdf given the misp attribute type and data
        :param image_buffer: an image contained an attribute, for example (buffer / Base 64)
        :return: a flowable image to add in the pdf, regarding the values of "data"
        '''

        try:
            # Get the image
            buf = image_buffer  # TODO : Do verification on the buffer ?

            # Create image within a bounded box (to allow pdf creation)
            img = Image(buf, width=FRAME_PICTURE_MAX_WIDTH, height=FRAME_PICTURE_MAX_HEIGHT, kind='bound')
            answer = img

        except OSError:
            logger.error("Trying to add an attachment during PDF export generation. Attachement joining failed. Attachement may not be an image.")
            answer = self.get_unoverflowable_paragraph(f"<font color={BAD_LINK_COLOR}>{NOT_A_PICTURE_MESSAGE}</font>", do_escape_string=False)

        return answer

    def get_good_link(self, value=None):
        '''
        Returns a flowable paragraph to add to the pdf given the misp_attribute value, if this is a link
        :param value: string, of an url to format as a good link
        :return: a Paragraph to add in the pdf, regarding the values of this "link" attribute
        '''
        return self.get_unoverflowable_paragraph(f"<font color={GOOD_LINK_COLOR}><a href={value}>{value}</a></font>", do_escape_string=False)

    def get_bad_link(self, value=None):
        '''
        Returns a flowable paragraph to add to the pdf given the misp_attribute value, if this is a link
        :param value: string, of an url to format as a bad link
        :return: a Paragraph to add in the pdf, regarding the values of this "url" attribute
        '''
        return self.get_unoverflowable_paragraph(f"<font color={BAD_LINK_COLOR}><a href={WARNING_MESSAGE_URL}>{value}</a></font>", do_escape_string=False)

    def get_good_or_bad_link(self, value=None, type=None):
        '''
        Returns a flowable paragraph to add to the pdf given the misp_attribute value, if this is a link or an url
        :param type: Type of the url (url or link) as a string
        :param value: string, of an url to format as a good or bad link
        :return: a Paragraph to add in the pdf, regarding the values of this "link" or "url" attribute
        '''

        answer = self.get_unoverflowable_paragraph("Not an URL")

        # Handle "Good" links
        if type == LINK_TYPE:
            answer = self.get_good_link(value=value)
        # Handle "bad "links
        elif type == URL_TYPE:
            answer = self.get_bad_link(value=value)

        return answer

    def get_galaxy_name_value(self, misp_galaxy):
        '''
        Create a displayable name for a galaxy
        :param misp_galaxy: MISP_EVENT galaxy, as an object (not a list)
        :return: a Flowable Paragraph to add in the pdf, regarding the value of the MISP galaxy
        '''
        answer = DEFAULT_VALUE

        if is_safe_dict_attribute(misp_galaxy, 'name'):
            answer = '{} <i>from</i> {}:{}'.format(safe_string(misp_galaxy['name']),
                                                   safe_string(misp_galaxy["namespace"]),
                                                   safe_string(misp_galaxy["type"]))

        return self.get_unoverflowable_paragraph(answer, do_small=True)

    def get_galaxy_cluster_name_value(self, misp_cluster, do_small=False):
        '''
        Create a displayable name for a cluster
        :param misp_cluster: a MISP_EVENT's GALAXY's cluster, as an object (not a list)
        :param do_small: Compress the display (reduce the size of the flowable paragraph, fonts, etc.)
        :return: a Flowable Paragraph to add in the pdf, regarding the value of the MISP cluster
        '''
        # TODO : To be changed when Clust becomes an object
        tmp_text = ""

        if is_safe_dict_attribute(misp_cluster, 'value'):
            tmp_text += safe_string(misp_cluster['value'])

            # if is_safe_dict_attribute(misp_cluster, item[3]) :
            # tmp_text += "<br/><i>Source :</i> " + misp_cluster[item[3]]

            if is_safe_dict_attribute(misp_cluster, "meta") and is_safe_dict_attribute(misp_cluster["meta"], "synonyms"):
                tmp_text += " <br/><i>Synonyms :</i> "
                for i, synonyme in enumerate(misp_cluster["meta"]["synonyms"]):
                    if i != 0:
                        tmp_text += " / "
                    tmp_text += safe_string(synonyme)

            return self.get_unoverflowable_paragraph(tmp_text, do_escape_string=False, do_small=do_small)
        return self.get_unoverflowable_paragraph(DEFAULT_VALUE, do_small=do_small)


class Event_Metadata():

    # ----------------------------------------------------------------------
    def __init__(self, config, value_formatter):
        self.config = config
        self.value_formatter = value_formatter
        self.sample_style_sheet = getSampleStyleSheet()

    # ----------------------------------------------------------------------

    ########################################################################
    # General Event's Attributes formater

    def create_flowable_table_from_event(self, misp_event):
        '''
        Returns Table presenting a MISP event
        :param misp_event: A misp event (complete or not)
        :return: a table that can be added to a pdf
        '''

        data = []
        flowable_table = []

        # Manual addition
        # UUID
        data.append([self.value_formatter.get_col1_paragraph("UUID"),
                     self.value_formatter.get_value_link_to_event(uuid=misp_event.get('uuid', None),
                                                                  text=misp_event.get('uuid', None))])

        # Date
        data.append({self.value_formatter.get_col1_paragraph("Date"),
                     self.value_formatter.get_date_value(date=misp_event.get('date', None))})

        # Owner
        data.append([self.value_formatter.get_col1_paragraph("Owner org"),
                     self.value_formatter.get_owner_value(owner=misp_event.get('owner', None))])

        # Threat
        data.append([self.value_formatter.get_col1_paragraph("Threat level"),
                     self.value_formatter.get_threat_value(threat_level=misp_event.get('threat_level_id', None))])

        # Analysis
        data.append([self.value_formatter.get_col1_paragraph("Analysis"),
                     self.value_formatter.get_analysis_value(analysis_level=misp_event.get('analysis', None))])

        # Info
        data.append([self.value_formatter.get_col1_paragraph("Info"),
                     self.value_formatter.get_value_link_to_event(uuid=misp_event.get('uuid', None),
                                                                  text=misp_event.get('info', None))])

        # Timestamp
        data.append([self.value_formatter.get_col1_paragraph("Event date"),
                     self.value_formatter.get_timestamp_value(timestamp=misp_event.get('timestamp', None))])

        # Published
        data.append([self.value_formatter.get_col1_paragraph("Published"),
                     self.value_formatter.get_published_value(published_bool=misp_event.get('published', None),
                                                              published_timestamp=misp_event.get('publish_timestamp', None))])

        # Creator organisation
        data.append([self.value_formatter.get_col1_paragraph("Creator Org"),
                     self.value_formatter.get_creator_organisation_value(creator=misp_event.get('Orgc', None))])

        # Number of Attributes
        data.append([self.value_formatter.get_col1_paragraph("# Attributes"),
                     self.value_formatter.get_attributes_number_value(attributes=misp_event.get('Attribute', None))])

        # Tags
        curr_Tags = Tags(self.config, self.value_formatter)
        data.append([self.value_formatter.get_col1_paragraph("Tags"),
                     curr_Tags.get_tag_value(tags=misp_event.get('Tag', None))])

        flowable_table.append(create_flowable_table_from_data(data))

        # Correlation
        if is_safe_table(misp_event.get('RelatedEvent', None)) and is_in_config(self.config, 4):
            flowable_table += self.get_correlation_values(related_events=misp_event.get('RelatedEvent', None))

        # Galaxies
        if is_safe_attribute_table(misp_event, "Related Galaxies") and is_in_config(self.config, 3):
            flowable_table.append(PageBreak())
            curr_Galaxy = Galaxy(self.config, self.value_formatter)
            flowable_table += curr_Galaxy.get_galaxy_value(galaxies=misp_event.get('Galaxy', None))

        return flowable_table

    def create_reduced_flowable_table_from_event(self, misp_event):
        '''
        Returns Table presenting a MISP event
        :param misp_event: A misp event (complete or not)
        :return: a table that can be added to a pdf
        '''

        data = []
        flowable_table = []

        # Manual addition
        # UUID
        data.append([self.value_formatter.get_col1_paragraph("UUID"),
                     self.value_formatter.get_value_link_to_event(uuid=misp_event.get('uuid', None),
                                                                  text=misp_event.get('uuid', None))])

        # Info
        data.append([self.value_formatter.get_col1_paragraph("Info"),
                     self.value_formatter.get_value_link_to_event(uuid=misp_event.get('uuid', None),
                                                                  text=misp_event.get('info', None))])

        # Timestamp
        data.append([self.value_formatter.get_col1_paragraph("Event date"),
                     self.value_formatter.get_timestamp_value(timestamp=misp_event.get('timestamp', None))])

        flowable_table.append(create_flowable_table_from_data(data))

        return flowable_table

    def create_flowable_description_from_event(self, misp_event):
        '''
        Returns a Paragraph presenting a MISP event
        :param misp_event: A misp event (complete or not)
        :return: a paragraph that can be added to a pdf
        '''

        '''
        The event "{EventName}" | that occurred on {EventDate}, | had been shared by {Organisation Name} | on the {Date}.
        '''

        text = ""

        if is_safe_attribute(misp_event, 'info'):
            text += "The event '"
            text += safe_string(misp_event.info)
            text += "'"
        else:
            text += "This event"

        if is_safe_attribute(misp_event, 'timestamp'):
            text += " that occurred on "
            text += safe_string(misp_event.timestamp.strftime(EXPORT_DATE_FORMAT))
            text += ","

        text += " had been shared by "
        if is_safe_attribute(misp_event, 'Orgc') and is_safe_attribute(misp_event, 'name'):
            text += safe_string(misp_event.Orgc.name)
        else:
            text += " an unknown organisation"

        if is_safe_attribute(misp_event, 'date'):
            text += " on the "
            text += safe_string(misp_event.date)
        else:
            text += " on an unknown date"
        text += "."

        '''
        The threat level of this event is {ThreatLevel} and the analysis that was made of this event is {AnalysisLevel}.
        '''

        text += " The threat level of this event is "
        if is_safe_attribute(misp_event, 'threat_level_id') and safe_string(misp_event.threat_level_id) in threat_map:
            text += threat_map[safe_string(misp_event.threat_level_id)]
        else:
            text += " unknown"

        text += " and the analysis that was made of this event is "
        if is_safe_attribute(misp_event, 'analysis') and safe_string(misp_event.analysis) in analysis_map:
            text += analysis_map[safe_string(misp_event.analysis)]
        else:
            text += " undefined"
        text += "."

        '''
        The event is currently {Published} and has associated attributes {Attribute Number}.
        '''

        text += " The event is currently "
        if is_safe_attribute(misp_event, 'published') and misp_event.published:
            text += " published"
            if is_safe_attribute(misp_event, 'publish_timestamp'):
                text += " since " + misp_event.publish_timestamp.strftime(EXPORT_DATE_FORMAT)
        else:
            text += " private"

        # Number of Attributes
        text += ", has "
        if is_safe_attribute_table(misp_event, 'Attribute'):
            text += safe_string(len(misp_event.Attribute))
        else:
            text += " 0"

        text += " associated attributes"

        # Number of Objects
        text += " and has "
        if is_safe_attribute_table(misp_event, 'Object'):
            text += safe_string(len(misp_event.Object))
        else:
            text += " 0"

        text += " associated objects."

        curr_attributes = Attributes(self.config, self.value_formatter)
        tmp_text = curr_attributes.get_external_analysis(misp_event)

        if tmp_text != "":
            text += "<br/>"
            text += tmp_text
            text += "<br/>"

        '''
        For more information on the event, please consult the rest of the document
        '''
        text += "<br/>For more information on the event, please consult following information."

        description_style = ParagraphStyle(name='Description', parent=self.value_formatter.col2_style,
                                           alignment=TA_JUSTIFY)

        return Paragraph(text, description_style)

    def get_correlation_values(self, related_events=None):
        '''
        Returns a flowable paragraph to add to the pdf given the misp_event correlated events
        :return: a Paragraph to add in the pdf, regarding the values of "RelatedEvent"
        '''
        flowable_table = []

        flowable_table.append(PageBreak())
        flowable_table.append(Paragraph("Related Events", self.sample_style_sheet['Heading3']))

        if is_safe_table(related_events):
            for i, evt in enumerate(related_events):
                flowable_table.append(Indenter(left=INDENT_SIZE_HEADING))
                flowable_table.append(
                    Paragraph("Related Event #" + str(i + OFFSET), self.sample_style_sheet['Heading4']))
                flowable_table.append(Indenter(left=-INDENT_SIZE_HEADING))

                flowable_table += self.create_reduced_flowable_table_from_event(evt['Event'])
                i += 1
        else:
            return flowable_table.append(self.value_formatter.get_unoverflowable_paragraph(DEFAULT_VALUE))

        return flowable_table


class Attributes():

    # ----------------------------------------------------------------------
    def __init__(self, config, value_formatter):
        self.config = config
        self.value_formatter = value_formatter
        self.sample_style_sheet = getSampleStyleSheet()

    # ----------------------------------------------------------------------

    def create_flowable_table_from_attributes(self, misp_event):
        '''
        Returns a list of flowables representing the list of attributes of a misp event.
        The list is composed alternatively of headers and tables, to add to the pdf
        :param misp_event: A misp event
        :return: a table of flowables
        '''
        flowable_table = []
        i = 0

        if is_safe_attribute_table(misp_event, "Attribute"):
            # There is some attributes for this object
            for item in getattr(misp_event, "Attribute"):
                # you can use a spacer instead of title to separate paragraph: flowable_table.append(Spacer(1, 5 * mm))
                flowable_table.append(Indenter(left=INDENT_SIZE_HEADING))
                flowable_table.append(Paragraph("Attribute #" + str(i + OFFSET), self.sample_style_sheet['Heading4']))
                flowable_table.append(Indenter(left=-INDENT_SIZE_HEADING))

                flowable_table += self.create_flowable_table_from_one_attribute(item)
                i += 1
        else:
            # No attributes for this object
            flowable_table.append(Paragraph("No attributes", self.sample_style_sheet['Heading4']))

        return flowable_table

    def create_flowable_table_from_one_attribute(self, misp_attribute):
        '''
        Returns a table (flowalbe) representing the attribute
        :param misp_attribute: A misp attribute
        :return: a table representing this misp's attribute's attributes, to add to the pdf as a flowable
        '''

        data = []
        flowable_table = []

        # To reduce code size, and automate it a bit, triplet (Displayed Name, object_attribute_name,
        # to_display_if_not_present) are store in the following list
        list_attr_automated = [["UUID", 'uuid', "None"],
                               ["Category", 'category', "None"],
                               ["Comment", 'comment', "None"],
                               ["Type", 'type', "None"],
                               ["Value", 'value', "None"]]

        # Handle the special case of links
        STANDARD_TYPE = True
        if is_safe_value(misp_attribute.get('type', None)) and (misp_attribute.type in [LINK_TYPE, URL_TYPE]):
            # Special case for links
            STANDARD_TYPE = False

        # Automated adding of standard (python) attributes of the misp event
        for item in list_attr_automated:
            if is_safe_attribute(misp_attribute, item[1]) and (STANDARD_TYPE or item[1] != 'value'):
                # The attribute exists, we fetch it and create the row
                data.append([self.value_formatter.get_col1_paragraph(item[0]),
                             self.value_formatter.get_unoverflowable_paragraph(getattr(misp_attribute, item[1]))])

            # The attribute does not exist, you may want to print a default text on the row. Then use as a else case :
            # data.append([Paragraph(item[0], col1_style), Paragraph(item[2], col2_style)])

        # Handle Special case for links (Value) - There were not written in the previous loop
        if not STANDARD_TYPE and is_safe_value(misp_attribute.get('value', None)):
            data.append([self.value_formatter.get_col1_paragraph("Value"),
                         self.value_formatter.get_good_or_bad_link(value=misp_attribute.get('value', None),
                                                                   type=misp_attribute.get('type', None))])

        # Handle pictures
        if is_safe_value(misp_attribute.get('data', None)) and misp_attribute.type == IMAGE_TYPE:
            data.append([self.value_formatter.get_col1_paragraph("Data"),
                         self.value_formatter.get_image_value(misp_attribute.get('data', None))])

        # Tags
        curr_Tags = Tags(self.config, self.value_formatter)

        if is_safe_table(misp_attribute.get('Tag', None)):
            data.append(
                [self.value_formatter.get_col1_paragraph("Tags"),
                 curr_Tags.get_tag_value(tags=misp_attribute.get('Tag', None))])

        # Sighting
        curr_Sighting = Sightings(self.config, self.value_formatter)

        if is_safe_table(misp_attribute.get('Sighting', None)):
            data.append([self.value_formatter.get_col1_paragraph("Sighting"),
                         curr_Sighting.create_flowable_paragraph_from_sightings(sightings=misp_attribute.get('Sighting', None))])

        flowable_table.append(create_flowable_table_from_data(data))

        # Galaxies
        if is_safe_attribute_table(misp_attribute, "Galaxy") and is_in_config(self.config, 3):
            curr_Galaxy = Galaxy(self.config, self.value_formatter)
            flowable_table.append(Indenter(left=INDENT_SIZE))
            flowable_table += curr_Galaxy.get_galaxy_value(misp_attribute.get('Galaxy', None))
            flowable_table.append(Indenter(left=-INDENT_SIZE))

        return flowable_table

    def get_external_analysis(self, misp_event):
        '''
        Returns a string representing the list of external analysis comments of a misp event.
        :param misp_event: A misp event
        :return: a table of flowables
        '''
        text = ""

        if is_safe_attribute_table(misp_event, "Attribute"):
            # There is some attributes for this object
            for attribute in getattr(misp_event, "Attribute"):
                # If the current event is an external analysis and a comment
                if (is_safe_attribute(attribute, "value")
                        and is_safe_attribute(attribute, "category")
                        and is_safe_attribute(attribute, "type")
                        and getattr(attribute, "category") == "External analysis"
                        and getattr(attribute, "type") == "comment"):
                    # We add it to the description
                    text += "<br/>" + EXTERNAL_ANALYSIS_PREFIX + safe_string(getattr(attribute, "value"))

        return text


class Tags():

    # ----------------------------------------------------------------------
    def __init__(self, config, value_formatter):
        self.config = config
        self.value_formatter = value_formatter

    # ----------------------------------------------------------------------

    def get_tag_value(self, tags=None):
        '''
        Returns a flowable paragraph to add to the pdf given the misp_event tags
        :return: a Paragraph to add in the pdf, regarding the values of "tags"
        '''
        if is_safe_table(tags):
            table_event_tags = self.create_flowable_table_from_tags(tags=tags)
            return table_event_tags
        return self.value_formatter.get_unoverflowable_paragraph(DEFAULT_VALUE)

    def create_flowable_table_from_tags(self, tags=None):
        '''
        Returns a Table (flowable) to add to a pdf, representing the list of tags of an event or a misp event
        :param misp_event: A misp event
        :return: a table of flowable to add to the pdf
        '''

        flowable_table = []
        i = 0

        if is_safe_table(tags):
            # There is some tags for this object
            for curr_tag in tags:
                flowable_table.append(create_flowable_tag(curr_tag))
                i += 1
            answer_tags = self.create_tags_table_from_data(flowable_table)
        else:
            # No tags for this object
            answer_tags = [self.value_formatter.get_unoverflowable_paragraph("No tags")]

        return answer_tags

    def create_tags_table_from_data(self, data):
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


class Sightings():

    # ----------------------------------------------------------------------
    def __init__(self, config, value_formatter):
        self.config = config
        self.value_formatter = value_formatter

    # ----------------------------------------------------------------------

    def create_flowable_paragraph_from_sightings(self, sightings=None):
        '''
        Returns a Table (flowable) to add to a pdf, representing the list of sightings of an event or a misp event
        :param misp_event: A misp event
        :return: a table of flowable to add to the pdf
        '''

        i = 0

        # No tags for this object
        answer = "No sighting"

        list_sighting = [0, 0, 0]
        if is_safe_table(sightings):
            # There is some tags for this object
            for curr_item in sightings:
                # TODO : When Sightings will be object : if is_safe_attribute(item, "type"):
                if is_safe_dict_attribute(curr_item, "type"):
                    # Store the likes/dislikes depending on their types
                    list_sighting[int(curr_item["type"])] += 1
                i += 1

            # Create the sighting text
            sight_text = f"<font color ={POSITIVE_SIGHT_COLOR}> Positive: {list_sighting[0]}</font>"
            sight_text += f" / <font color ={NEGATIVE_SIGHT_COLOR}> Negative: {list_sighting[1]}</font>"
            sight_text += f" / <font color ={MISC_SIGHT_COLOR}> Misc.: {list_sighting[2]}</font>"

            answer = sight_text

        return self.value_formatter.get_unoverflowable_paragraph(answer, do_escape_string=False)


class Object():

    # ----------------------------------------------------------------------
    def __init__(self, config, value_formatter):
        self.config = config
        self.value_formatter = value_formatter
        self.sample_style_sheet = getSampleStyleSheet()

    # ----------------------------------------------------------------------

    def create_flowable_table_from_objects(self, objects=None):
        '''
        Returns a list of flowables representing the list of objects of a misp event.
        The list is composed of a serie of
        [ header object, table of object information, [ header of attribute, table of attribute]*] to add to the pdf
        :param misp_event: A misp event
        :return: a table of flowables
        '''

        flowable_table = []
        i = 0
        if is_safe_table(objects):

            # There is a list of objects
            for item in objects:
                # you can use a spacer instead of title to separate paragraph: flowable_table.append(Spacer(1, 5 * mm))
                flowable_table.append(Indenter(left=INDENT_SIZE_HEADING))
                flowable_table.append(Paragraph("Object #" + str(i + OFFSET), self.sample_style_sheet['Heading3']))
                flowable_table.append(Indenter(left=-INDENT_SIZE_HEADING))
                flowable_table += self.create_flowable_table_from_one_object(item, self.config)
                i += 1
        else:
            # No object found
            flowable_table.append(Paragraph("No object", self.sample_style_sheet['Heading3']))

        return flowable_table

    def create_flowable_table_from_one_object(self, misp_object, config=None):
        '''
        Returns a table (flowable) representing the object
        :param misp_attribute: A misp object
        :return: a table representing this misp's object's attributes, to add to the pdf as a flowable
        '''
        data = []

        # To reduce code size, and automate it a bit, triplet (Displayed Name, object_attribute_name,
        # to_display_if_not_present) are store in the following list
        list_attr_automated = [["UUID", 'uuid', "None"],
                               ["Description", 'description', "None"],
                               ["Meta Category", 'meta-category', "None"],
                               ["Object Name", 'name', "None"],
                               ["Comment", 'comment', "None"],
                               ["Type", 'type', "None"]]

        # Automated adding of standard (python) attributes of the misp object
        for item in list_attr_automated:
            if is_safe_attribute(misp_object, item[1]):
                # The attribute exists, we fetch it and create the row
                data.append([self.value_formatter.get_col1_paragraph(item[0]),
                             self.value_formatter.get_unoverflowable_paragraph(getattr(misp_object, item[1]))])

            # The attribute does not exist, you may want to print a default text on the row. Then use as a else case :
            # data.append([Paragraph(item[0], col1_style), Paragraph(item[2], col2_style)])

        # Timestamp
        data.append([self.value_formatter.get_col1_paragraph("Object date"),
                     self.value_formatter.get_timestamp_value(misp_object.get('timestamp', None))])

        # Transform list of value in a table
        data = [create_flowable_table_from_data(data)]

        # Handle all the attributes
        if is_safe_value(misp_object.get("Attribute", None)):
            curr_attributes = Attributes(self.config, self.value_formatter)
            data.append(Indenter(left=INDENT_SIZE))
            data += curr_attributes.create_flowable_table_from_attributes(misp_object)
            data.append(Indenter(left=-INDENT_SIZE))

        # Add a page break at the end of an object
        data.append(PageBreak())

        return data


class Galaxy():

    # ----------------------------------------------------------------------
    def __init__(self, config, value_formatter):
        self.config = config
        self.value_formatter = value_formatter
        self.sample_style_sheet = getSampleStyleSheet()

    # ----------------------------------------------------------------------

    def get_galaxy_value(self, galaxies=None):
        '''
        Returns a flowable paragraph to add to the pdf given the misp_event galaxies
        :return: a Flowable to add in the pdf, regarding the values of "galaxies"
        '''

        flowable_table = []

        # Galaxies
        # item = ["Related Galaxies", 'Galaxy', "None"]
        if is_safe_table(galaxies) and is_in_config(self.config, 3):
            galaxy_title = Paragraph(safe_string("Related Galaxies"), self.sample_style_sheet['Heading5'])
            flowable_table.append(Indenter(left=INDENT_SIZE_HEADING))
            flowable_table.append(galaxy_title)
            flowable_table.append(Indenter(left=-INDENT_SIZE_HEADING))
            flowable_table += self.create_flowable_table_from_galaxies(galaxies=galaxies)
        else:
            flowable_table.append(self.value_formatter.get_unoverflowable_paragraph(DEFAULT_VALUE))

        return flowable_table

    def create_flowable_table_from_galaxies(self, galaxies=None):
        '''
        Returns a Table (flowable) to add to a pdf, representing the list of galaxies of an event or a misp event
        :param misp_event: A misp event
        :return: a table of flowables to add to the pdf
        '''
        flowable_table = []
        scheme_alternation = []
        curr_color = 0
        i = 0
        small_title_style = ParagraphStyle(name='Column_1', parent=self.sample_style_sheet['Heading6'],
                                           fontName=FIRST_COL_FONT, alignment=TA_LEFT)

        if is_safe_table(galaxies):
            # There is some galaxies for this object

            for curr_galaxy in galaxies:
                # For each galaxy of the misp object

                txt_title = "Galaxy #" + str(i + OFFSET) + " - " + safe_string(curr_galaxy["name"])
                galaxy_title = Paragraph(txt_title, small_title_style)
                flowable_table.append(Indenter(left=INDENT_SIZE_HEADING))
                flowable_table.append(galaxy_title)
                flowable_table.append(Indenter(left=-INDENT_SIZE_HEADING))
                i += 1

                # Add metadata about the Galaxy
                galaxy_metadata, nb_added_item = self.create_flowable_table_from_one_galaxy(curr_galaxy)
                flowable_table += galaxy_metadata

                # Construct the line color scheme and line scheme
                scheme_alternation += [curr_color] * nb_added_item

                # Add metadata about clusters
                curr_cluster = Galaxy_cluster(self.config, self.value_formatter)
                clusters_metadata = curr_cluster.create_flowable_table_from_galaxy_clusters(curr_galaxy)
                flowable_table += clusters_metadata

        else:
            # No galaxies for this object
            answer_tags = [self.value_formatter.get_unoverflowable_paragraph("No galaxies")]
            flowable_table.append(create_flowable_table_from_data(answer_tags))

        return flowable_table

    def create_flowable_table_from_one_galaxy(self, misp_galaxy):
        '''
        Returns a table (flowable) representing the galaxy
        :param misp_galaxy: A misp galaxy
        :return: a table representing this misp's galaxy's attributes, to add to the pdf as a flowable
        '''
        data = []
        nb_added_item = 0

        # Name
        if is_safe_value(misp_galaxy.get('name', None)):
            data.append([self.value_formatter.get_col1_paragraph("Name", do_small=DO_SMALL_GALAXIES),
                         self.value_formatter.get_galaxy_name_value(misp_galaxy)])
            nb_added_item += 1

        # Description
        if is_safe_value(misp_galaxy.get('description', None)):
            data.append([self.value_formatter.get_col1_paragraph("Description", do_small=DO_SMALL_GALAXIES),
                         self.value_formatter.get_unoverflowable_paragraph(misp_galaxy.get('description', None), do_small=DO_SMALL_GALAXIES)])
            nb_added_item += 1

        flowable_table = []
        flowable_table.append(create_flowable_table_from_data(data))

        return flowable_table, nb_added_item


class Galaxy_cluster():

    # ----------------------------------------------------------------------
    def __init__(self, config, value_formatter):
        self.config = config
        self.value_formatter = value_formatter
        self.sample_style_sheet = getSampleStyleSheet()

    # ----------------------------------------------------------------------
    def create_flowable_table_from_galaxy_clusters(self, misp_galaxy):
        '''
        Returns a Table (flowable) to add to a pdf, representing the list of galaxy clusters of a galaxy
        :param misp_event: A misp event
        :return: a table of flowables to add to the pdf
        '''

        data = []
        tmp_title = "Cluster #"

        if is_safe_value(misp_galaxy.get("GalaxyCluster", None)):
            # There is some clusters for this object
            for i, curr_cluster in enumerate(misp_galaxy.get("GalaxyCluster", None)):
                # If title is needed :
                # galaxy_title = [Paragraph("Cluster #" + str(i), self.sample_style_sheet['Heading6'])]
                # data.append(galaxy_title)

                tmp_title = "Cluster #" + str(i + OFFSET)

                # For each cluster
                tmp_data = self.create_flowable_table_from_one_galaxy_cluster(curr_cluster)
                tmp_flowable_table = []
                tmp_flowable_table.append(create_flowable_table_from_data(tmp_data, col_w=SECOND_LEVEL_GALAXY_WIDTHS,
                                                                          color_alternation=CLUSTER_COLORS,
                                                                          line_alternation=[], galaxy_colors=True))
                data.append([self.value_formatter.get_col1_paragraph(tmp_title, do_small=DO_SMALL_GALAXIES),
                             tmp_flowable_table])  # Cluster #X - 3 lines

        else:
            # No galaxies for this object
            data = [self.value_formatter.get_unoverflowable_paragraph("No galaxy cluster", do_small=DO_SMALL_GALAXIES)]

        flowable_table = []
        flowable_table.append(
            create_flowable_table_from_data(data, col_w=FIRST_LEVEL_GALAXY_WIDTHS, color_alternation=CLUSTER_COLORS,
                                            galaxy_colors=True))

        return flowable_table

    def create_flowable_table_from_one_galaxy_cluster(self, misp_cluster):
        '''
        Returns a table (flowable) representing a galaxy cluster
        :param misp_attribute: A misp galaxy
        :return: a table representing this misp's galaxy's cluster attributes, to add to the pdf as a flowable
        '''
        data = []

        # Name
        data.append([self.value_formatter.get_col1_paragraph("Name", do_small=True),
                     self.value_formatter.get_galaxy_cluster_name_value(misp_cluster, do_small=True)])

        if misp_cluster['value'] != misp_cluster['description']:  # Prevent name that are same as description
            # Description
            data.append([self.value_formatter.get_col1_paragraph("Description", do_small=True),
                         self.value_formatter.get_unoverflowable_paragraph(misp_cluster.get('description', None), do_small=True)])

        # Refs ?
        # item = ["Description", 'description', "None"]
        # data.append([self.value_formatter.get_col1_paragraph(item[0]),
        # self.value_formatter.get_unoverflowable_paragraph(misp_cluster[item[1]])])

        return data


########################################################################
# Handling static parts drawn on the upper layer


class Statics_Drawings():

    # ----------------------------------------------------------------------
    def __init__(self, config, misp_event):
        self.config = config
        self.misp_event = misp_event

    # ----------------------------------------------------------------------

    def set_template(self, canvas, doc):
        self.add_page_number(canvas, doc)
        self.add_metadata(canvas, doc)
        # TODO : add_header()
        # TODO : add_footer()

    def add_metadata(self, canvas, doc):
        '''
        Allow to add metadata to the pdf. Would need deeper digging to change other metadata.
        :param canvas: / Automatically filled during pdf compilation
        :param doc: / Automatically filled during pdf compilation
        :param misp_event: To send trough "partial", to get information to complete metadaa
        :return: / Automatically filled during pdf compilation
        '''

        if is_safe_attribute(self.misp_event, 'info'):
            canvas.setTitle(self.misp_event.info)
            canvas.setSubject(self.misp_event.info)

        if is_safe_attribute(self.misp_event, 'Orgc'):
            if is_safe_attribute(self.misp_event.Orgc, 'name'):
                canvas.setAuthor(self.misp_event.Orgc.name)

                if is_in_config(self.config, 1):
                    canvas.setCreator(self.config[moduleconfig[1]])
                else:
                    canvas.setCreator(self.misp_event.Orgc.name)

        if is_safe_attribute(self.misp_event, 'uuid'):
            canvas.setKeywords(self.misp_event.uuid)

    def add_page_number(self, canvas, doc):
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
    col1_style, col2_style = get_table_styles()
    col1_small_style, col2_small_style = get_clusters_table_styles()
    curr_val_f = Value_Formatter(config, col1_style, col2_style, col1_small_style, col2_small_style)

    # Create stuff
    title_style = ParagraphStyle(name='Column_1', parent=sample_style_sheet['Heading1'],
                                 fontName=FIRST_COL_FONT, alignment=TA_CENTER)
    title = curr_val_f.get_value_link_to_event(uuid=misp_event.get('uuid', None),
                                               text=misp_event.get('info', None),
                                               curr_style=title_style, color=False)
    # Add all parts to final PDF
    flowables.append(title)

    # Creation of handling objects
    curr_event = Event_Metadata(config, curr_val_f)
    curr_attr = Attributes(config, curr_val_f)
    curr_object = Object(config, curr_val_f)

    if is_in_config(config, 2):  # If description is activated
        description = Paragraph("Description", sample_style_sheet['Heading2'])
        description_text = curr_event.create_flowable_description_from_event(misp_event)
        flowables.append(description)
        flowables.append(description_text)

    subtitle = Paragraph("General information", sample_style_sheet['Heading2'])
    table_general_metainformation = curr_event.create_flowable_table_from_event(misp_event)
    flowables.append(subtitle)
    flowables += table_general_metainformation

    if is_safe_attribute_table(misp_event, "Attribute"):
        flowables.append(PageBreak())

    event_attributes_title = Paragraph("Attributes", sample_style_sheet['Heading2'])
    table_direct_attributes = curr_attr.create_flowable_table_from_attributes(misp_event)
    flowables.append(event_attributes_title)
    flowables += table_direct_attributes

    if is_safe_attribute_table(misp_event, "Object"):
        flowables.append(PageBreak())

    event_objects_title = Paragraph("Objects", sample_style_sheet['Heading2'])
    table_objects = curr_object.create_flowable_table_from_objects(objects=misp_event.get("Object", None))
    flowables.append(event_objects_title)
    flowables += table_objects

    # If you want to output the full json (as debug), just add next line and add it to flowables
    # paragraph_2 = Paragraph(str(misp_event.to_json()), sample_style_sheet['Code'])

    return flowables


def export_flowables_to_pdf(document, misp_event, flowables, config):
    '''
    Export function : creates a pdf from a list of flowables, adding page numbers, etc.
    :param document: A document template
    :param pdf_buffer: / not used
    :param flowables: list of flowables to compile as pdf
    :return:
    '''

    static_drawer = Statics_Drawings(config, misp_event)

    document.build(
        flowables,
        # Partial used to set the metadata
        onFirstPage=static_drawer.set_template,  # Pagination for first page
        onLaterPages=static_drawer.set_template,  # Pagination for all other page
    )
    # Old way : onLaterPages=partial(static_drawer.set_template, misp_event=misp_event),  # Pagination for all other page


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

    if is_in_config(config, 5):  # We want internationalization
        logger.info("Internationalization of fonts during pdf export activated. CJK-fonts supported.")
        internationalize_font(config)

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
