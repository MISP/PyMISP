#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Standard imports
from io import BytesIO
import base64
import logging
import pymisp

logger = logging.getLogger('pymisp')

# Potentially not installed imports
try:
    from reportlab.platypus import SimpleDocTemplate
    from reportlab.platypus import Paragraph
    from reportlab.platypus import PageBreak

    from reportlab.lib.styles import getSampleStyleSheet

    from reportlab.lib.units import mm, inch

    from reportlab.pdfgen import canvas

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, inch
    from reportlab.lib.enums import TA_RIGHT, TA_CENTER, TA_JUSTIFY, TA_LEFT
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False
    print("ReportLab cannot be imported. Please verify that ReportLab is installed on the system.")

'''
"UTILITIES" METHODS. Not meant to be used except for development purposes
'''
import pprint


def get_sample_fonts():
    # Create a dummy canvas
    c = canvas.Canvas("hello.pdf")

    # Print list of usable fonts
    pprint.pprint(c.getAvailableFonts())


def get_sample_styles():
    # Get styles, as for example sample_style_sheet['Heading1'], sample_style_sheet['BodyText'] ...
    sample_style_sheet = getSampleStyleSheet()

    # if you want to see all the sample styles, this prints them
    sample_style_sheet.list()


'''
"INTERNAL" METHODS. Not meant to be used outside of this class. 
'''
EVEN_COLOR = colors.whitesmoke
ODD_COLOR = colors.lightgrey


def alternate_colors_style_generator(data):
    # Modified from : https://gist.github.com/chadcooper/5798392

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


LINE_COLOR = colors.lightslategray
LINE_THICKNESS = 0.75

def lines_style_generator(data):
    data_len = len(data)
    lines_list = []

    # For each line, generate a tuple giving to a line a color
    for each in range(data_len):
        lines_list.append(('LINEABOVE', (0, each), (-1, each), LINE_THICKNESS, LINE_COLOR))

    # Last line
    lines_list.append(('LINEBELOW', (0, len(data)-1), (-1, len(data)-1), LINE_THICKNESS, LINE_COLOR))

    return lines_list

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
COL_WIDTHS = ['30%', '75%'] #  colWidths='*' # Not documented but does exist
ROW_HEIGHT = 5 * mm  # 4.5 * mm (a bit too short to allow vertical align TODO : Fix it)

def get_published_value(misp_event):
    '''
    :param misp_event: A misp event with or without "published"/"publish_timestamp" attributes
    :return: a string to print in the pdf, regarding the values of "published"/"publish_timestamp"
    # More information on how to play with paragraph into reportlab cells : https://stackoverflow.com/questions/11810008/reportlab-add-two-paragraphs-into-one-table-cell
    '''

    item = ["Published", 'published', "None", "publish_timestamp"]
    _, col2_style = get_table_styles()
    RED_COLOR = '#ff0000'
    GREEN_COLOR = '#008000'
    YES_ANSWER = "<font color=" + GREEN_COLOR + "><b> Yes </b></font> ("
    NO_ANSWER = "<font color=" + RED_COLOR + "><b>No</b></font>"

    # Formatting similar to MISP Event web view
    if hasattr(misp_event, item[1]):
        if getattr(misp_event, item[1]):  # == True
            if hasattr(misp_event, item[3]):
                # Published and have published date
                return Paragraph(YES_ANSWER + getattr(misp_event, item[3]).strftime(EXPORT_DATE_FORMAT) + ")",
                                 col2_style)
            else:
                # Published without published date
                return YES_ANSWER + "no date)"
        else:
            # Not published
            return NO_ANSWER
    else:
        # Does not have a published attribute
        return item[2]


def create_flowable_table_from_event(misp_event: pymisp.MISPEvent):
    # == Run on >1000 OSINT Events ==
    # 'Tag': 1065,                  OK
    # 'Attribute': 1050,            NOT OK
    # 'Object': 175,                NOT OK
    # 'info': 1065,                 OK
    # 'threat_level_id': 1065,      OK (added) TODO : improve design
    # 'analysis': 1065,             OK (added) TODO : improve design + Ask where the enum is !
    # 'published': 1065,            OK (added)
    # 'date': 1065,                 OK (added)
    # 'timestamp': 1065,            OK (added)
    # 'publish_timestamp': 1065,    OK (added)
    # 'Orgc': 1065,                 OK
    # 'uuid': 1065                  OK (added)

    # To reduce code size, and automate it a bit, triplet (Displayed Name, object_attribute_name,
    # to_display_if_not_present) are store in the following list
    list_attr_automated = [["Event ID", 'id', "None"],
                           ["UUID", 'uuid', "None"],                        # OK
                           ["Creator org", 'org', "None"],
                           ["Date", 'date', "None"],
                           ["Owner org", 'owner', "None"],
                           ["Email", 'email', "None"],
                           ["Tags", 'TODO', "None"],
                           ["Threat level", 'threat_level_id', "None"],
                           ["Analysis", 'analysis', "None"],
                           ["Distribution", 'distribution', "None"],
                           ["Info", 'info', "None"],                        # OK
                           ["# Attributes", 'attribute_count', "None"],
                           ["First recorded change", 'TODO', "None"],
                           ["Last change", 'TODO', "None"],
                           ["Modification map", 'TODO', "None"],
                           ["Sightings", 'TODO', "None"]
                           ]

    list_attr_manual = [["Event date", 'timestamp', "None"],                 # OK
                        ["Published", 'published', "None"],                  # OK
                        ["Sightings", 'TODO', "None"]
                        ]

    data = []
    col1_style, col2_style = get_table_styles()

    # Automated adding of standard (python) attributes of the misp event
    # Note that PEP 0363 may change the syntax in future release : https://www.python.org/dev/peps/pep-0363/
    for item in list_attr_automated:
        if hasattr(misp_event, item[1]):
            # The attribute exist, we fetch it and create the row
            data.append([Paragraph(item[0], col1_style), Paragraph(str(getattr(misp_event, item[1])), col2_style)])
        else:
            # The attribute does not exist ,we print a default text on the row
            data.append([Paragraph(item[0], col1_style), Paragraph(item[2], col2_style)])

    # Manual addition of specific attributes
    item = list_attr_manual[0]  # Timestamp
    if hasattr(misp_event, item[1]):
        data.append([Paragraph(item[0], col1_style), Paragraph(str(getattr(misp_event, item[1]).strftime(EXPORT_DATE_FORMAT)), col2_style)])
    else :
        data.append([Paragraph(item[0], col1_style), Paragraph(item[2], col2_style)])

    # Published (Factorized, because too long)
    item = list_attr_manual[1]
    data.append([Paragraph(item[0], col1_style), get_published_value(misp_event)])

    # Create styles and set parameters
    alternate_colors_style = alternate_colors_style_generator(data)
    lines_style = lines_style_generator(data)

    # Create the table
    curr_table = Table(data, COL_WIDTHS,
                       rowHeights=(ROW_HEIGHT))  # colWidths='*' does a 100% and share the space automatically

    # Make the table nicer
    curr_table.setStyle(TableStyle([('TEXTCOLOR', (0, 0), (0, -1), FIRST_COL_FONT_COLOR),
                                    ('TEXTCOLOR', (1, 0), (-1, -1), SECOND_COL_FONT_COLOR),
                                    ('FONT', (0, 0), (0, -1), FIRST_COL_FONT),
                                    ('FONT', (1, 0), (-1, -1), SECOND_COL_FONT),
                                    ('FONTSIZE', (0, 0), (-1, -1), TEXT_FONT_SIZE),
                                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                                    ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
                                    # ('BOX', (0, 0), (-1, -1), 0.25, colors.black) # Box for all
                                    ] + alternate_colors_style + lines_style))

    return curr_table


def create_style():
    sample_style_sheet = getSampleStyleSheet()

    custom_body_style = sample_style_sheet['BodyText']
    custom_body_style.fontName = 'Helvetica'
    custom_body_style.fontSize = 9

    # custom_body_style.listAttrs() # Print list of attributes that can be changed
    # styles.add(ParagraphStyle(name='Justify', alignment=TA_JUSTIFY))

    return custom_body_style


def get_table_styles():
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


def collect_parts(misp_event: pymisp.MISPEvent):
    # List of elements/content we want to add
    flowables = []
    # Get the list of available styles
    sample_style_sheet = getSampleStyleSheet()

    # Create own style
    custom_style = create_style()

    # Create stuff
    paragraph_1 = Paragraph(misp_event.info, sample_style_sheet['Heading1'])
    paragraph_2 = Paragraph(str(misp_event.to_json()), custom_style)
    paragraph_3 = Paragraph("Dingbat <font name=HELVETICA-bold>paragraph</font>",
                            sample_style_sheet['BodyText'])  # Apply custom style
    paragraph_4 = Paragraph("A <b>bold</b> word.<br /> An <i>italic</i> word.",
                            sample_style_sheet['BodyText'])  # HTML markup is working too
    table = create_flowable_table_from_event(misp_event)

    # Add all parts to final PDF
    flowables.append(paragraph_1)
    flowables.append(table)
    flowables.append(PageBreak())
    flowables.append(PageBreak())
    flowables.append(paragraph_2)
    flowables.append(paragraph_3)

    return flowables


def add_page_number(canvas, doc):
    canvas.saveState()
    canvas.setFont('Times-Roman', 10)
    page_number_text = "%d" % (doc.page)

    canvas.drawCentredString(
        0.75 * inch,
        0.75 * inch,
        page_number_text
    )

    canvas.restoreState()


def export_flowables_to_pdf(document, pdf_buffer, flowables):
    # my_doc.build(flowables) # Basic building of the final document

    document.build(
        flowables,
        onFirstPage=add_page_number,  # Pagination for first page
        onLaterPages=add_page_number,  # Pagination for all other page
    )


'''
"EXTERNAL" exposed METHODS. Meant to be used outside of this class.
'''

PAGESIZE = (140 * mm, 216 * mm)  # width, height
BASE_MARGIN = 5 * mm  # Create a list here to specify each row separately


def convert_event_in_pdf_buffer(misp_event: pymisp.MISPEvent):
    # Create a document buffer
    pdf_buffer = BytesIO()

    # DEBUG / TO DELETE : curr_document = SimpleDocTemplate('myfile.pdf')
    curr_document = SimpleDocTemplate(pdf_buffer,
                                      pagesize=PAGESIZE,
                                      topMargin=BASE_MARGIN,
                                      leftMargin=BASE_MARGIN,
                                      rightMargin=BASE_MARGIN,
                                      bottomMargin=BASE_MARGIN)

    # Apply standard template
    # TODO

    # Set the layout
    # TODO

    # Collect already accessible event's parts to be shown
    flowables = collect_parts(misp_event)

    # Export
    export_flowables_to_pdf(curr_document, pdf_buffer, flowables)
    pdf_value = pdf_buffer.getvalue()

    # TODO : Not sure what to give back ? Buffer ? Buffer.value() ? Base64(buffer.value()) ? ...
    # pdf_buffer.close()
    # return pdf_value

    return pdf_buffer


def get_values_from_buffer(pdf_buffer):
    return pdf_buffer.value()


def get_base64_from_buffer(pdf_buffer):
    return base64.b64encode(pdf_buffer.value())


def register_to_file(pdf_buffer, file_name):
    pdf_buffer.seek(0)

    with open(file_name, 'wb') as f:
        f.write(pdf_buffer.read())


if __name__ == "__main__":
    # pdf_buffer = convert_event_in_pdf_buffer(None)

    # register_to_file(pdf_buffer, 'test.pdf')
    get_sample_fonts()

    # get_values_from_buffer(pdf_buffer)
    # get_base64_from_buffer(pdf_buffer)

''' In the future ? 
try:
    from pymispgalaxies import Clusters
    has_pymispgalaxies = True
except ImportError:
    has_pymispgalaxies = False

try:
    from pytaxonomies import Taxonomies
    has_pymispgalaxies = True
except ImportError:
    has_pymispgalaxies = False
'''
'''
class ReportLabObject():

    def __init__(self, parameters, strict=True, standalone=True, **kwargs):
        super(ReportLabObject, self).__init__('reportlab', strict=strict, standalone=standalone, **kwargs)
        self._parameters = parameters
        self.generate_attributes()

    def generate_attributes(self):
        first = self._sanitize_timestamp(self._parameters.pop('first-seen', None))
        self._parameters['first-seen'] = first
        last = self._sanitize_timestamp(self._parameters.pop('last-seen', None))
        self._parameters['last-seen'] = last
        return super(ReportLabObject, self).generate_attributes()
'''
