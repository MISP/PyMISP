#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Standard imports
from io import BytesIO
import base64
import logging

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
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle

    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False
    print("ReportLab cannot be imported. Please verify that ReportLab is installed on the system.")

'''
"INTERNAL" METHODS. Not meant to be used outside of this class. 
'''

def create_flowable_table_from_event(misp_event):

    data = [['00', '01', '02', '03', '04'],
            ['10', '11', '12', '13', '14'],
            ['20', '21', '22', '23', '24'],
            ['30', '31', '32', '33', '34']]

    t = Table(data, 5 * [0.4 * inch], 4 * [0.4 * inch])

    t.setStyle(TableStyle([('TEXTCOLOR', (0, 0), (0, -1), colors.blue),
                           ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                           ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                           ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
                           ('BOX', (0, 0), (-1, -1), 0.25, colors.black),
                           ]))

    return t


def collect_parts(misp_event):
    # List of elements/content we want to add
    flowables = []
    # Get the list of available styles
    sample_style_sheet = getSampleStyleSheet()

    # Create stuff
    paragraph_1 = Paragraph("A title", sample_style_sheet['Heading1'])
    paragraph_2 = Paragraph("Some normal body text",sample_style_sheet['BodyText'])
    paragraph_3 = Paragraph("Dingbat paragraph", sample_style_sheet['BodyText']) # Apply custom style
    Paragraph("A <b>bold</b> word.<br /> An <i>italic</i> word.", sample_style_sheet['BodyText']) # HTML markup is working too
    table = create_flowable_table_from_event(misp_event)

    # Add all parts to final PDF
    flowables.append(paragraph_1)
    flowables.append(paragraph_2)
    flowables.append(table)
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
        onFirstPage=add_page_number, # Pagination for first page
        onLaterPages=add_page_number, # Pagination for all other page
    )

'''
"EXTERNAL" exposed METHODS. Meant to be used outside of this class.
'''

PAGESIZE = (140 * mm, 216 * mm) # width, height
BASE_MARGIN = 5 * mm

def convert_event_in_pdf_buffer(misp_event):

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

    #TODO : Not sure what to give back ? Buffer ? Buffer.value() ? Base64(buffer.value()) ? ...
    #pdf_buffer.close()
    #return pdf_value

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
    pdf_buffer = convert_event_in_pdf_buffer(None)

    register_to_file(pdf_buffer, 'test.pdf')

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
