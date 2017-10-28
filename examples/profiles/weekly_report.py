types_to_attach = ['ip-dst', 'url', 'domain', 'md5']
objects_to_attach = ['domain-ip', 'file']

headers = """
:toc: right
:toclevels: 1
:toc-title: Weekly Report
:icons: font
:sectanchors:
:sectlinks:
= Weekly report by {org_name}
{date}

:icons: font

"""

event_level_tags = """
"""

attributes = """
=== Indicator(s) of compromise

{list_attributes}

"""

title = """
== ({internal_id}) {title}

{summary}

"""
