types_to_attach = ['ip-dst', 'url', 'domain']
objects_to_attach = ['domain-ip']

headers = """
:toc: right
:toclevels: 1
:toc-title: Daily Report
:icons: font
:sectanchors:
:sectlinks:
= Daily report by {org_name}
{date}

:icons: font

"""

event_level_tags = """
IMPORTANT: This event is classified TLP:{value}.

{expanded}

"""

attributes = """
=== Indicator(s) of compromise

{list_attributes}

"""

title = """
== ({internal_id}) {title}

{summary}

"""
