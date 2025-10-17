pymisp - Tools
==============

.. toctree::
   :maxdepth: 4

.. automodule:: pymisp.tools
    :members:

Excel / CSV Importer
--------------------

If the header of the CSV file has valid object relations in the template you're using:

.. code-block:: python

    from pymisp.tools import CSVLoader
    from pymisp import MISPEvent
    from pathlib import Path

    csv1 = CSVLoader(template_name='file', csv_path=Path('tests/csv_testfiles/valid_fieldnames.csv'))
    event = MISPEvent()
    event.info = 'Test event from CSV loader'
    for o in csv1.load():
        event.add_object(**o)

If the header of the CSV file does not have valid object relations in the template you're using:

.. code-block:: python

    event = MISPEvent()
    event.info = 'Test event from CSV loader'
    csv2 = CSVLoader(template_name='file', csv_path=Path('tests/csv_testfiles/invalid_fieldnames.csv'),
                     fieldnames=['SHA1', 'fileName', 'size-in-bytes'], has_fieldnames=True)

    for o in csv2.load():
        event.add_object(**o)

.. autoclass:: CSVLoader
    :members:
    :inherited-members:

File Object
-----------

.. autoclass:: FileObject
    :members:
    :inherited-members:

ELF Object
----------

.. autoclass:: ELFObject
    :members:
    :inherited-members:

.. autoclass:: ELFSectionObject
    :members:
    :inherited-members:

PE Object
---------

.. autoclass:: PEObject
    :members:
    :inherited-members:

.. autoclass:: PESectionObject
    :members:
    :inherited-members:

Mach-O Object
-------------

.. autoclass:: MachOObject
    :members:
    :inherited-members:

.. autoclass:: MachOSectionObject
    :members:
    :inherited-members:

VT Report Object
----------------

.. autoclass:: VTReportObject
    :members:
    :inherited-members:

STIX
----

.. automodule:: pymisp.tools.stix
    :members:

OpenIOC
--------

.. automethod:: pymisp.tools.load_openioc

.. automethod:: pymisp.tools.load_openioc_file
