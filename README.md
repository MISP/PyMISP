PyMISP is a Python library to access [MISP](https://github.com/MISP/MISP) platforms via their REST API.

Requirements
------------

 * [requests](http://docs.python-requests.org)

Install
-------

python setup.py install

Example
-------

An example to copy events between MISP instances is included in examples/

Documentation
-------------

[PyMISP API documentation is available](http://www.circl.lu/assets/files/PyMISP.pdf).

Documentation can be generated with epydoc:

~~~~
   epydoc --url https://github.com/CIRCL/PyMISP --graph all --name PyMISP --pdf pymisp -o doc
~~~~
