README
======

[![Documentation Status](https://readthedocs.org/projects/pymisp/badge/?version=latest)](http://pymisp.readthedocs.io/?badge=latest)
[![Build Status](https://travis-ci.org/MISP/PyMISP.svg?branch=master)](https://travis-ci.org/MISP/PyMISP)
[![Coverage Status](https://coveralls.io/repos/github/MISP/PyMISP/badge.svg?branch=master)](https://coveralls.io/github/MISP/PyMISP?branch=master)

# PyMISP - Python Library to access MISP

PyMISP is a Python library to access [MISP](https://github.com/MISP/MISP) platforms via their REST API.

PyMISP allows you to fetch events, add or update events/attributes, add or update samples or search for attributes.

## Requirements

 * [requests](http://docs.python-requests.org)

## Install from pip

```
pip3 install pymisp
```

## Install the latest version from repo

```
git clone https://github.com/MISP/PyMISP.git && cd PyMISP
git submodule update --init
pip3 install -I .
```

## Samples and how to use PyMISP

Various examples and samples scripts are in the [examples/](examples/) directory.

In the examples directory, you will need to change the keys.py.sample to enter your MISP url and API key.

```
cd examples
cp keys.py.sample keys.py
vim keys.py
```

The API key of MISP is available in the Automation section of the MISP web interface.

To test if your URL and API keys are correct, you can test with examples/last.py to
fetch the last 10 events published.

```
cd examples
python3 last.py -l 10
```

## Debugging

You have two options there:

1. Pass `debug=True` to `PyMISP` and it will enable logging.DEBUG to stderr on the whole module

2. Use the python logging module directly:

```python

import logging
logger = logging.getLogger('pymisp')

# Configure it as you whish, for example, enable DEBUG mode:
logger.setLevel(logging.DEBUG)
```

Or if you want to write the debug output to a file instead of stderr:

```python
import pymisp
import logging

logger = logging.getLogger('pymisp')
logging.basicConfig(level=logging.DEBUG, filename="debug.log", filemode='w', format=pymisp.FORMAT)
```

## Documentation

[PyMISP API documentation is available](https://media.readthedocs.org/pdf/pymisp/latest/pymisp.pdf).

Documentation can be generated with epydoc:

```
epydoc --url https://github.com/MISP/PyMISP --graph all --name PyMISP --pdf pymisp -o doc
```

## Everything is a Mutable Mapping

... or at least everything that can be imported/exported from/to a json blob

`AbstractMISP` is the master class, and inherit `collections.MutableMapping` which means
the class can be represented as a python dictionary.

The abstraction assumes every property that should not be seen in the dictionary is prepended with a `_`,
or its name is added to the private list `__not_jsonable` (accessible through `update_not_jsonable` and `set_not_jsonable`.

This master class has helpers that will make it easy to load, and export, to, and from, a json string.

`MISPEvent`, `MISPAttribute`, `MISPObjectReference`, `MISPObjectAttribute`, and `MISPObject`
are subclasses of AbstractMISP, which mean that they can be handled as python dictionaries.

## MISP Objects

Creating a new MISP object generator should be done using a pre-defined template and inherit `AbstractMISPObjectGenerator`.

Your new MISPObject generator need to generate attributes, and add them as class properties using `add_attribute`.

When the object is sent to MISP, all the class properties will be exported to the JSON export.
