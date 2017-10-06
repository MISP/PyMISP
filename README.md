README
======

[![Documentation Status](https://readthedocs.org/projects/pymisp/badge/?version=master)](http://pymisp.readthedocs.io/en/master/?badge=master)
[![Build Status](https://travis-ci.org/MISP/PyMISP.svg?branch=master)](https://travis-ci.org/MISP/PyMISP)
[![Coverage Status](https://coveralls.io/repos/github/MISP/PyMISP/badge.svg?branch=master)](https://coveralls.io/github/MISP/PyMISP?branch=master)

# PyMISP - Python Library to access MISP

PyMISP is a Python library to access [MISP](https://github.com/MISP/MISP) platforms via their REST API.

PyMISP allows you to fetch events, add or update events/attributes, add or update samples or search for attributes.

## Requirements

 * [requests](http://docs.python-requests.org)

## Install from pip

To install the package:
```
pip3 install pymisp
```

To update it:
```
pip3 install pymisp --upgrade
```

## Install the latest version from repo

To install the package:
```
pip3 install git+https://github.com/CIRCL/PyMISP.git
```

To update it:
```
pip3 install git+https://github.com/CIRCL/PyMISP.git --upgrade
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

## Documentation

[PyMISP API documentation is available](https://media.readthedocs.org/pdf/pymisp/master/pymisp.pdf).

Documentation can be generated with epydoc:

```
epydoc --url https://github.com/CIRCL/PyMISP --graph all --name PyMISP --pdf pymisp -o doc
```
