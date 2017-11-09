#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import setup
import pymisp


setup(
    name='pymisp',
    version=pymisp.__version__,
    author='Raphaël Vinot',
    author_email='raphael.vinot@circl.lu',
    maintainer='Raphaël Vinot',
    url='https://github.com/MISP/PyMISP',
    description='Python API for MISP.',
    packages=['pymisp', 'pymisp.tools'],
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Operating System :: POSIX :: Linux',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Telecommunications Industry',
        'Intended Audience :: Information Technology',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: Internet',
    ],
    test_suite="tests.test_offline",
    install_requires=['six', 'requests', 'python-dateutil', 'jsonschema', 'setuptools>=36.4'],
    extras_require={'fileobjects': ['lief>=0.8', 'python-magic'],
                    'neo': ['py2neo'],
                    'openioc': ['beautifulsoup4'],
                    'virustotal': ['validators']},
    tests_require=[
        'jsonschema',
        'python-dateutil',
        'python-magic',
        'requests-mock',
        'six'
    ],
    include_package_data=True,
    package_data={'pymisp': ['data/*.json',
                             'data/misp-objects/schema_objects.json',
                             'data/misp-objects/schema_relationships.json',
                             'data/misp-objects/objects/*/definition.json',
                             'data/misp-objects/relationships/definition.json']},
)
