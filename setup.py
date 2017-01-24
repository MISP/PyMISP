#!/usr/bin/python
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
    test_suite="tests",
    install_requires=['requests', 'python-dateutil', 'jsonschema'],
    include_package_data=True,
    package_data={'data': ['schema.json', 'schema-lax.json', 'describeTypes.json']},
)
