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
    packages=['pymisp'],
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Telecommunications Industry',
        'Programming Language :: Python',
        'Topic :: Security',
        'Topic :: Internet',
    ],
    test_suite="tests",
    install_requires=['requests'],
)
