#!/usr/bin/python
# -*- coding: utf-8 -*-
from setuptools import setup

setup(
    name='pymisp',
    version='1.0.1',
    author='Raphaël Vinot',
    author_email='raphael.vinot@circl.lu',
    maintainer='Raphaël Vinot',
    url='https://github.com/MISP/PyMISP',
    description='Python API for MISP.',
    long_description=open('README.md').read(),
    packages=['pymisp'],
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Telecommunications Industry',
        'Programming Language :: Python',
        'Topic :: Security',
        'Topic :: Internet',
        ],
    install_requires=['requests'],
    )
