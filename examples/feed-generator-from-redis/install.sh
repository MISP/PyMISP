#!/bin/bash
virtualenv -p python3 serv-env
. ./serv-env/bin/activate
pip3 install -U flask Flask-AutoIndex redis
