#!/usr/bin/env bash

set -e
set -x

# We're in python3, installing with pipenv.
pip3 install pipenv
pipenv update --dev
