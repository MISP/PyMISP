#!/usr/bin/env bash

set -e
set -x

# We're in python3, installing with pipenv.
pip install pipenv
pipenv update --dev
