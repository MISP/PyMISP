#!/usr/bin/env bash

set -e
set -x

# We're in python3, installing with poetry.
pip3 install poetry
poetry install -E fileobjects -E openioc -E virustotal -E docs -E pdfexport
