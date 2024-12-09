#!/usr/bin/env bash

set -e
set -x

poetry run nosetests-3.4 --with-coverage --cover-package=pymisp,tests --cover-tests tests/test_*.py
poetry run mypy tests/testlive_comprehensive.py tests/test_mispevent.py tests/testlive_sync.py pymisp
poetry run flake8 --ignore=E501,W503,E226,E252 pymisp
