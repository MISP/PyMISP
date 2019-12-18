#!/usr/bin/env bash

set -e
set -x

pipenv run nosetests-3.4 --with-coverage --cover-package=pymisp,tests --cover-tests tests/test_*.py
