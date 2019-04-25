#!/usr/bin/env bash

set -e
set -x

if [ -z ${LEGACY} ]; then
    # We're in python3, test all and use pipenv.
    pipenv run nosetests-3.4 --with-coverage --cover-package=pymisp,tests --cover-tests tests/test_*.py
else
	nosetests --with-coverage --cover-package=pymisp,tests --cover-tests tests/test_offline.py
fi
