#!/usr/bin/env bash

set -e
set -x

if [ ${LEGACY} == true ]; then
    pip install nose coveralls codecov requests-mock pydeep
    pip install .[fileobjects]
else
    # We're in python3, installing with pipenv.
    pip install pipenv
    pipenv update --dev
fi
