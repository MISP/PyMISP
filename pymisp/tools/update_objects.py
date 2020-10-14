#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import zipfile
from io import BytesIO
from pathlib import Path

import requests

from ..abstract import resources_path

static_repo = "https://github.com/MISP/misp-objects/archive/main.zip"


def update_objects():
    r = requests.get(static_repo)

    zipped_repo = BytesIO(r.content)

    with zipfile.ZipFile(zipped_repo, 'r') as myzip:
        for name in myzip.namelist():
            if not name.endswith('.json'):
                continue
            name_on_disk = name.replace('misp-objects-main', 'misp-objects')
            path = resources_path / Path(name_on_disk)
            if not path.parent.exists():
                path.parent.mkdir(parents=True)
            with path.open('wb') as f:
                f.write(myzip.read(name))
