#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
from pymisp import MISPEvent
import json
from typing import List


def feed_meta_generator(path: Path):
    manifests = {}
    hashes: List[str] = []

    for f_name in path.glob('*.json'):
        if str(f_name.name) == 'manifest.json':
            continue
        event = MISPEvent()
        event.load_file(str(f_name))
        manifests.update(event.manifest)
        hashes += [f'{h},{event.uuid}' for h in event.attributes_hashes('md5')]

    with (path / 'manifest.json').open('w') as f:
        json.dump(manifests, f)

    with (path / 'hashes.csv').open('w') as f:
        for h in hashes:
            f.write(f'{h}\n')
