#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
from pymisp import MISPEvent, MISPOrganisation, PyMISP
from dateutil.parser import parse
import json
from pymisp.tools import feed_meta_generator
from io import BytesIO

make_feed = False

path = Path('/home/raphael/gits/covid-19-china/data')


if make_feed:
    org = MISPOrganisation()
    org.name = 'CIRCL'
    org.uuid = "55f6ea5e-2c60-40e5-964f-47a8950d210f"
else:
    from covid_key import url, key
    misp = PyMISP(url, key)

for p in path.glob('*_json/current_china.json'):
    d = parse(p.parent.name[:-5])
    event = MISPEvent()
    event.info = f"[{d.isoformat()}] DXY COVID-19 live report"
    event.date = d
    event.distribution = 3
    event.add_tag('tlp:white')
    if make_feed:
        event.orgc = org
    else:
        e = misp.search(eventinfo=event.info, metadata=True, pythonify=True)
        if e:
            # Already added.
            continue
    event.add_attribute('attachment', p.name, data=BytesIO(p.open('rb').read()))
    with p.open() as f:
        data = json.load(f)
    for province in data:
        obj_province = event.add_object(name='covid19-dxy-live-province', standalone=False)
        obj_province.add_attribute('province', province['provinceName'])
        obj_province.add_attribute('update', d)
        if province['currentConfirmedCount']:
            obj_province.add_attribute('current-confirmed', province['currentConfirmedCount'])
        if province['confirmedCount']:
            obj_province.add_attribute('total-confirmed', province['confirmedCount'])
        if province['curedCount']:
            obj_province.add_attribute('total-cured', province['curedCount'])
        if province['deadCount']:
            obj_province.add_attribute('total-death', province['deadCount'])
        if province['comment']:
            obj_province.add_attribute('comment', province['comment'])

        for city in province['cities']:
            obj_city = event.add_object(name='covid19-dxy-live-city', standalone=False)
            obj_city.add_attribute('city', city['cityName'])
            obj_city.add_attribute('update', d)
            if city['currentConfirmedCount']:
                obj_city.add_attribute('current-confirmed', city['currentConfirmedCount'])
            if city['confirmedCount']:
                obj_city.add_attribute('total-confirmed', city['confirmedCount'])
            if city['curedCount']:
                obj_city.add_attribute('total-cured', city['curedCount'])
            if city['deadCount']:
                obj_city.add_attribute('total-death', city['deadCount'])
            obj_city.add_reference(obj_province, 'part-of')

    if make_feed:
        with (Path('output') / f'{event.uuid}.json').open('w') as _w:
            json.dump(event.to_feed(), _w)
    else:
        misp.add_event(event)

if make_feed:
    feed_meta_generator(Path('output'))
