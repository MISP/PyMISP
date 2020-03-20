#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
from csv import DictReader
from pymisp import MISPEvent, MISPOrganisation, PyMISP
from datetime import datetime
from dateutil.parser import parse
import json
from pymisp.tools import feed_meta_generator
from io import BytesIO

make_feed = False

path = Path('/home/raphael/gits/COVID-19/csse_covid_19_data/csse_covid_19_daily_reports/')


if make_feed:
    org = MISPOrganisation()
    org.name = 'CIRCL'
    org.uuid = "55f6ea5e-2c60-40e5-964f-47a8950d210f"
else:
    from covid_key import url, key
    misp = PyMISP(url, key)

for p in path.glob('**/*.csv'):
    d = datetime.strptime(p.name[:-4], '%m-%d-%Y').date()
    event = MISPEvent()
    event.info = f"[{d.isoformat()}] CSSE COVID-19 daily report"
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
    event.add_attribute('link', f'https://github.com/CSSEGISandData/COVID-19/tree/master/csse_covid_19_data/csse_covid_19_daily_reports/{p.name}', comment='Source')
    with p.open() as f:
        reader = DictReader(f)
        for row in reader:
            obj = event.add_object(name='covid19-csse-daily-report', standalone=False)
            if 'Province/State' in row:
                if row['Province/State']:
                    obj.add_attribute('province-state', row['Province/State'])
            elif '\ufeffProvince/State' in row:
                if row['\ufeffProvince/State']:
                    obj.add_attribute('province-state', row['\ufeffProvince/State'])
            else:
                print(p, row.keys())
                raise Exception()
            obj.add_attribute('country-region', row['Country/Region'])
            obj.add_attribute('update', parse(row['Last Update']))
            if row['Confirmed']:
                obj.add_attribute('confirmed', int(row['Confirmed']))
            if row['Deaths']:
                obj.add_attribute('death', int(row['Deaths']))
            if row['Recovered']:
                obj.add_attribute('recovered', int(row['Recovered']))
    if make_feed:
        with (Path('output') / f'{event.uuid}.json').open('w') as _w:
            json.dump(event.to_feed(), _w)
    else:
        event = misp.add_event(event)
        misp.publish(event)

if make_feed:
    feed_meta_generator(Path('output'))
