#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
from csv import DictReader
from pymisp import MISPEvent, MISPOrganisation, PyMISP, MISPObject
from datetime import datetime
from dateutil.parser import parse
import json
from pymisp.tools import feed_meta_generator
from io import BytesIO
from collections import defaultdict

make_feed = False

aggregate_by_country = True

path = Path('/home/raphael/gits/COVID-19/csse_covid_19_data/csse_covid_19_daily_reports/')


def get_country_region(row):
    if 'Country/Region' in row:
        return row['Country/Region']
    elif 'Country_Region' in row:
        return row['Country_Region']
    else:
        print(p, row.keys())
        raise Exception()


def get_last_update(row):
    if 'Last_Update' in row:
        return parse(row['Last_Update'])
    elif 'Last Update' in row:
        return parse(row['Last Update'])
    else:
        print(p, row.keys())
        raise Exception()


def add_detailed_object(obj, row):
    if 'Province/State' in row:
        if row['Province/State']:
            obj.add_attribute('province-state', row['Province/State'])
    elif '\ufeffProvince/State' in row:
        if row['\ufeffProvince/State']:
            obj.add_attribute('province-state', row['\ufeffProvince/State'])
    elif 'Province_State' in row:
        if row['Province_State']:
            obj.add_attribute('province-state', row['Province_State'])
    else:
        print(p, row.keys())
        raise Exception()

    obj.add_attribute('country-region', get_country_region(row))

    obj.add_attribute('update', get_last_update(row))

    if 'Lat' in row:
        obj.add_attribute('latitude', row['Lat'])

    if 'Long_' in row:
        obj.add_attribute('longitude', row['Long_'])
    elif 'Long' in row:
        obj.add_attribute('longitude', row['Long'])

    if row['Confirmed']:
        obj.add_attribute('confirmed', int(row['Confirmed']))
    if row['Deaths']:
        obj.add_attribute('death', int(row['Deaths']))
    if row['Recovered']:
        obj.add_attribute('recovered', int(row['Recovered']))
    if 'Active' in row and row['Active']:
        obj.add_attribute('active', int(row['Active']))


def country_aggregate(aggregate, row):
    c = get_country_region(row)
    if c not in aggregate:
        aggregate[c] = defaultdict(active=0, death=0, recovered=0, confirmed=0, update=datetime.fromtimestamp(0))
    if row['Confirmed']:
        aggregate[c]['confirmed'] += int(row['Confirmed'])
    if row['Deaths']:
        aggregate[c]['death'] += int(row['Deaths'])
    if row['Recovered']:
        aggregate[c]['recovered'] += int(row['Recovered'])
    if 'Active' in row and row['Active']:
        aggregate[c]['active'] += int(row['Active'])

    update = get_last_update(row)
    if update > aggregate[c]['update']:
        aggregate[c]['update'] = update


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
    if aggregate_by_country:
        event.info = f"[{d.isoformat()}] CSSE COVID-19 daily report"
    else:
        event.info = f"[{d.isoformat()}] CSSE COVID-19 detailed daily report"
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
    if aggregate_by_country:
        aggregate = defaultdict()
    with p.open() as f:
        reader = DictReader(f)
        for row in reader:
            if aggregate_by_country:
                country_aggregate(aggregate, row)
            else:
                obj = MISPObject(name='covid19-csse-daily-report')
                add_detailed_object(obj, row)
                event.add_object(obj)

    if aggregate_by_country:
        for country, values in aggregate.items():
            obj = event.add_object(name='covid19-csse-daily-report', standalone=False)
            obj.add_attribute('country-region', country)
            obj.add_attribute('update', values['update'])
            obj.add_attribute('confirmed', values['confirmed'])
            obj.add_attribute('death', values['death'])
            obj.add_attribute('recovered', values['recovered'])
            obj.add_attribute('active', values['active'])

    if make_feed:
        with (Path('output') / f'{event.uuid}.json').open('w') as _w:
            json.dump(event.to_feed(), _w)
    else:
        event = misp.add_event(event)
        misp.publish(event)

if make_feed:
    feed_meta_generator(Path('output'))
