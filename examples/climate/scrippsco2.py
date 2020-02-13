#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import datetime
from dateutil.parser import parse
import csv
from pathlib import Path
import json
from uuid import uuid4
import requests

from pymisp import MISPEvent, MISPObject, MISPTag, MISPOrganisation
from pymisp.tools import feed_meta_generator


class Scrippts:

    def __init__(self, output_dir: str= 'output', org_name: str='CIRCL',
                 org_uuid: str='55f6ea5e-2c60-40e5-964f-47a8950d210f'):
        self.misp_org = MISPOrganisation()
        self.misp_org.name = org_name
        self.misp_org.uuid = org_uuid

        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        self.data_dir = self.output_dir / 'data'
        self.data_dir.mkdir(exist_ok=True)

        self.scrippts_meta_file = self.output_dir / '.meta_scrippts'
        self.scrippts_meta = {}
        if self.scrippts_meta_file.exists():
            # Format: <infofield>,<uuid>.json
            with self.scrippts_meta_file.open() as f:
                reader = csv.reader(f)
                for row in reader:
                    self.scrippts_meta[row[0]] = row[1]
        else:
            self.scrippts_meta_file.touch()

    def geolocation_alt(self) -> MISPObject:
        # Alert, NWT, Canada
        location = MISPObject('geolocation', standalone=False)
        location.add_attribute('latitude', 82.3)
        location.add_attribute('longitude', 62.3)
        location.add_attribute('altitude', 210)
        location.add_attribute('text', 'Alert, NWT, Canada')
        return location

    def tag_alt(self) -> MISPTag:
        tag = MISPTag()
        tag.name = 'scrippsco2-sampling-stations:ALT'
        return tag

    def geolocation_ptb(self):
        # Point Barrow, Alaska
        location = MISPObject('geolocation')
        location.add_attribute('latitude', 71.3)
        location.add_attribute('longitude', 156.6)
        location.add_attribute('altitude', 11)
        location.add_attribute('text', 'Point Barrow, Alaska')
        return location

    def tag_ptb(self):
        tag = MISPTag()
        tag.name = 'scrippsco2-sampling-stations:PTB'
        return tag

    def geolocation_stp(self) -> MISPObject:
        # Station P
        location = MISPObject('geolocation')
        location.add_attribute('latitude', 50)
        location.add_attribute('longitude', 145)
        location.add_attribute('altitude', 0)
        location.add_attribute('text', 'Station P')
        return location

    def tag_stp(self):
        tag = MISPTag()
        tag.name = 'scrippsco2-sampling-stations:STP'
        return tag

    def geolocation_ljo(self) -> MISPObject:
        # La Jolla Pier, California
        location = MISPObject('geolocation')
        location.add_attribute('latitude', 32.9)
        location.add_attribute('longitude', 117.3)
        location.add_attribute('altitude', 10)
        location.add_attribute('text', 'La Jolla Pier, California')
        return location

    def tag_ljo(self):
        tag = MISPTag()
        tag.name = 'scrippsco2-sampling-stations:LJO'
        return tag

    def geolocation_bcs(self) -> MISPObject:
        # Baja California Sur, Mexico
        location = MISPObject('geolocation')
        location.add_attribute('latitude', 23.3)
        location.add_attribute('longitude', 110.2)
        location.add_attribute('altitude', 4)
        location.add_attribute('text', 'Baja California Sur, Mexico')
        return location

    def tag_bcs(self):
        tag = MISPTag()
        tag.name = 'scrippsco2-sampling-stations:BCS'
        return tag

    def geolocation_mlo(self) -> MISPObject:
        # Mauna Loa Observatory, Hawaii
        location = MISPObject('geolocation')
        location.add_attribute('latitude', 19.5)
        location.add_attribute('longitude', 155.6)
        location.add_attribute('altitude', 3397)
        location.add_attribute('text', 'Mauna Loa Observatory, Hawaii')
        return location

    def tag_mlo(self):
        tag = MISPTag()
        tag.name = 'scrippsco2-sampling-stations:MLO'
        return tag

    def geolocation_kum(self) -> MISPObject:
        # Cape Kumukahi, Hawaii
        location = MISPObject('geolocation')
        location.add_attribute('latitude', 19.5)
        location.add_attribute('longitude', 154.8)
        location.add_attribute('altitude', 3)
        location.add_attribute('text', 'Cape Kumukahi, Hawaii')
        return location

    def tag_kum(self):
        tag = MISPTag()
        tag.name = 'scrippsco2-sampling-stations:KUM'
        return tag

    def geolocation_chr(self):
        # Christmas Island, Fanning Island
        location = MISPObject('geolocation')
        location.add_attribute('latitude', 2)
        location.add_attribute('longitude', 157.3)
        location.add_attribute('altitude', 2)
        location.add_attribute('text', 'Christmas Island, Fanning Island')
        return location

    def tag_chr(self):
        tag = MISPTag()
        tag.name = 'scrippsco2-sampling-stations:CHR'
        return tag

    def geolocation_sam(self):
        # American Samoa
        location = MISPObject('geolocation')
        location.add_attribute('latitude', 14.2)
        location.add_attribute('longitude', 170.6)
        location.add_attribute('altitude', 30)
        location.add_attribute('text', 'American Samoa')
        return location

    def tag_sam(self):
        tag = MISPTag()
        tag.name = 'scrippsco2-sampling-stations:SAM'
        return tag

    def geolocation_ker(self):
        # Kermadec Islands, Raoul Island
        location = MISPObject('geolocation')
        location.add_attribute('latitude', 29.2)
        location.add_attribute('longitude', 177.9)
        location.add_attribute('altitude', 2)
        location.add_attribute('text', 'Kermadec Islands, Raoul Island')
        return location

    def tag_ker(self):
        tag = MISPTag()
        tag.name = 'scrippsco2-sampling-stations:KER'
        return tag

    def geolocation_nzd(self):
        # Baring Head, New Zealand
        location = MISPObject('geolocation')
        location.add_attribute('latitude', 41.4)
        location.add_attribute('longitude', 174.9)
        location.add_attribute('altitude', 85)
        location.add_attribute('text', 'Baring Head, New Zealand')
        return location

    def tag_nzd(self):
        tag = MISPTag()
        tag.name = 'scrippsco2-sampling-stations:NZD'
        return tag

    def geolocation_psa(self):
        # Palmer Station, Antarctica
        location = MISPObject('geolocation')
        location.add_attribute('latitude', 64.9)
        location.add_attribute('longitude', 64)
        location.add_attribute('altitude', 10)
        location.add_attribute('text', 'Palmer Station, Antarctica')
        return location

    def tag_psa(self):
        tag = MISPTag()
        tag.name = 'scrippsco2-sampling-stations:PSA'
        return tag

    def geolocation_spo(self):
        # South Pole
        location = MISPObject('geolocation')
        location.add_attribute('latitude', 90)
        location.add_attribute('longitude', 0)
        location.add_attribute('altitude', 2810)
        location.add_attribute('text', 'South Pole')
        return location

    def tag_spo(self):
        tag = MISPTag()
        tag.name = 'scrippsco2-sampling-stations:SPO'
        return tag

    def fetch(self, url):
        filepath = self.data_dir / Path(url).name
        r = requests.get(url)
        if r.status_code != 200 or r.text[0] != '"':
            print(url)
            return False
        with filepath.open('w') as f:
            f.write(r.text)
        return filepath

    def import_all(self, stations_short_names, interval, data_type):
        object_creator = getattr(self, f'{interval}_flask_{data_type}')
        if data_type == 'co2':
            base_url = 'https://scrippsco2.ucsd.edu/assets/data/atmospheric/stations/flask_co2/'
        elif data_type in ['c13', 'o18']:
            base_url = 'https://scrippsco2.ucsd.edu/assets/data/atmospheric/stations/flask_isotopic/'
        for station in stations_short_names:
            url = f'{base_url}/{interval}/{interval}_flask_{data_type}_{station}.csv'
            infofield = f'[{station.upper()}] {interval} average atmospheric {data_type} concentrations'
            filepath = self.fetch(url)
            if not filepath:
                continue
            if infofield in self.scrippts_meta:
                event = MISPEvent()
                event.load_file(str(self.output_dir / self.scrippts_meta[infofield]))
                location = event.get_objects_by_name('geolocation')[0]
                update = True
            else:
                event = MISPEvent()
                event.uuid = str(uuid4())
                event.info = infofield
                event.Orgc = self.misp_org
                event.add_tag(getattr(self, f'tag_{station}')())
                location = getattr(self, f'geolocation_{station}')()
                event.add_object(location)
                event.add_attribute('link', f'https://scrippsco2.ucsd.edu/data/atmospheric_co2/{station}')
                update = False
                with self.scrippts_meta_file.open('a') as f:
                    writer = csv.writer(f)
                    writer.writerow([infofield, f'{event.uuid}.json'])

            object_creator(event, location, filepath, update)
            if update:
                # Bump the publish timestamp
                event.publish_timestamp = datetime.datetime.timestamp(datetime.datetime.now())
            feed_output = event.to_feed(with_meta=False)
            with (self.output_dir / f'{event.uuid}.json').open('w') as f:
                # json.dump(feed_output, f, indent=2, sort_keys=True)  # For testing
                json.dump(feed_output, f)

    def import_monthly_co2_all(self):
        to_import = ['alt', 'ptb', 'stp', 'ljo', 'bcs', 'mlo', 'kum', 'chr', 'sam', 'ker', 'nzd']
        self.import_all(to_import, 'monthly', 'co2')

    def import_monthly_c13_all(self):
        to_import = ['alt', 'ptb', 'stp', 'ljo', 'bcs', 'mlo', 'kum', 'chr', 'sam', 'ker', 'nzd', 'psa', 'spo']
        self.import_all(to_import, 'monthly', 'c13')

    def import_monthly_o18_all(self):
        to_import = ['alt', 'ptb', 'stp', 'ljo', 'bcs', 'mlo', 'kum', 'chr', 'sam', 'ker', 'nzd', 'spo']
        self.import_all(to_import, 'monthly', 'o18')

    def import_daily_co2_all(self):
        to_import = ['alt', 'ptb', 'stp', 'ljo', 'bcs', 'mlo', 'kum', 'chr', 'sam', 'ker', 'nzd']
        self.import_all(to_import, 'daily', 'co2')

    def import_daily_c13_all(self):
        to_import = ['alt', 'ptb', 'ljo', 'bcs', 'mlo', 'kum', 'chr', 'sam', 'ker', 'nzd', 'spo']
        self.import_all(to_import, 'daily', 'c13')

    def import_daily_o18_all(self):
        to_import = ['alt', 'ptb', 'ljo', 'bcs', 'mlo', 'kum', 'chr', 'sam', 'ker', 'nzd', 'spo']
        self.import_all(to_import, 'daily', 'o18')

    def split_data_comment(self, csv_file, update, event):
        comment = ''
        data = []
        with csv_file.open() as f:
            for line in f:
                if line[0] == '"':
                    if update:
                        continue
                    if '----------' in line:
                        event.add_attribute('comment', comment, disable_correlation=True)
                        comment = ''
                        continue
                    comment += line[1:-1].strip()
                else:
                    data.append(line)
            if not update:
                event.add_attribute('comment', comment, disable_correlation=True)
        return data

    def monthly_flask_co2(self, event, location, csv_file, update):
        data = self.split_data_comment(csv_file, update, event)

        dates_already_imported = []
        if update:
            # get all datetime from existing event
            for obj in event.get_objects_by_name('scrippsco2-co2-monthly'):
                date_attribute = obj.get_attributes_by_relation('sample-datetime')[0]
                dates_already_imported.append(date_attribute.value)

        reader = csv.reader(data)
        for row in reader:
            if not row[0].isdigit():
                # This file has fucked up headers
                continue
            sample_date = parse(f'{row[0]}-{row[1]}-16T00:00:00')
            if sample_date in dates_already_imported:
                continue
            obj = MISPObject('scrippsco2-co2-monthly', standalone=False)
            obj.add_attribute('sample-datetime', sample_date)
            obj.add_attribute('sample-date-excel', float(row[2]))
            obj.add_attribute('sample-date-fractional', float(row[3]))
            obj.add_attribute('monthly-co2', float(row[4]))
            obj.add_attribute('monthly-co2-seasonal-adjustment', float(row[5]))
            obj.add_attribute('monthly-co2-smoothed', float(row[6]))
            obj.add_attribute('monthly-co2-smoothed-seasonal-adjustment', float(row[7]))
            obj.add_reference(location, 'sampling-location')
            event.add_object(obj)

    def monthly_flask_c13(self, event, location, csv_file, update):
        data = self.split_data_comment(csv_file, update, event)

        dates_already_imported = []
        if update:
            # get all datetime from existing event
            for obj in event.get_objects_by_name('scrippsco2-c13-monthly'):
                date_attribute = obj.get_attributes_by_relation('sample-datetime')[0]
                dates_already_imported.append(date_attribute.value)

        reader = csv.reader(data)
        for row in reader:
            if not row[0].isdigit():
                # This file has fucked up headers
                continue
            sample_date = parse(f'{row[0]}-{row[1]}-16T00:00:00')
            if sample_date in dates_already_imported:
                continue
            obj = MISPObject('scrippsco2-c13-monthly', standalone=False)
            obj.add_attribute('sample-datetime', sample_date)
            obj.add_attribute('sample-date-excel', float(row[2]))
            obj.add_attribute('sample-date-fractional', float(row[3]))
            obj.add_attribute('monthly-c13', float(row[4]))
            obj.add_attribute('monthly-c13-seasonal-adjustment', float(row[5]))
            obj.add_attribute('monthly-c13-smoothed', float(row[6]))
            obj.add_attribute('monthly-c13-smoothed-seasonal-adjustment', float(row[7]))
            obj.add_reference(location, 'sampling-location')
            event.add_object(obj)

    def monthly_flask_o18(self, event, location, csv_file, update):
        data = self.split_data_comment(csv_file, update, event)

        dates_already_imported = []
        if update:
            # get all datetime from existing event
            for obj in event.get_objects_by_name('scrippsco2-o18-monthly'):
                date_attribute = obj.get_attributes_by_relation('sample-datetime')[0]
                dates_already_imported.append(date_attribute.value)

        reader = csv.reader(data)
        for row in reader:
            if not row[0].isdigit():
                # This file has fucked up headers
                continue
            sample_date = parse(f'{row[0]}-{row[1]}-16T00:00:00')
            if sample_date in dates_already_imported:
                continue
            obj = MISPObject('scrippsco2-o18-monthly', standalone=False)
            obj.add_attribute('sample-datetime', sample_date)
            obj.add_attribute('sample-date-excel', float(row[2]))
            obj.add_attribute('sample-date-fractional', float(row[3]))
            obj.add_attribute('monthly-o18', float(row[4]))
            obj.add_attribute('monthly-o18-seasonal-adjustment', float(row[5]))
            obj.add_attribute('monthly-o18-smoothed', float(row[6]))
            obj.add_attribute('monthly-o18-smoothed-seasonal-adjustment', float(row[7]))
            obj.add_reference(location, 'sampling-location')
            event.add_object(obj)

    def daily_flask_co2(self, event, location, csv_file, update):
        data = self.split_data_comment(csv_file, update, event)

        dates_already_imported = []
        if update:
            # get all datetime from existing event
            for obj in event.get_objects_by_name('scrippsco2-co2-daily'):
                date_attribute = obj.get_attributes_by_relation('sample-datetime')[0]
                dates_already_imported.append(date_attribute.value)

        reader = csv.reader(data)
        for row in reader:
            sample_date = parse(f'{row[0]}-{row[1]}')
            if sample_date in dates_already_imported:
                continue
            obj = MISPObject('scrippsco2-co2-daily', standalone=False)
            obj.add_attribute('sample-datetime', sample_date)
            obj.add_attribute('sample-date-excel', float(row[2]))
            obj.add_attribute('sample-date-fractional', float(row[3]))
            obj.add_attribute('number-flask', int(row[4]))
            obj.add_attribute('flag', int(row[5]))
            attr = obj.add_attribute('co2-value', float(row[6]))
            attr.add_tag(f'scrippsco2-fgc:{int(row[5])}')
            obj.add_reference(location, 'sampling-location')
            event.add_object(obj)

    def daily_flask_c13(self, event, location, csv_file, update):
        data = self.split_data_comment(csv_file, update, event)

        dates_already_imported = []
        if update:
            # get all datetime from existing event
            for obj in event.get_objects_by_name('scrippsco2-c13-daily'):
                date_attribute = obj.get_attributes_by_relation('sample-datetime')[0]
                dates_already_imported.append(date_attribute.value)

        reader = csv.reader(data)
        for row in reader:
            sample_date = parse(f'{row[0]}-{row[1]}')
            if sample_date in dates_already_imported:
                continue
            obj = MISPObject('scrippsco2-c13-daily', standalone=False)
            obj.add_attribute('sample-datetime', sample_date)
            obj.add_attribute('sample-date-excel', float(row[2]))
            obj.add_attribute('sample-date-fractional', float(row[3]))
            obj.add_attribute('number-flask', int(row[4]))
            obj.add_attribute('flag', int(row[5]))
            attr = obj.add_attribute('c13-value', float(row[6]))
            attr.add_tag(f'scrippsco2-fgi:{int(row[5])}')
            obj.add_reference(location, 'sampling-location')
            event.add_object(obj)

    def daily_flask_o18(self, event, location, csv_file, update):
        data = self.split_data_comment(csv_file, update, event)

        dates_already_imported = []
        if update:
            # get all datetime from existing event
            for obj in event.get_objects_by_name('scrippsco2-o18-daily'):
                date_attribute = obj.get_attributes_by_relation('sample-datetime')[0]
                dates_already_imported.append(date_attribute.value)

        reader = csv.reader(data)
        for row in reader:
            sample_date = parse(f'{row[0]}-{row[1]}')
            if sample_date in dates_already_imported:
                continue
            obj = MISPObject('scrippsco2-o18-daily', standalone=False)
            obj.add_attribute('sample-datetime', sample_date)
            obj.add_attribute('sample-date-excel', float(row[2]))
            obj.add_attribute('sample-date-fractional', float(row[3]))
            obj.add_attribute('number-flask', int(row[4]))
            obj.add_attribute('flag', int(row[5]))
            attr = obj.add_attribute('o18-value', float(row[6]))
            attr.add_tag(f'scrippsco2-fgi:{int(row[5])}')
            obj.add_reference(location, 'sampling-location')
            event.add_object(obj)


if __name__ == '__main__':
    output_dir = 'scrippsco2_feed'

    i = Scrippts(output_dir=output_dir)
    i.import_daily_co2_all()
    i.import_daily_c13_all()
    i.import_daily_o18_all()
    i.import_monthly_co2_all()
    i.import_monthly_c13_all()
    i.import_monthly_o18_all()

    feed_meta_generator(Path(output_dir))
