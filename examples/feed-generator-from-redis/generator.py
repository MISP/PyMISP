#!/usr/bin/env python3

import sys
import json
import os
import hashlib
import datetime
import time
import uuid

from pymisp import MISPEvent

import settings


def get_system_templates():
    """Fetch all MISP-Object template present on the local system.

    Returns:
        dict: A dictionary listing all MISP-Object templates

    """
    misp_objects_path = os.path.join(
        os.path.abspath(os.path.dirname(sys.modules['pymisp'].__file__)),
        'data', 'misp-objects', 'objects')

    templates = {}
    for root, dirs, files in os.walk(misp_objects_path, topdown=False):
        for def_file in files:
            obj_name = root.split('/')[-1]
            template_path = os.path.join(root, def_file)
            with open(template_path, 'r') as f:
                definition = json.load(f)
                templates[obj_name] = definition
    return templates


def gen_uuid():
    """Generate a random UUID and returns its string representation"""
    return str(uuid.uuid4())


class FeedGenerator:
    """Helper object to create MISP feed.

    Configuration taken from the file settings.py"""

    def __init__(self):
        """This object can be use to easily create a daily MISP-feed.

        It handles the event creation, manifest file and cache file
        (hashes.csv).

        """
        self.sys_templates = get_system_templates()
        self.constructor_dict = settings.constructor_dict

        self.flushing_interval = settings.flushing_interval
        self.flushing_next = time.time() + self.flushing_interval

        self.manifest = {}
        self.attributeHashes = []

        self.daily_event_name = settings.daily_event_name + ' {}'
        event_date_str, self.current_event_uuid, self.event_name = self.get_last_event_from_manifest()
        temp = [int(x) for x in event_date_str.split('-')]
        self.current_event_date = datetime.date(temp[0], temp[1], temp[2])
        self.current_event = self._get_event_from_id(self.current_event_uuid)

    def add_sighting_on_attribute(self, sight_type, attr_uuid, **data):
        """Add a sighting on an attribute.

        Not supported for the moment."""
        self.update_daily_event_id()
        self._after_addition()
        return False

    def add_attribute_to_event(self, attr_type, attr_value, **attr_data):
        """Add an attribute to the daily event"""
        self.update_daily_event_id()
        self.current_event.add_attribute(attr_type, attr_value, **attr_data)
        self._add_hash(attr_type, attr_value)
        self._after_addition()
        return True

    def add_object_to_event(self, obj_name, **data):
        """Add an object to the daily event"""
        self.update_daily_event_id()
        if obj_name not in self.sys_templates:
            print('Unkown object template')
            return False

        #  Get MISP object constructor
        obj_constr = self.constructor_dict.get(obj_name, None)
        #  Constructor not known, using the generic one
        if obj_constr is None:
            obj_constr = self.constructor_dict.get('generic')
            misp_object = obj_constr(obj_name)
            #  Fill generic object
            for k, v in data.items():
                # attribute is not in the object template definition
                if k not in self.sys_templates[obj_name]['attributes']:
                    # add it with type text
                    misp_object.add_attribute(k, **{'value': v, 'type': 'text'})
                else:
                    misp_object.add_attribute(k, **{'value': v})

        else:
            misp_object = obj_constr(data)

        self.current_event.add_object(misp_object)
        for attr_type, attr_value in data.items():
            self._add_hash(attr_type, attr_value)

        self._after_addition()
        return True

    def _after_addition(self):
        """Write event on disk"""
        now = time.time()
        if self.flushing_next <= now:
            self.flush_event()
            self.flushing_next = now + self.flushing_interval

    # Cache
    def _add_hash(self, attr_type, attr_value):
        if ('|' in attr_type or attr_type == 'malware-sample'):
            split = attr_value.split('|')
            self.attributeHashes.append([
                hashlib.md5(str(split[0]).encode("utf-8")).hexdigest(),
                self.current_event_uuid
            ])
            self.attributeHashes.append([
                hashlib.md5(str(split[1]).encode("utf-8")).hexdigest(),
                self.current_event_uuid
            ])
        else:
            self.attributeHashes.append([
                hashlib.md5(str(attr_value).encode("utf-8")).hexdigest(),
                self.current_event_uuid
            ])

    # Manifest
    def _init_manifest(self):
        # create an empty manifest
        with open(os.path.join(settings.outputdir, 'manifest.json'), 'w'):
            pass
        # create new event and save manifest
        self.create_daily_event()

    def flush_event(self, new_event=None):
        print('Writting event on disk'+' '*50)
        if new_event is not None:
            event_uuid = new_event['uuid']
            event = new_event
        else:
            event_uuid = self.current_event_uuid
            event = self.current_event

        eventFile = open(os.path.join(settings.outputdir, event_uuid+'.json'), 'w')
        eventFile.write(event.to_json())
        eventFile.close()

        self.save_hashes()

    def save_manifest(self):
        try:
            manifestFile = open(os.path.join(settings.outputdir, 'manifest.json'), 'w')
            manifestFile.write(json.dumps(self.manifest))
            manifestFile.close()
            print('Manifest saved')
        except Exception as e:
            print(e)
            sys.exit('Could not create the manifest file.')

    def save_hashes(self):
        if len(self.attributeHashes) == 0:
            return False
        try:
            hashFile = open(os.path.join(settings.outputdir, 'hashes.csv'), 'a')
            for element in self.attributeHashes:
                hashFile.write('{},{}\n'.format(element[0], element[1]))
            hashFile.close()
            self.attributeHashes = []
            print('Hash saved' + ' '*30)
        except Exception as e:
            print(e)
            sys.exit('Could not create the quick hash lookup file.')

    def _addEventToManifest(self, event):
        event_dict = event.to_dict()['Event']
        tags = []
        for eventTag in event_dict.get('EventTag', []):
            tags.append({'name': eventTag['Tag']['name'],
                         'colour': eventTag['Tag']['colour']})
        return {
                'Orgc': event_dict.get('Orgc', []),
                'Tag': tags,
                'info': event_dict['info'],
                'date': event_dict['date'],
                'analysis': event_dict['analysis'],
                'threat_level_id': event_dict['threat_level_id'],
                'timestamp': event_dict.get('timestamp', int(time.time()))
               }

    def get_last_event_from_manifest(self):
        """Retreive last event from the manifest.

        If the manifest doesn't  exists or if it is empty, initialize it.

        """
        try:
            manifest_path = os.path.join(settings.outputdir, 'manifest.json')
            with open(manifest_path, 'r') as f:
                man = json.load(f)
                dated_events = []
                for event_uuid, event_json in man.items():
                    # add events to manifest
                    self.manifest[event_uuid] = event_json
                    dated_events.append([
                        event_json['date'],
                        event_uuid,
                        event_json['info']
                    ])
                # Sort by date then by event name
                dated_events.sort(key=lambda k: (k[0], k[2]), reverse=True)
                return dated_events[0]
        except FileNotFoundError as e:
            print('Manifest not found, generating a fresh one')
            self._init_manifest()
            return self.get_last_event_from_manifest()

    # DAILY
    def update_daily_event_id(self):
        if self.current_event_date != datetime.date.today():  # create new event
            # save current event on disk
            self.flush_event()
            self.current_event = self.create_daily_event()
            self.current_event_date = datetime.date.today()
            self.current_event_uuid = self.current_event.get('uuid')
            self.event_name = self.current_event.info

    def _get_event_from_id(self, event_uuid):
        with open(os.path.join(settings.outputdir, '%s.json' % event_uuid), 'r') as f:
            event_dict = json.load(f)['Event']
            event = MISPEvent()
            event.from_dict(**event_dict)
            return event

    def create_daily_event(self):
        new_uuid = gen_uuid()
        today = str(datetime.date.today())
        event_dict = {
            'uuid': new_uuid,
            'id': len(self.manifest)+1,
            'Tag': settings.Tag,
            'info': self.daily_event_name.format(today),
            'analysis': settings.analysis,  # [0-2]
            'threat_level_id': settings.threat_level_id,  # [1-4]
            'published': settings.published,
            'date': today
        }
        event = MISPEvent()
        event.from_dict(**event_dict)

        # reference org
        org_dict = {}
        org_dict['name'] = settings.org_name
        org_dict['uui'] = settings.org_uuid
        event['Orgc'] = org_dict

        # save event on disk
        self.flush_event(new_event=event)
        # add event to manifest
        self.manifest[event['uuid']] = self._addEventToManifest(event)
        self.save_manifest()
        return event
