#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import json
import os
import hashlib
import argparse
import datetime, time
import uuid
import threading
import redis

from redis import StrictRedis as Redis
import settings

from pymisp import MISPEvent, MISPAttribute
from pymisp.tools import GenericObjectGenerator

evtObj=thr=None # animation thread

def get_system_templates():
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
    return str(uuid.uuid4())

def processing_animation(evtObj, buffer_state, refresh_rate=5):
    i = 0
    buffer_state_str = 'attributes: {}, objects: {}, sightings: {}'.format(buffer_state['attribute'], buffer_state['object'], buffer_state['sighting'])
    while True:
        if evtObj.is_set():
            print(" "*(len(buffer_state_str)+20), end="\r", sep="") # overwrite last characters
            sys.stdout.flush()
            return
        i += 1
        print("Remaining: { %s }\t" % buffer_state_str + "/-\|"[i%4], end="\r", sep="")
        sys.stdout.flush()
        time.sleep(1.0/float(refresh_rate))

def beautyful_sleep(sleep):
    length = 20
    sleeptime = float(sleep) / float(length)
    for i in range(length):
        temp_string = '|'*i + ' '*(length-i-1)
        print('sleeping [{}]'.format(temp_string), end='\r', sep='')
        sys.stdout.flush()
        time.sleep(sleeptime)




class RedisToMISPFeed:
    SUFFIX_SIGH = '_sighting'
    SUFFIX_ATTR = '_attribute'
    SUFFIX_OBJ = '_object'
    SUFFIX_LIST = [SUFFIX_SIGH, SUFFIX_ATTR, SUFFIX_OBJ]

    def __init__(self):
        self.host = settings.host
        self.port = settings.port
        self.db = settings.db
        self.serv = redis.StrictRedis(self.host, self.port, self.db, decode_responses=True)

        self.keynames = []
        for k in settings.keyname_pop:
            for s in self.SUFFIX_LIST:
                self.keynames.append(k+s)

        # get all templates
        self.sys_templates = get_system_templates()

        self.sleep = settings.sleep
        self.flushing_interval = settings.flushing_interval
        self.flushing_next = time.time() + self.flushing_interval

        self.manifest = {}
        self.attributeHashes = []

        self.keynameError = settings.keyname_error
        self.allow_animation = settings.allow_animation

        self.daily_event_name = settings.daily_event_name + ' {}'
        _, self.current_event_uuid, self.event_name = self.get_last_event_from_manifest()
        self.current_date = datetime.date.today()
        self.current_event = self.get_event_from_id(self.current_event_uuid)

        global evtObj, thr
        self.evtObj = evtObj
        self.thr = thr

    def consume(self):
        while True:
            flag_empty = True
            for key in self.keynames:
                while True:
                    data = self.pop(key)
                    if data is None:
                        break
                    try:
                        self.perform_action(key, data)
                    except Exception as error:
                        self.save_error_to_redis(error, data)
                    flag_empty = False


            if flag_empty and self.flushing_next <= time.time():
                self.flush_event()
                flushing_next = time.time() + self.flushing_interval

            beautyful_sleep(5)

    def pop(self, key):
        popped = self.serv.rpop(key)
        if popped is None:
            return None
        try:
            popped = json.loads(popped)
        except ValueError as error:
            self.save_error_to_redis(error, popped)
        except ValueError as error:
            self.save_error_to_redis(error, popped)
        return popped


    def perform_action(self, key, data):
        self.update_daily_event_id()

        # sighting
        if key.endswith(self.SUFFIX_SIGH):
            pass

        # attribute
        elif key.endswith(self.SUFFIX_ATTR):
            attr_type = data.pop('type')
            attr_value = data.pop('value')
            self.current_event.add_attribute(attr_type, attr_value, **data)
            self.add_hash(attr_type, attr_value)

        # object
        elif key.endswith(self.SUFFIX_OBJ):
            # create the MISP object
            obj_name = data.pop('name')
            misp_object = GenericObjectGenerator(obj_name)
            for k, v in data.items():
                if k not in self.sys_templates[obj_name]['attributes']: # attribute is not in the object template definition
                    # add it with type text
                    misp_object.add_attribute(k, **{'value': v, 'type': 'text'})
                else:
                    misp_object.add_attribute(k, **{'value': v})

            self.current_event.add_object(misp_object)
            for attr_type, attr_value in data.items():
                self.add_hash(attr_type, attr_value)


        else:
            raise NoValidKey("Can't define action to perform")


    def add_hash(self, attr_type, attr_value):
         if ('|' in attr_type or attr_type == 'malware-sample'):
             split = attr_value.split('|')
             self.attributeHashes.append([hashlib.md5(str(split[0]).encode("utf-8")).hexdigest(), self.current_event_uuid])
             self.attributeHashes.append([hashlib.md5(str(split[1]).encode("utf-8")).hexdigest(), self.current_event_uuid])
         else:
             self.attributeHashes.append([hashlib.md5(str(attr_value).encode("utf-8")).hexdigest(), self.current_event_uuid])

    # Manifest
    def init_manifest(self):
        # create an empty manifest
        with open(os.path.join(settings.outputdir, 'manifest.json'), 'w') as f:
            pass
        # create new event and save manifest
        self.create_daily_event()


    def flush_event(self, new_event=None):
        print('Writting event on disk'+' '*20)
        self.print_processing()
        if new_event is not None:
            event_uuid = new_event['uuid']
            event = new_event
        else:
            event_uuid = self.current_event_uuid
            event = self.current_event

        eventFile = open(os.path.join(settings.outputdir, event_uuid + '.json'), 'w')
        eventFile.write(event.to_json())
        eventFile.close()

        self.saveHashes()
        if self.allow_animation:
            self.evtObj.set()
            self.thr.join()

    def saveManifest(self):
        try:
            manifestFile = open(os.path.join(settings.outputdir, 'manifest.json'), 'w')
            manifestFile.write(json.dumps(self.manifest))
            manifestFile.close()
            print('Manifest saved')
        except Exception as e:
            print(e)
            sys.exit('Could not create the manifest file.')
    
    def saveHashes(self):
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

   
    def __addEventToManifest(self, event):
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

    # Retreive last event from the manifest, if the manifest doesn't exists
    # or if it is empty, initialize it.
    def get_last_event_from_manifest(self):
        try:
            with open(os.path.join(settings.outputdir, 'manifest.json'), 'r') as f:
                man = json.load(f)
                dated_events = []
                for event_uuid, event_json in man.items():
                    # add events to manifest
                    self.manifest[event_uuid] = event_json
                    dated_events.append([event_json['date'], event_uuid, event_json['info']])
                dated_events.sort(key=lambda k: (k[0], k[2]), reverse=True) # sort by date then by event name
                return dated_events[0]
        except FileNotFoundError as e:
            print('Manifest not found, generating a fresh one')
            self.init_manifest()
            return self.get_last_event_from_manifest()

    # DAILY
    def update_daily_event_id(self):
        if self.current_date != datetime.date.today(): # create new event
            # save current event on disk
            self.flush_event()
            self.current_event = create_daily_event()
            self.current_event_uuid = self.current_event.get('uuid')
            self.event_name = self.current_event.info

    def get_event_from_id(self, event_uuid):
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
            'analysis': settings.analysis, # [0-2]
            'threat_level_id': settings.threat_level_id, # [1-4]
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
        self.manifest[event['uuid']] = self.__addEventToManifest(event)
        self.saveManifest()
        return event

    # OTHERS
    def get_buffer_state(self):
        buffer_state = {'attribute': 0, 'object': 0, 'sighting': 0}
        for k in self.keynames:
            _ , suffix = k.rsplit('_', 1)
            buffer_state[suffix] += self.serv.llen(k)
        return buffer_state


    def print_processing(self):
        if self.allow_animation:
            buff_states = self.get_buffer_state()
            self.evtObj = threading.Event()
            self.thr = threading.Thread(name="processing-animation", target=processing_animation, args=(self.evtObj, buff_states, ))
            self.thr.start()

    def save_error_to_redis(self, error, item):
        to_push = {'error': str(error), 'item': str(item)}
        print('Error:', str(error), '\nOn adding:', item)
        self.serv.lpush(self.keynameError, to_push)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Pop item fom redis and add it to the MISP feed. By default, each action are pushed into a daily named event. Configuration taken from the file settings.py.")
    args = parser.parse_args()

    redisToMISP = RedisToMISPFeed()
    try:
        redisToMISP.consume()
    except (KeyboardInterrupt, SystemExit):
        if evtObj is not None:
            evtObj.set()
            thr.join()
