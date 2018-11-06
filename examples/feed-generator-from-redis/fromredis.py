#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import argparse
import datetime
import time
import redis

import settings

from generator import FeedGenerator


def beautyful_sleep(sleep, additional):
    length = 20
    sleeptime = float(sleep) / float(length)
    for i in range(length):
        temp_string = '|'*i + ' '*(length-i-1)
        print('sleeping [{}]\t{}'.format(temp_string, additional), end='\r', sep='')
        sys.stdout.flush()
        time.sleep(sleeptime)


class RedisToMISPFeed:
    SUFFIX_SIGH = '_sighting'
    SUFFIX_ATTR = '_attribute'
    SUFFIX_OBJ = '_object'
    SUFFIX_NO = ''
    SUFFIX_LIST = [SUFFIX_SIGH, SUFFIX_ATTR, SUFFIX_OBJ, SUFFIX_NO]

    def __init__(self):
        self.host = settings.host
        self.port = settings.port
        self.db = settings.db
        self.serv = redis.StrictRedis(self.host, self.port, self.db, decode_responses=True)

        self.generator = FeedGenerator()

        self.keynames = []
        for k in settings.keyname_pop:
            for s in self.SUFFIX_LIST:
                self.keynames.append(k+s)

        self.keynameError = settings.keyname_error

        self.update_last_action("Init system")

    def consume(self):
        self.update_last_action("Started consuming redis")
        while True:
            for key in self.keynames:
                while True:
                    data = self.pop(key)
                    if data is None:
                        break
                    try:
                        self.perform_action(key, data)
                    except Exception as error:
                        self.save_error_to_redis(error, data)

            beautyful_sleep(5, self.format_last_action())

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
        # sighting
        if key.endswith(self.SUFFIX_SIGH):
            if self.generator.add_sighting_on_attribute():
                self.update_last_action("Added sighting")
            else:
                self.update_last_action("Error while adding sighting")

        # attribute
        elif key.endswith(self.SUFFIX_ATTR):
            attr_type = data.pop('type')
            attr_value = data.pop('value')
            if self.generator.add_attribute_to_event(attr_type, attr_value, **data):
                self.update_last_action("Added attribute")
            else:
                self.update_last_action("Error while adding attribute")

        # object
        elif key.endswith(self.SUFFIX_OBJ):
            # create the MISP object
            obj_name = data.pop('name')
            if self.generator.add_object_to_event(obj_name, **data):
                self.update_last_action("Added object")
            else:
                self.update_last_action("Error while adding object")

        else:
            # Suffix not provided, try to add anyway
            if settings.fallback_MISP_type == 'attribute':
                new_key = key + self.SUFFIX_ATTR
                # Add atribute type from the config
                if 'type' not in data and settings.fallback_attribute_type:
                    data['type'] = settings.fallback_attribute_type
                else:
                    new_key = None

            elif settings.fallback_MISP_type == 'object':
                new_key = key + self.SUFFIX_OBJ
                # Add object template name from the config
                if 'name' not in data and settings.fallback_object_template_name:
                    data['name'] = settings.fallback_object_template_name
                else:
                    new_key = None

            elif settings.fallback_MISP_type == 'sighting':
                new_key = key + self.SUFFIX_SIGH

            else:
                new_key = None

            if new_key is None:
                self.update_last_action("Redis key suffix not supported and automatic not configured")
            else:
                self.perform_action(new_key, data)

    # OTHERS
    def update_last_action(self, action):
        self.last_action = action
        self.last_action_time = datetime.datetime.now()

    def format_last_action(self):
        return "Last action: [{}] @ {}".format(
            self.last_action,
            self.last_action_time.isoformat().replace('T', ' '),
        )


    def save_error_to_redis(self, error, item):
        to_push = {'error': str(error), 'item': str(item)}
        print('Error:', str(error), '\nOn adding:', item)
        self.serv.lpush(self.keynameError, to_push)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Pop item fom redis and add "
        + "it to the MISP feed. By default, each action are pushed into a "
        + "daily named event. Configuration taken from the file settings.py.")
    args = parser.parse_args()

    redisToMISP = RedisToMISPFeed()
    redisToMISP.consume()
