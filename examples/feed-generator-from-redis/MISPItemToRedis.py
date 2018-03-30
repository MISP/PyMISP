#!/usr/bin/env python3
import redis
import json


class MISPItemToRedis:
    """This class provides a simple normalization to add MISP item to
    redis, so that they can easily be processed and added to MISP later on."""
    SUFFIX_SIGH = '_sighting'
    SUFFIX_ATTR = '_attribute'
    SUFFIX_OBJ = '_object'
    SUFFIX_LIST = [SUFFIX_SIGH, SUFFIX_ATTR, SUFFIX_OBJ]

    def __init__(self, keyname, host='localhost', port=6379, db=0):
        self.host = host
        self.port = port
        self.db = db
        self.keyname = keyname
        self.serv = redis.StrictRedis(self.host, self.port, self.db)

    def push_json(self, jdata, keyname, action):
        all_action = [s.lstrip('_') for s in self.SUFFIX_LIST]
        if action not in all_action:
            raise('Error: Invalid action. (Allowed: {})'.format(all_action))
        key = keyname + '_' + action
        self.serv.lpush(key, jdata)

    def push_attribute(self, type_value, value, category=None, to_ids=False,
                comment=None, distribution=None, proposal=False, **kwargs):
        to_push = {}
        to_push['type'] = type_value
        to_push['value'] = value
        if category is not None:
            to_push['category'] = category
        if to_ids is not None:
            to_push['to_ids'] = to_ids
        if comment is not None:
            to_push['comment'] = comment
        if distribution is not None:
            to_push['distribution'] = distribution
        if proposal is not None:
            to_push['proposal'] = proposal
        for k, v in kwargs.items():
            to_push[k] = v
        key = self.keyname + self.SUFFIX_ATTR
        self.serv.lpush(key, json.dumps(to_push))

    def push_attribute_obj(self, MISP_Attribute, keyname):
        key = keyname + self.SUFFIX_ATTR
        jdata = MISP_Attribute.to_json()
        self.serv.lpush(key, jdata)

    def push_object(self, dict_values):
        # check that 'name' field is present
        if 'name' not in dict_values:
            print("Error: JSON must contain the field 'name'")
        key = self.keyname + self.SUFFIX_OBJ
        self.serv.lpush(key, json.dumps(dict_values))

    def push_object_obj(self, MISP_Object, keyname):
        key = keyname + self.SUFFIX_OBJ
        jdata = MISP_Object.to_json()
        self.serv.lpush(key, jdata)

    def push_sighting(self, value=None, uuid=None, id=None, source=None,
                      type=0, timestamp=None, **kargs):
        to_push = {}
        if value is not None:
            to_push['value'] = value
        if uuid is not None:
            to_push['uuid'] = uuid
        if id is not None:
            to_push['id'] = id
        if source is not None:
            to_push['source'] = source
        if type is not None:
            to_push['type'] = type
        if timestamp is not None:
            to_push['timestamp'] = timestamp

        for k, v in kargs.items():
            if v is not None:
                to_push[k] = v
        key = self.keyname + self.SUFFIX_SIGH
        self.serv.lpush(key, json.dumps(to_push))

    def push_sighting_obj(self, MISP_Sighting, keyname):
        key = keyname + self.SUFFIX_SIGH
        jdata = MISP_Sighting.to_json()
        self.serv.lpush(key, jdata)
