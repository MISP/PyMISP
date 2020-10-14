#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random
from random import randint
import string
from pymisp import MISPEvent, MISPAttribute


def randomStringGenerator(size, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


def randomIpGenerator():
    return str(randint(0, 255)) + '.' + str(randint(0, 255)) + '.' + str(randint(0, 255)) + '.' + str(randint(0, 255))


def _attribute(category, type, value):
    attribute = MISPAttribute()
    attribute.category = category
    attribute.type = type
    attribute.value = value
    return attribute


def floodtxt(misp, event, maxlength=255):
    text = randomStringGenerator(randint(1, maxlength))
    choose_from = [('Internal reference', 'comment', text), ('Internal reference', 'text', text),
                   ('Internal reference', 'other', text), ('Network activity', 'email-subject', text),
                   ('Artifacts dropped', 'mutex', text), ('Artifacts dropped', 'filename', text)]
    misp.add_attribute(event, _attribute(*random.choice(choose_from)))


def floodip(misp, event):
    ip = randomIpGenerator()
    choose_from = [('Network activity', 'ip-src', ip), ('Network activity', 'ip-dst', ip)]
    misp.add_attribute(event, _attribute(*random.choice(choose_from)))


def flooddomain(misp, event, maxlength=25):
    a = randomStringGenerator(randint(1, maxlength))
    b = randomStringGenerator(randint(2, 3), chars=string.ascii_lowercase)
    domain = a + '.' + b
    choose_from = [('Network activity', 'domain', domain), ('Network activity', 'hostname', domain)]
    misp.add_attribute(event, _attribute(*random.choice(choose_from)))


def floodemail(misp, event, maxlength=25):
    a = randomStringGenerator(randint(1, maxlength))
    b = randomStringGenerator(randint(1, maxlength))
    c = randomStringGenerator(randint(2, 3), chars=string.ascii_lowercase)
    email = a + '@' + b + '.' + c
    choose_from = [('Network activity', 'email-dst', email), ('Network activity', 'email-src', email)]
    misp.add_attribute(event, _attribute(*random.choice(choose_from)))


def create_dummy_event(misp):
    event = MISPEvent()
    event.info = 'Dummy event'
    event = misp.add_event(event, pythonify=True)
    return event


def create_massive_dummy_events(misp, nbattribute):
    event = MISPEvent()
    event.info = 'massive dummy event'
    event = misp.add_event(event)
    print(event)
    functions = [floodtxt, floodip, flooddomain, floodemail]
    for i in range(nbattribute):
        functions[random.randint(0, len(functions) - 1)](misp, event)
