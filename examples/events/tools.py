#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random
from random import randint
import string
from pymisp import MISPEvent


def randomStringGenerator(size, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


def randomIpGenerator():
    return str(randint(0, 255)) + '.' + str(randint(0, 255)) + '.' + str(randint(0, 255)) + '.' + str(randint(0, 255))


def floodtxt(misp, event, maxlength=255):
    text = randomStringGenerator(randint(1, maxlength))
    textfunctions = [misp.add_internal_comment, misp.add_internal_text, misp.add_internal_other, misp.add_email_subject, misp.add_mutex, misp.add_filename]
    textfunctions[randint(0, 5)](event, text)


def floodip(misp, event):
    ip = randomIpGenerator()
    ipfunctions = [misp.add_ipsrc, misp.add_ipdst]
    ipfunctions[randint(0, 1)](event, ip)


def flooddomain(misp, event, maxlength=25):
    a = randomStringGenerator(randint(1, maxlength))
    b = randomStringGenerator(randint(2, 3), chars=string.ascii_lowercase)
    domain = a + '.' + b
    domainfunctions = [misp.add_hostname, misp.add_domain]
    domainfunctions[randint(0, 1)](event, domain)


def flooddomainip(misp, event, maxlength=25):
    a = randomStringGenerator(randint(1, maxlength))
    b = randomStringGenerator(randint(2, 3), chars=string.ascii_lowercase)
    domain = a + '.' + b
    ip = randomIpGenerator()
    misp.add_domain_ip(event, domain, ip)


def floodemail(misp, event, maxlength=25):
    a = randomStringGenerator(randint(1, maxlength))
    b = randomStringGenerator(randint(1, maxlength))
    c = randomStringGenerator(randint(2, 3), chars=string.ascii_lowercase)
    email = a + '@' + b + '.' + c
    emailfunctions = [misp.add_email_src, misp.add_email_dst]
    emailfunctions[randint(0, 1)](event, email)


def floodattachment(misp, eventid, distribution, to_ids, category, comment, info, analysis, threat_level_id):
    filename = randomStringGenerator(randint(1, 128))
    misp.upload_sample(filename, 'dummy', eventid, distribution, to_ids, category, comment, info, analysis, threat_level_id)


def create_dummy_event(misp):
    event = misp.new_event(0, 4, 0, 'dummy event')
    flooddomainip(misp, event)
    floodattachment(misp, event['Event']['id'], event['Event']['distribution'], False, 'Payload delivery', '', event['Event']['info'], event['Event']['analysis'], event['Event']['threat_level_id'])


def create_massive_dummy_events(misp, nbattribute):
    event = MISPEvent()
    event.info = 'massive dummy event'
    event = misp.add_event(event)
    print(event)
    eventid = event.id
    distribution = '0'
    functions = [floodtxt, floodip, flooddomain, flooddomainip, floodemail, floodattachment]
    for i in range(nbattribute):
        choice = randint(0, 5)
        if choice == 5:
            floodattachment(misp, eventid, distribution, False, 'Payload delivery', '', event.info, event.analysis, event.threat_level_id)
        else:
            functions[choice](misp, event)
