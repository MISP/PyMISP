#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
# Copy Emerging Threats Block IPs list to several MISP events
# Because of the large size of the list the first run will take a minute
# Running it again will update the MISP events if changes are detected
#
# This script requires PyMISP 2.4.50 or later

import sys, json, time, requests
from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert

et_url = 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt'
et_str = 'Emerging Threats '

def init_misp():
    global mymisp
    mymisp = PyMISP(misp_url, misp_key, misp_verifycert)

def load_misp_event(eid):
    global et_attr
    global et_drev
    global et_event
    et_attr = {}
    et_drev = {}
    
    et_event = mymisp.get(eid)
    echeck(et_event)
    for a in et_event['Event']['Attribute']:
        if a['category'] == 'Network activity':
            et_attr[a['value']] = a['id']
            continue
        if a['category'] == 'Internal reference':
            et_drev = a;

def init_et():
    global et_data
    global et_rev
    requests.packages.urllib3.disable_warnings()
    s = requests.Session()
    r = s.get(et_url)
    if r.status_code != 200:
        raise Exception('Error getting ET data: {}'.format(r.text))
    name = ''
    et_data = {}
    et_rev = 0
    for line in r.text.splitlines():
        if line.startswith('# Rev '):
            et_rev = int(line[6:])
            continue
        if line.startswith('#'):
            name = line[1:].strip()
            if et_rev and not et_data.get(name):
                et_data[name] = {}
            continue
        l = line.rstrip()
        if l:
            et_data[name][l] = name

def update_et_event(name):
    if et_drev and et_rev and int(et_drev['value']) < et_rev:
        # Copy MISP attributes to new dict
        et_ips = dict.fromkeys(et_attr.keys())

        # Weed out attributes still in ET data
        for k,v in et_data[name].items():
            et_attr.pop(k, None)
        
        # Delete the leftover attributes from MISP
        for k,v in et_attr.items():
            r = mymisp.delete_attribute(v)
            if r.get('errors'):
                print "Error deleting attribute {} ({}): {}\n".format(v,k,r['errors'])

        # Weed out ips already in the MISP event
        for k,v in et_ips.items():
            et_data[name].pop(k, None)

        # Add new attributes to MISP event
        ipdst = []
        for i,k in enumerate(et_data[name].items(), 1-len(et_data[name])):
            ipdst.append(k[0])
            if i % 100 == 0:
                r = mymisp.add_ipdst(et_event, ipdst)
                echeck(r, et_event['Event']['id'])
                ipdst = []

        # Update revision number
        et_drev['value'] = et_rev
        et_drev.pop('timestamp', None)
        attr = []
        attr.append(et_drev)

        # Publish updated MISP event 
        et_event['Event']['Attribute'] = attr
        et_event['Event']['published'] = False
        et_event['Event']['date'] = time.strftime('%Y-%m-%d')
        r = mymisp.publish(et_event)
        echeck(r, et_event['Event']['id'])

def echeck(r, eid=None):
    if r.get('errors'):
        if eid:
            print "Processing event {} failed: {}".format(eid, r['errors'])
        else:
            print r['errors']
        sys.exit(1)

if __name__ == '__main__':
    init_misp()
    init_et()

    for et_type in set(et_data.keys()):
        info = et_str + et_type
        r = mymisp.search_index(eventinfo=info)
        if r['response']:
            eid=r['response'][0]['id']
        else: # event not found, create it
            new_event = mymisp.new_event(info=info, distribution=3, threat_level_id=4, analysis=1)
            echeck(new_event)
            eid=new_event['Event']['id']
            r = mymisp.add_internal_text(new_event, 1, comment='Emerging Threats revision number')
            echeck(r, eid)
        load_misp_event(eid)
        update_et_event(et_type)
