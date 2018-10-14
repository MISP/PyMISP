#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Export IOC's from MISP in CEF format
# Based on cef_export.py MISP module by Hannah Ward

import sys
import datetime
from pymisp import PyMISP, MISPAttribute
from keys import misp_url, misp_key, misp_verifycert

cefconfig  = {"Default_Severity":1, "Device_Vendor":"MISP", "Device_Product":"MISP", "Device_Version":1}

cefmapping = {"ip-src":"src", "ip-dst":"dst", "hostname":"dhost", "domain":"destinationDnsDomain",
              "md5":"fileHash", "sha1":"fileHash", "sha256":"fileHash",
              "filename|md5":"fileHash", "filename|sha1":"fileHash", "filename|sha256":"fileHash",
              "url":"request"}

mispattributes = {'input':list(cefmapping.keys())}


def make_cef(event):
  for attr in event["Attribute"]:
    if attr["to_ids"] and attr["type"] in cefmapping:
      if '|' in attr["type"] and '|' in attr["value"]:
        value = attr["value"].split('|')[1]
      else:
        value = attr["value"]
      response = "{} host CEF:0|{}|{}|{}|{}|{}|{}|msg={} customerURI={} externalId={} {}={}".format(
                      datetime.datetime.fromtimestamp(int(attr["timestamp"])).strftime("%b %d %H:%M:%S"),
                      cefconfig["Device_Vendor"],
                      cefconfig["Device_Product"],
                      cefconfig["Device_Version"],
                      attr["category"],
                      attr["category"],
                      cefconfig["Default_Severity"],
                      event["info"].replace("\\","\\\\").replace("=","\\=").replace('\n','\\n') + "(MISP Event #" + event["id"] + ")",
                      misp_url + 'events/view/' + event["id"],
                      attr["uuid"],
                      cefmapping[attr["type"]],
                      value,
               )
      print(str(bytes(response, 'utf-8'), 'utf-8'))
                        

def init_misp():
  global mymisp
  mymisp = PyMISP(misp_url, misp_key, misp_verifycert)


def echeck(r):
  if r.get('errors'):
    if r.get('message') == 'No matches.':
      return
    else:
      print(r['errors'])
      sys.exit(1)


def find_events():
  r = mymisp.search(controller='events', published=True, to_ids=True)
  echeck(r)
  if not r.get('response'):
    return
  for ev in r['response']:
    make_cef(ev['Event'])


if __name__ == '__main__':
  init_misp()
  find_events()
