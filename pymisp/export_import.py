#!/usr/bin/env python
# -*- coding: utf-8 -*-
from api import *


key_source = 'ExrJUE1UehwOWFM5FQbfNGpHTXXzWGsAeTk9ym3M'
url_source = 'https://misp.circl.lu/events'


key_dest = 'vmDndechmTUHHqsm2fsAJmmr29mOPuIkQlH4ATlW'
url_dest = 'https://misppriv.circl.lu/events'

init_server(url_source, key_source)

r = get_event(709)
source_data = unicode(r.json())

#init_server(url_dest, key_dest)

print source_data

#r = add_event(source_data.encode('utf-8'))

#print r.text

