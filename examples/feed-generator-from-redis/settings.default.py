""" REDIS RELATED """
# Your redis server
host='127.0.0.1'
port=6379
db=0
## The keynames to POP element from
keyname_pop=['cowrie']

# OTHERS
## If key prefix not provided, data will be added as either object, attribute or sighting
fallback_MISP_type = 'object'
### How to handle the fallback
fallback_object_template_name = 'cowrie' # MISP-Object only
fallback_attribute_category = 'comment'  # MISP-Attribute only

## How frequent the event should be written on disk
flushing_interval=5*60
## The redis list keyname in which to put items that generated an error
keyname_error='feed-generation-error'

""" FEED GENERATOR CONFIGURATION """

# The output dir for the feed. This will drop a lot of files, so make
# sure that you use a directory dedicated to the feed
outputdir = 'output'

# Event meta data
## Required
### The organisation id that generated this feed
org_name='myOrg'
### Your organisation UUID
org_uuid=''
### The daily event name to be used in MISP.
### (e.g. honeypot_1, will produce each day an event of the form honeypot_1 dd-mm-yyyy)
daily_event_name='PyMISP default event name'

## Optional
analysis=0
threat_level_id=3
published=False
Tag=[
    {
        "colour": "#ffffff",
        "name": "tlp:white"
    },
    {
        "colour": "#ff00ff",
        "name": "my:custom:feed"
    }
]

# MISP Object constructor
from ObjectConstructor.CowrieMISPObject import CowrieMISPObject
from pymisp.tools import GenericObjectGenerator

constructor_dict = {
    'cowrie': CowrieMISPObject,
    'generic': GenericObjectGenerator
}

# Others
## Redis pooling time
sleep=60
