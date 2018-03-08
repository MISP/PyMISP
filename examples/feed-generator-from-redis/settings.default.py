# Your redis server
host='127.0.0.1'
port=6379
db=0
## The keynames to POP element from
#keyname_pop='misp_feed_generator_key'
keyname_pop=['cowrie']

# The output dir for the feed. This will drop a lot of files, so make
# sure that you use a directory dedicated to the feed
outputdir = 'output'

# Event meta data
## Required
### The organisation id that generated this feed
org_name='myOrg'
### Your organisation UUID
org_uuid=''
### The daily event name to be used in MISP. (e.g. honeypot_1, will produce each day an event of the form honeypot_1 dd-mm-yyyy)
daily_event_name='PyMISP default event name'

## Optional
analysis=0
threat_level_id=3
published=False
Tag=[{
        "colour": "#ffffff",
        "name": "tlp:white"
    }]

# Others
## Redis pooling time
sleep=1
## The redis list keyname in which to put items that generated an error
keyname_error='feed-generation-error'
## Display an animation while adding element to MISP
allow_animation=True
## How frequent the event should be written on disk
flushing_interval=2*5
