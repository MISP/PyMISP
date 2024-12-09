# Generic MISP feed generator
## Description

- ``generator.py`` exposes a class allowing to generate a MISP feed in real time, where each items can be added on daily generated events.
- ``fromredis.py`` uses ``generator.py`` to generate a MISP feed based on data stored in redis.
- ``server.py`` is a simple script using *Flask_autoindex* to serve data to MISP.
- ``MISPItemToRedis.py`` permits to push (in redis) items to be added in MISP by the ``fromredis.py`` script.


## Installation

```
# redis-server
sudo apt install redis-server

# Check if redis is running
redis-cli ping

#  Feed generator
git clone https://github.com/MISP/PyMISP
cd PyMISP/examples/feed-generator-from-redis
cp settings.default.py settings.py
vi settings.py  # adjust your settings

python3 fromredis.py

# Serving file to MISP
bash install.sh
. ./serv-env/bin/activate
python3 server.py
````


## Usage

``` 
# Activate virtualenv
. ./serv-env/bin/activate
```

### Adding items to MISP

```
# create helper object
>>> helper = MISPItemToRedis("redis_list_keyname")

# push an attribute to redis
>>> helper.push_attribute("ip-src", "8.8.8.8", category="Network activity")

# push an object to redis
>>> helper.push_object({ "name": "cowrie", "session": "session_id", "username": "admin", "password": "admin", "protocol": "telnet" })

# push a sighting to redis
>>> helper.push_sighting(uuid="5a9e9e26-fe40-4726-8563-5585950d210f")
```

### Generate the feed

```
# Create the FeedGenerator object using the configuration provided in the file settings.py
# It will create daily event in which attributes and object will be added
>>> generator = FeedGenerator()

# Add an attribute to the daily event
>>> attr_type = "ip-src"
>>> attr_value = "8.8.8.8"
>>> additional_data = {}
>>> generator.add_attribute_to_event(attr_type, attr_value, **additional_data)

# Add a cowrie object to the daily event
>>> obj_name = "cowrie"
>>> obj_data = { "session": "session_id", "username": "admin", "password": "admin", "protocol": "telnet" }
>>> generator.add_object_to_event(obj_name, **obj_data)

# Immediately write the event to the disk (Bypassing the default flushing behavior)
>>> generator.flush_event()
```

### Consume stored data in redis

```
# Configuration provided in the file settings.py
>>> python3 fromredis.py
```

### Serve data to MISP

```
>>> python3 server.py
```
