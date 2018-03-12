# What

- ``generator.py`` exposes a class allowing to generate a MISP feed in real time.
- ``fromredis.py`` uses ``generator.py`` to generate a MISP feed based on data stored in redis.
- ``server.py`` is a simple script using *Flask_autoindex* to serve data to MISP


# Installation

````
#  Feed generator
git clone https://github.com/CIRCL/PyMISP
cd examples/feed-generator-from-redis
cp settings.default.py settings.py
vi settings.py  # adjust your settings

python3 fromredis.py

# Serving file to MISP
bash install.sh
. ./serv-env/bin/activate
python3 server.py
````
