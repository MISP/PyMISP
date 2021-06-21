# What

This python script can be used to generate a MISP feed based on an existing MISP instance.

# Installation

````
git clone https://github.com/MISP/PyMISP.git
cd examples/feed-generator
cp settings.default.py settings.py
vi settings.py #adjust your settings
python3 generate.py
````

# Output

The generated feed will be stored in your `outputdir`.
It contains the files:
- `manifest.json` - containing the feed manifest (generic event information)
- `hashes.csv` - listing the hashes of the attribute values
- `*.json` - a large amount of `json` files 


# Importing in MISP

To import this feed into your MISP instance:
- Sync Actions > List Feeds > Add feed
- Fill in the form while ensuring the 'source format' is set to 'MISP Feed'

For more information about feeds please read: https://misp.gitbooks.io/misp-book/content/managing-feeds/
