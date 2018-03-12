#!/usr/bin/env python3

import os.path
from flask import Flask
from flask_autoindex import AutoIndex
from settings import outputdir

app = Flask(__name__)
AutoIndex(app, browse_root=os.path.join(os.path.curdir, outputdir))

if __name__ == '__main__':
    app.run(host='0.0.0.0')
