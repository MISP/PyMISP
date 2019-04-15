#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#
#    A simple tool to add file metadata objects to a MISP event.
#    Copyright (C) 2019 Roger Johnston
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

from pymisp import PyMISP
from pymisp.tools.mimetypeobject import MIMETypeObject

import traceback
from keys import misp_url, misp_key, misp_verifycert
import glob
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract metadata out of file and add MISP object to a MISP instance.')
    parser.add_argument("-e", "--event", required=True, help="Event ID to update.")
    parser.add_argument("-p", "--path", required=True, help="Path to file (expanded using glob).")
    args = parser.parse_args()

    pymisp = PyMISP(misp_url, misp_key, misp_verifycert)

    for f in glob.glob(args.path):
        try:
            mispObject = MIMETypeObject(filepath=f)
        except Exception as e:
            traceback.print_exc()
            continue

        if mispObject:
            r = pymisp.add_object(args.event, mispObject)
