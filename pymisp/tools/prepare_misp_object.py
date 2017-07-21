#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from pymisp.tools import FileObject, PEObject
from pymisp.tools import make_binary_objects
import traceback


try:
    import lief
    HAS_LIEF = True
except ImportError:
    HAS_LIEF = False
    raise ImportError("Please install lief: https://github.com/lief-project/LIEF")


if __name__ == '__main__':
    pymisp = PyMISP('https://mispbeta.circl.lu', 'et9ZEgn70YJ6URkCr6741LpJNAVUMYD1rM063od3')


    # fo, peo, seos = make_objects('/home/raphael/.viper/projects/troopers17/vt_samples/1189/566ab945f61be016bfd9e83cc1b64f783b9b8deb891e6d504d3442bc8281b092')
    import glob
    for f in glob.glob('/home/raphael/.viper/projects/troopers17/vt_samples/*/*'):
    #for f in glob.glob('/home/raphael/gits/pefile-tests/tests/corkami/*/*.exe'):
    #for f in glob.glob('/home/raphael/gits/pefile-tests/tests/corkami/pocs/version_mini.exe'):
    #for f in glob.glob('/home/raphael/gits/pefile-tests/tests/corkami/pocs/version_cust.exe'):
    #for f in glob.glob('/home/raphael/gits/pefile-tests/tests/data/*.dll'):
        print('\n', f)
        try:
            fo, peo, seos = make_binary_objects(f)
        except Exception as e:
            traceback.print_exc()
            continue
        continue
        if fo:
            response = pymisp.add_object(2221, 7, fo)
            print(response)
        if peo:
            pymisp.add_object(2221, 11, peo)
        if seos:
            for s in seos:
                pymisp.add_object(2221, 12, s)

        #with open('fileobj.json', 'w') as f:
        #    json.dump(fo, f)
        #with open('peobj.json', 'w') as f:
        #    json.dump(peo, f)
        #with open('seobj.json', 'w') as f:
        #    json.dump(seos, f)
        break
