#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pymisp.tools import VehicleObject
import argparse


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get information for a VehicleObject and add MISP objects to a MISP instance.')
    parser.add_argument("-u", "--username", required=True, help="Account username.")
    parser.add_argument("-c", "--country", required=True, help="Country.")
    parser.add_argument("-r", "--registration", required=True, help="Registration ID.")
    parser.add_argument("-d", "--dump", action='store_true', help="(Debug) Dump the object in the terminal.")
    args = parser.parse_args()

    if args.dump:
        vehicle = VehicleObject(country=args.country, registration=args.registration, username=args.username)
        print(vehicle.report)
        print(vehicle.to_json())
    else:
        # not Implemented yet.
        pass
