#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pymisp.tools import feed_meta_generator
import argparse
from pathlib import Path

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Build meta files for feed')
    parser.add_argument("--feed", required=True, help="Path to directory containing the feed.")
    args = parser.parse_args()

    feed = Path(args.feed)

    feed_meta_generator(feed)
