#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from pymisp import Neo4j
from pymisp import MISPEvent
from keys import misp_url, misp_key
import argparse

"""
Sample Neo4J query:


MATCH ()-[r:has]->(n)
WITH n, count(r) as rel_cnt
WHERE rel_cnt > 5
MATCH (m)-[r:has]->(n)
RETURN m, n LIMIT 200;
"""

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get all the events matching a value.')
    parser.add_argument("-s", "--search", required=True, help="String to search.")
    parser.add_argument("--host", default='localhost:7474', help="Host where neo4j is running.")
    parser.add_argument("-u", "--user", default='neo4j', help="User on neo4j.")
    parser.add_argument("-p", "--password", default='neo4j', help="Password on neo4j.")
    parser.add_argument("-d", "--deleteall", action="store_true", default=False, help="Delete all nodes from the database")
    args = parser.parse_args()

    neo4j = Neo4j(args.host, args.user, args.password)
    if args.deleteall:
        neo4j.del_all()
    misp = PyMISP(misp_url, misp_key)
    result = misp.search_all(args.search)
    for json_event in result['response']:
        if not json_event['Event']:
            print(json_event)
            continue
        print('Importing', json_event['Event']['info'], json_event['Event']['id'])
        try:
            misp_event = MISPEvent()
            misp_event.load(json_event)
            neo4j.import_event(misp_event)
        except:
            print('broken')
