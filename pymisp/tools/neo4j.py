from __future__ import annotations

import glob
import os

from .. import MISPEvent

try:
    from py2neo import authenticate, Graph, Node, Relationship  # type: ignore
    has_py2neo = True
except ImportError:
    has_py2neo = False


class Neo4j():

    def __init__(self, host: str='localhost:7474', username: str='neo4j', password: str='neo4j') -> None:
        if not has_py2neo:
            raise Exception('py2neo is required, please install: pip install py2neo')
        authenticate(host, username, password)
        self.graph = Graph(f"http://{host}/db/data/")

    def load_events_directory(self, directory: str) -> None:
        self.events: list[MISPEvent] = []
        for path in glob.glob(os.path.join(directory, '*.json')):
            e = MISPEvent()
            e.load(path)
            self.import_event(e)

    def del_all(self) -> None:
        self.graph.delete_all()

    def import_event(self, event: MISPEvent) -> None:
        tx = self.graph.begin()
        event_node = Node('Event', uuid=event.uuid, name=event.info)
        # event_node['distribution'] = event.distribution
        # event_node['threat_level_id'] = event.threat_level_id
        # event_node['analysis'] = event.analysis
        # event_node['published'] = event.published
        # event_node['date'] = event.date.isoformat()
        tx.create(event_node)
        for a in event.attributes:
            attr_node = Node('Attribute', a.type, uuid=a.uuid)
            attr_node['category'] = a.category
            attr_node['name'] = a.value
            # attr_node['to_ids'] = a.to_ids
            # attr_node['comment'] = a.comment
            # attr_node['distribution'] = a.distribution
            tx.create(attr_node)
            member_rel = Relationship(event_node, "is member", attr_node)
            tx.create(member_rel)
            val = Node('Value', name=a.value)
            ev = Relationship(event_node, "has", val)
            av = Relationship(attr_node, "is", val)
            s = val | ev | av
            tx.merge(s)
            # tx.graph.push(s)
        tx.commit()
