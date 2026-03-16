from __future__ import annotations

import glob
import os
import re

from .. import MISPEvent

try:
    from neo4j import GraphDatabase  # type: ignore
    has_neo4j = True
except ImportError:
    has_neo4j = False


class Neo4j():

    def __init__(self, host: str='localhost', port: int=7687, username: str='neo4j', password: str='neo4j') -> None:
        if not has_neo4j:
            raise Exception('neo4j is required, please install: pip install neo4j')
        self.driver = GraphDatabase.driver(f"neo4j://{host}:{port}", auth=(username, password))


    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        self.driver.close()

    def load_events_directory(self, directory: str) -> None:
        self.events: list[MISPEvent] = []
        for path in glob.glob(os.path.join(directory, '*.json')):
            e = MISPEvent()
            e.load_file(path)
            self.import_event(e)

    def del_all(self) -> None:
        with self.driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")

    def import_event(self, event: MISPEvent) -> None:
        def _tx(tx) -> None:
            tx.run(
            "CREATE (e:Event {uuid: $uuid, name: $name})",    # Create the Event node with uuid and info as properties
            uuid=str(event.uuid), name=event.info
            )
            for a in event.attributes:
                safe_type = re.sub(r'[^A-Za-z0-9_]', '_', a.type) # Sanitisation - Neo4j labels must be alphanumeric or underscores
                if safe_type != a.type:
                    print(f"Warning: Attribute type '{a.type}' sanitized to '{safe_type}'")

                tx.run(
                    "MATCH (e:Event {{uuid: $event_uuid}}) " # Find the Event node by uuid reate 
                    "CREATE (attr:Attribute:$($attribute_type) {{uuid: $uuid, category: $category, name: $value}}) " # Create an Attribute node with the sanitized type as a label
                    "CREATE (e)-[:`is member`]->(attr)", # Then create a relationship (is member) between the Event and Attribute
                    event_uuid=str(event.uuid), uuid=str(a.uuid),
                    category=a.category, value=a.value, attribute_type=safe_type
                )
                tx.run(
                    "MATCH (e:Event {uuid: $event_uuid}) " # Find the Event node by uuid 
                    "MATCH (attr:Attribute {uuid: $attr_uuid}) " # Find the Attribute node by uuid
                    "MERGE (v:Value {name: $value}) " # Merges a value node and adds has and is relationships below
                    "MERGE (e)-[:has]->(v) "
                    "MERGE (attr)-[:is]->(v)",
                    event_uuid=str(event.uuid), attr_uuid=str(a.uuid), value=a.value
                )


        with self.driver.session() as session:
            session.execute_write(_tx)
