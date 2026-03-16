#!/usr/bin/env python

from __future__ import annotations
# Keep type annotations as strings until needed, which avoids some runtime import issues.

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


from pymisp import MISPEvent

from pymisp.tools import neo4j as neo4j_tool_mod

class TestNeo4j(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture_path = Path('tests') / 'misp_event.json'
        cls.fixture_event = MISPEvent()
        cls.fixture_event.load_file(cls.fixture_path)

    def _build_neo4j(self) -> tuple[neo4j_tool_mod.Neo4j, MagicMock, MagicMock]:
        driver = MagicMock()
        graph_database = MagicMock()
        graph_database.driver.return_value = driver

        with patch.object(neo4j_tool_mod, 'has_neo4j', True), patch.object(neo4j_tool_mod, 'GraphDatabase', graph_database, create=True):
            neo4j = neo4j_tool_mod.Neo4j(host='graph.local', port=7777, username='alice', password='secret')

        return neo4j, driver, graph_database

    def _load_fixture_event(self) -> MISPEvent:
        event = MISPEvent()
        event.load_file(self.fixture_path)
        return event

    def test_init_raises_when_neo4j_dependency_is_missing(self) -> None:
        
        with patch.object(neo4j_tool_mod, 'has_neo4j', False):
            with self.assertRaisesRegex(Exception, 'neo4j is required'):
                neo4j_tool_mod.Neo4j()

    def test_init_uses_expected_driver_configuration(self) -> None:
        _, driver, graph_database = self._build_neo4j()
        graph_database.driver.assert_called_once_with('neo4j://graph.local:7777', auth=('alice', 'secret'))
        self.assertIsNotNone(driver)

    def test_context_manager_and_delete_all_close_and_run_query(self) -> None:
        neo4j, driver, _ = self._build_neo4j()
        session = driver.session.return_value.__enter__.return_value
        
        with neo4j as managed:
            self.assertIs(managed, neo4j)
            neo4j.del_all()

        session.run.assert_called_once_with('MATCH (n) DETACH DELETE n')
        driver.close.assert_called_once()

    def test_load_events_directory_imports_json_fixture(self) -> None:
        neo4j, _, _ = self._build_neo4j()

        with tempfile.TemporaryDirectory() as temp_dir:
            shutil.copy(self.fixture_path, Path(temp_dir) / 'event.json')
            with patch.object(neo4j, 'import_event') as import_event:
                neo4j.load_events_directory(temp_dir)

        import_event.assert_called_once()
        imported_event = import_event.call_args.args[0]
        self.assertEqual(imported_event.uuid, self.fixture_event.uuid)
        self.assertEqual(imported_event.info, self.fixture_event.info)
        self.assertEqual(len(imported_event.attributes), len(self.fixture_event.attributes))

    def test_import_event_creates_expected_queries_for_fixture(self) -> None:
        neo4j, driver, _ = self._build_neo4j()
        session = driver.session.return_value.__enter__.return_value
        tx = MagicMock()
        session.execute_write.side_effect = lambda callback: callback(tx)
        event = self._load_fixture_event()

        neo4j.import_event(event)
        self.assertEqual(tx.run.call_count, 1 + len(event.attributes) * 2)


        event_query, event_params = tx.run.call_args_list[0]
        self.assertIn('CREATE (e:Event {uuid: $uuid, name: $name})', event_query[0])
        self.assertEqual(event_params, {'uuid': str(event.uuid), 'name': event.info})

        first_attribute = event.attributes[0]
        attribute_query, attribute_params = tx.run.call_args_list[1]
        self.assertIn('MATCH (e:Event {{uuid: $event_uuid}})', attribute_query[0])
        self.assertIn('CREATE (attr:Attribute:$($attribute_type)', attribute_query[0])
        self.assertEqual(attribute_params, {
            'event_uuid': str(event.uuid),
            'uuid': str(first_attribute.uuid),
            'category': first_attribute.category,
            'value': first_attribute.value,
            'attribute_type': first_attribute.type,
        })

        value_query, value_params = tx.run.call_args_list[2]
        self.assertIn('MERGE (v:Value {name: $value})', value_query[0])
        self.assertEqual(value_params, {
            'event_uuid': str(event.uuid),
            'attr_uuid': str(first_attribute.uuid),
            'value': first_attribute.value,
        })

    def test_import_event_sanitizes_attribute_types_before_querying(self) -> None:
        neo4j, driver, _ = self._build_neo4j()
        session = driver.session.return_value.__enter__.return_value
        tx = MagicMock()
        session.execute_write.side_effect = lambda callback: callback(tx)
        event = self._load_fixture_event()
        event.attributes[0].type = 'domain|ip'

        with patch('builtins.print') as mocked_print:
            neo4j.import_event(event)

        sanitized_params = tx.run.call_args_list[1].kwargs
        self.assertEqual(sanitized_params['attribute_type'], 'domain_ip')
        mocked_print.assert_called_once_with("Warning: Attribute type 'domain|ip' sanitized to 'domain_ip'")


if __name__ == '__main__':
    unittest.main()
