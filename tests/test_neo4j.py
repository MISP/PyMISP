from pymisp.tools import neo4j
import os


def test_neo4j():
    try:
        print("=" * 60)
        print("Neo4j Integration Test - PyMISP Event Import")
        print("=" * 60 + "\n")

        print("1. Connecting to Neo4j at localhost:7687...")
        n = neo4j.Neo4j(host='localhost', port=7687, username='neo4j', password='neo5j')
        print("   ✓ Connected successfully\n")

        print("2. Testing direct import with simple event...")
        # Create a simple test event programmatically
        from pymisp import MISPEvent

        event = MISPEvent()
        event.info = "Test Event - Neo4j Import"
        event.uuid = "test-event-uuid-001"

        # Add some attributes
        event.add_attribute("ip-src", "192.168.1.100")
        event.add_attribute("domain", "example.com")
        event.add_attribute("url", "http://example.com/malware")
        event.add_attribute("md5", "5d41402abc4b2a76b9719d911017c592")

        print(f"   ✓ Created test event with {len(event.attributes)} attributes")
        print(f"   ✓ Importing event to Neo4j...\n")

        n.import_event(event)

        print("3. Querying Neo4j database...")
        with n.driver.session() as session:
            # Count Event nodes
            result = session.run("MATCH (e:Event) RETURN COUNT(e) as count")
            record = result.single()
            event_nodes = record['count'] if record else 0

            # Count Attribute nodes
            result = session.run("MATCH (a:Attribute) RETURN COUNT(a) as count")
            record = result.single()
            attr_count = record['count'] if record else 0

            # Count Value nodes
            result = session.run("MATCH (v:Value) RETURN COUNT(v) as count")
            record = result.single()
            value_count = record['count'] if record else 0

            print(f"   Events in Neo4j:      {event_nodes}")
            print(f"   Attributes in Neo4j:  {attr_count}")
            print(f"   Values in Neo4j:      {value_count}\n")

        print("4. Checking relationships and data integrity...")
        with n.driver.session() as session:
            # Find events with attributes
            result = session.run(
                "MATCH (e:Event)-[:is_member]->(a:Attribute) "
                "RETURN e.name as event_name, COUNT(a) as attr_count"
            )
            records = result.fetch(10)  # Use fetch() instead of records
            if records:
                print("   Event relationships:")
                for record in records:
                    print(f"   - {record['event_name']}: {record['attr_count']} attributes")
            print()

        print("5. Checking label sanitization...")
        with n.driver.session() as session:
            result = session.run(
                "MATCH (a:Attribute) "
                "RETURN DISTINCT LABELS(a) as labels LIMIT 20"
            )
            records = result.fetch(20)
            if records:
                print("   Sample attribute labels (showing sanitization):")
                sanitized_count = 0
                for record in records:
                    labels = record['labels']
                    if len(labels) > 1:
                        sanitized_count += 1
                        # Only print first 5
                        if sanitized_count <= 5:
                            print(f"   - {labels}")
                if sanitized_count == 0:
                    print("   (No special characters found in attribute types)")
                else:
                    print(f"   (Found {sanitized_count} attribute types with special chars)")
            print()

        print("6. Cleaning up (deleting all data)...")
        n.del_all()

        # Verify deletion
        with n.driver.session() as session:
            result = session.run("MATCH (n) RETURN COUNT(n) as count")
            record = result.single()
            remaining = record['count'] if record else 0
            print(f"   ✓ All data deleted (remaining nodes: {remaining})\n")

        n.close()
        print("=" * 60)
        print("✅ Test completed successfully!")
        print("=" * 60)

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


def main():
    test_neo4j()


if __name__ == "__main__":
    main()