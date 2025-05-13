import requests
import json
from pymisp import PyMISP, MISPEvent, MISPOrganisation
from keys import misp_url, misp_key, misp_verifycert, proofpoint_key

# initialize PyMISP and set url for Panorama
misp = PyMISP(url=misp_url, key=misp_key, ssl=misp_verifycert)

urlVap = "https://tap-api-v2.proofpoint.com/v2/people/vap?window=30"  # Window can be 14, 30, and 90 Days

headers = {
    'Authorization': "Basic " + proofpoint_key
}

responseVap = requests.request("GET", urlVap, headers=headers)

jsonDataVap = json.loads(responseVap.text)

for alert in jsonDataVap["users"]:
    orgc = MISPOrganisation()
    orgc.name = 'Proofpoint'
    orgc.id = '#{ORGC.ID}'  # organisation id
    orgc.uuid = '#{ORGC.UUID}'  # organisation uuid
    # initialize and set MISPEvent()
    event = MISPEvent()
    event.Orgc = orgc
    event.info = 'Very Attacked Person ' + jsonDataVap["interval"]
    event.distribution = 0  # Optional, defaults to MISP.default_event_distribution in MISP config
    event.threat_level_id = 2  # setting this to 0 breaks the integration
    event.analysis = 0  # Optional, defaults to 0 (initial analysis)

    totalVapUsers = event.add_attribute('counter', jsonDataVap["totalVapUsers"], comment="Total VAP Users")

    averageAttackIndex = event.add_attribute('counter', jsonDataVap["averageAttackIndex"], comment="Average Attack Count")

    vapAttackIndexThreshold = event.add_attribute('counter', jsonDataVap["vapAttackIndexThreshold"], comment="Attack Threshold")

    emails = event.add_attribute('email-dst', alert["identity"]["emails"], comment="Email Destination")

    attack = event.add_attribute('counter', alert["threatStatistics"]["attackIndex"], comment="Attack Count")

    vip = event.add_attribute('other', str(alert["identity"]["vip"]), comment="VIP")

    guid = event.add_attribute('other', alert["identity"]["guid"], comment="GUID")

    if alert["identity"]["customerUserId"] is not None:
        customerUserId = event.add_attribute('other', alert["identity"]["customerUserId"], comment="Customer User Id")

    if alert["identity"]["department"] is not None:
        department = event.add_attribute(alert['other', "identity"]["department"], comment="Department")

    if alert["identity"]["location"] is not None:
        location = event.add_attribute('other', alert["identity"]["location"], comment="Location")

    if alert["identity"]["name"] is not None:

        name = event.add_attribute('target-user', alert["identity"]["name"], comment="Name")

    if alert["identity"]["title"] is not None:

        title = event.add_attribute('other', alert["identity"]["title"], comment="Title")

    event.add_tag("VAP")

    misp.add_event(event.to_json())
