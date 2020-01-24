from trustar import TruStar, datetime_to_millis
from datetime import datetime, timedelta
from keys import misp_url, misp_key, misp_verifycert
from pymisp import PyMISP, MISPEvent, MISPOrganisation, MISPObject

# enclave_ids = '7a33144f-aef3-442b-87d4-dbf70d8afdb0'  # RHISAC
enclave_ids = None

time_interval = {'days': 30, 'hours': 0}

distribution = None  # Optional, defaults to MISP.default_event_distribution in MISP config
threat_level_id = None  # Optional, defaults to MISP.default_event_threat_level in MISP config
analysis = None  # Optional, defaults to 0 (initial analysis)



tru = TruStar()

misp = PyMISP(misp_url, misp_key, misp_verifycert)

now = datetime.now()

# date range for pulling reports is last 4 hours when script is run
to_time = datetime.now()
from_time = to_time - timedelta(**time_interval)

# convert to millis since epoch
to_time = datetime_to_millis(to_time)
from_time = datetime_to_millis(from_time)

if not enclave_ids:
    reports = tru.get_reports(from_time=from_time,
                              to_time=to_time)
else:
    reports = tru.get_reports(from_time=from_time,
                          to_time=to_time,
                          is_enclave=True,
                          enclave_ids=enclave_ids)

# loop through each trustar report and create MISP events for each
for report in reports:
    # initialize and set MISPEvent()
    event = MISPEvent()
    event.info = report.title
    event.distribution = distribution
    event.threat_level_id = threat_level_id
    event.analysis = analysis

    # get tags for report
    for tag in tru.get_enclave_tags(report.id):
        event.add_tag(tag.name)

    obj = MISPObject('trustar_report', standalone=False, strict=True)
    # get indicators for report
    for indicator in tru.get_indicators_for_report(report.id):
        obj.add_attribute(indicator.type, indicator.value)
    event.add_object(obj)
    # post each event to MISP via API
    misp.add_event(event)
