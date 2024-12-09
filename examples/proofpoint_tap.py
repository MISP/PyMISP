import requests
from requests.auth import HTTPBasicAuth
import json
from pymisp import ExpandedPyMISP, MISPEvent
from keys import misp_url, misp_key, misp_verifycert, proofpoint_sp, proofpoint_secret
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if proofpoint_secret == '<proofpoint secret>':
    print('Set the proofpoint_secret in keys.py before running.  Exiting...')
    quit()

# initialize PyMISP and set url for Panorama
misp = ExpandedPyMISP(url=misp_url, key=misp_key, ssl=misp_verifycert)

urlSiem = "https://tap-api-v2.proofpoint.com/v2/siem/all"

alertType = ("messagesDelivered", "messagesBlocked", "clicksPermitted", "clicksBlocked")

# max query is 1h, and we want Proofpoint TAP api to return json
queryString = {
    "sinceSeconds": "3600",
    "format": "json"
}



responseSiem = requests.request("GET", urlSiem,  params=queryString, auth=HTTPBasicAuth(proofpoint_sp, proofpoint_secret))
if 'Credentials authentication failed' in responseSiem.text:
    print('Credentials invalid, please edit keys.py and try again')
    quit()

jsonDataSiem = json.loads(responseSiem.text)

for alert in alertType:
    for messages in jsonDataSiem[alert]:
        # initialize and set MISPEvent()
        event = MISPEvent()
        if alert == "messagesDelivered" or alert == "messagesBlocked":
            if alert == "messagesDelivered":
                event.info = alert
                event.distribution = 0  # Optional, defaults to MISP.default_event_distribution in MISP config
                event.threat_level_id = 2  # setting this to 0 breaks the integration 
                event.analysis = 0  # Optional, defaults to 0 (initial analysis)
            else:
                event.info = alert
                event.distribution = 0  # Optional, defaults to MISP.default_event_distribution in MISP config
                event.threat_level_id = 2  # BLOCKED = LOW
                event.analysis = 0  # Optional, defaults to 0 (initial analysis)

            recipient = event.add_attribute('email-dst', messages["recipient"][0])
            recipient.comment = 'recipient address'

            sender = event.add_attribute('email-src', messages["sender"])
            sender.comment = 'sender address'

            if messages["fromAddress"] is not None and messages["fromAddress"] != "" :
                fromAddress = event.add_attribute('email-src-display-name', messages["fromAddress"])

            headerFrom = event.add_attribute('email-header', messages["headerFrom"])
            headerFrom.comment = 'email header from'

            senderIP = event.add_attribute('ip-src', messages["senderIP"])
            senderIP.comment = 'sender IP'

            subject = event.add_attribute('email-subject', messages["subject"])
            subject.comment = 'email subject'

            if messages["quarantineFolder"] is not None and messages["quarantineFolder"] != "":
                quarantineFolder = event.add_attribute('comment', messages["quarantineFolder"])
                quarantineFolder.comment = 'quarantine folder'

            if messages["quarantineRule"] is not None and messages["quarantineRule"] != "":
                quarantineRule = event.add_attribute('comment', messages["quarantineRule"])
                quarantineRule.comment = 'quarantine rule'

            messageSize = event.add_attribute('size-in-bytes', messages["messageSize"])
            messageSize.comment = 'size of email in bytes'

            malwareScore = event.add_attribute('comment', messages["malwareScore"])
            malwareScore.comment = 'malware score'

            phishScore = event.add_attribute('comment', messages["phishScore"])
            phishScore.comment = 'phish score'

            spamScore = event.add_attribute('comment', messages["spamScore"])
            spamScore.comment = 'spam score'

            imposterScore = event.add_attribute('comment', messages["impostorScore"])
            imposterScore.comment = 'impostor score'

            completelyRewritten = event.add_attribute('comment', messages["completelyRewritten"])
            completelyRewritten.comment = 'proofpoint url defense'

            # grab the threat info for each message in TAP
            for threatInfo in messages["threatsInfoMap"]:
                threat_type = {
                    "url": "url",
                    "attachment": "email-attachment",
                    "message": "email-body"
                }

                threat = event.add_attribute(threat_type.get(threatInfo["threatType"]), threatInfo["threat"])
                threat.comment = 'threat'

                threatUrl = event.add_attribute('link', threatInfo["threatUrl"])
                threatUrl.comment = 'link to threat in TAP'

                threatStatus = event.add_attribute('comment', threatInfo["threatStatus"])
                threatStatus.comment = "proofpoint's threat status"

                event.add_tag(threatInfo["classification"])

                # get campaignID from each TAP alert and query campaign API
                if threatInfo["campaignID"] is not None and threatInfo["campaignID"] != "":
                    urlCampaign = "https://tap-api-v2.proofpoint.com/v2/campaign/" + threatInfo["campaignID"]
                    responseCampaign = requests.request("GET", urlCampaign, auth=HTTPBasicAuth(proofpoint_sp, proofpoint_secret))

                    jsonDataCampaign = json.loads(responseCampaign.text)

                    campaignType = ("actors", "families", "malware", "techniques")

                    # loop through campaignType and grab tags to add to MISP event
                    for tagType in campaignType:
                        for tag in jsonDataCampaign[tagType]:
                            event.add_tag(tag['name'])

            # grab which policy route the message took
            for policy in messages["policyRoutes"]:
                policyRoute = event.add_attribute('comment', policy)
                policyRoute.comment = 'email policy route'

            # was the threat in the body of the email or is it an attachment?
            for parts in messages["messageParts"]:
                disposition = event.add_attribute('comment', parts["disposition"])
                disposition.comment = 'email body or attachment'

                # sha256 hash of threat
                if parts["sha256"] is not None and parts["sha256"] != "":
                    sha256 = event.add_attribute('sha256', parts["sha256"])
                    sha256.comment = 'sha256 hash'

                # md5 hash of threat
                if parts["md5"] is not None and parts["md5"] != "":
                    md5 = event.add_attribute('md5', parts["md5"])
                    md5.comment = 'md5 hash'

                # filename of threat
                if parts["filename"] is not None and parts["filename"] != "":
                    filename = event.add_attribute('filename', parts["filename"])
                    filename.comment = 'filename'

            misp.add_event(event.to_json())

        if alert == "clicksPermitted" or alert == "clicksBlocked":
            if alert == "clicksPermitted":
                print(alert + " is a permitted click")
                event.info = alert
                event.distribution = 0  # Optional, defaults to MISP.default_event_distribution in MISP config
                event.threat_level_id = 2  # setting this to 0 breaks the integration
                event.analysis = 0  # Optional, defaults to 0 (initial analysis)
            else:
                print(alert + " is a blocked click")
                event.info = alert
                event.distribution = 0  # Optional, defaults to MISP.default_event_distribution in MISP config
                event.threat_level_id = 2  # BLOCKED = LOW
                event.analysis = 0  # Optional, defaults to 0 (initial analysis)

            event.add_tag(messages["classification"])

            campaignId = event.add_attribute('campaign-id', messages["campaignId"][0])
            campaignId.comment = 'campaignId'

            clickIP = event.add_attribute('ip-src', messages["clickIP"])
            clickIP.comment = 'clickIP'

            clickTime = event.add_attribute('datetime', messages["clickTime"])
            clickTime.comment = 'clicked threat'

            threatTime = event.add_attribute('datetime', messages["threatTime"])
            threatTime.comment = 'identified threat'

            GUID = event.add_attribute('comment', messages["GUID"])
            GUID.comment = 'PPS message ID'

            recipient = event.add_attribute('email-dst', messages["recipient"][0])
            recipient.comment = 'recipient address'

            sender = event.add_attribute('email-src', messages["sender"])
            sender.comment = 'sender address'

            senderIP = event.add_attribute('ip-src', messages["senderIP"])
            senderIP.comment = 'sender IP'

            threatURL = event.add_attribute('link', messages["threatURL"])
            threatURL.comment = 'link to threat in TAP'

            url = event.add_attribute('link', messages["url"])
            url.comment = 'malicious url clicked'

            userAgent = event.add_attribute('user-agent', messages["userAgent"])

            misp.add_event(event.to_json())
