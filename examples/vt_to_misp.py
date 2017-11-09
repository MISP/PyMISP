''' Convert a VirusTotal report into MISP objects '''
import argparse
import json
import logging
from datetime import datetime
from urllib.parse import urlsplit

import pymisp
from pymisp.tools import VTReportObject

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(module)s.%(funcName)s.%(lineno)d | %(message)s")


def build_cli():
    '''
    Build the command-line arguments
    '''
    desc = "Take an indicator or list of indicators to search VT for and import the results into MISP"
    post_desc = """
config.json: Should be a JSON file containing MISP and VirusTotal credentials with the following format:
{"misp": {"url": "<url_to_misp>", "key": "<misp_api_key>"}, "virustotal": {"key": "<vt_api_key>"}}
Please note: Only public API features work in the VTReportObject for now. I don't have a quarter million to spare ;)

Example:
    python vt_to_misp.py -i 719c97a8cd8db282586c1416894dcaf8 -c ./config.json
    """
    parser = argparse.ArgumentParser(description=desc, epilog=post_desc, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-e", "--event", help="MISP event id to add to")
    parser.add_argument("-c", "--config", default="config.json", help="Path to JSON configuration file to read")
    indicators = parser.add_mutually_exclusive_group(required=True)
    indicators.add_argument("-i", "--indicator", help="Single indicator to look up")
    indicators.add_argument("-f", "--file", help="File of indicators to look up - one on each line")
    indicators.add_argument("-l", "--link", help="Link to a VirusTotal report")
    return parser.parse_args()


def build_config(path=None):
    '''
    Read a configuration file path. File is expected to be

    :path: Path to a configuration file
    '''
    try:
        with open(path, "r") as ifile:
            return json.load(ifile)
    except OSError:
        raise OSError("Couldn't find path to configuration file: %s", path)
    except json.JSONDecodeError:
        raise IOError("Couldn't parse configuration file. Please make sure it is a proper JSON document")


def generate_report(indicator, apikey):
    '''
    Build our VirusTotal report object, File object, and AV signature objects
    and link them appropriately

    :indicator: Indicator hash to search in VT for
    '''
    report_objects = []
    vt_report = VTReportObject(apikey, indicator)
    report_objects.append(vt_report)
    raw_report = vt_report._report
    if vt_report._resource_type == "file":
        file_object = pymisp.MISPObject(name="file")
        file_object.add_attribute("md5", value=raw_report["md5"])
        file_object.add_attribute("sha1", value=raw_report["sha1"])
        file_object.add_attribute("sha256", value=raw_report["sha256"])
        vt_report.add_reference(referenced_uuid=file_object.uuid, relationship_type="report of")
        report_objects.append(file_object)
    elif vt_report._resource_type == "url":
        parsed = urlsplit(indicator)
        url_object = pymisp.MISPObject(name="url")
        url_object.add_attribute("url", value=parsed.geturl())
        url_object.add_attribute("host", value=parsed.hostname)
        url_object.add_attribute("scheme", value=parsed.scheme)
        url_object.add_attribute("port", value=parsed.port)
        vt_report.add_reference(referenced_uuid=url_object.uuid, relationship_type="report of")
        report_objects.append(url_object)
    for antivirus in raw_report["scans"]:
        if raw_report["scans"][antivirus]["detected"]:
            av_object = pymisp.MISPObject(name="av-signature")
            av_object.add_attribute("software", value=antivirus)
            signature_name = raw_report["scans"][antivirus]["result"]
            av_object.add_attribute("signature", value=signature_name, disable_correlation=True)
            vt_report.add_reference(referenced_uuid=av_object.uuid, relationship_type="included-in")
            report_objects.append(av_object)
    return report_objects


def get_misp_event(event_id=None, info=None):
    '''
    Smaller helper function for generating a new MISP event or using a preexisting one

    :event_id: The event id of the MISP event to upload objects to

    :info: The event's title/info
    '''
    if event_id:
        event = misp.get_event(event_id)
    elif info:
        event = misp.new_event(info=info)
    else:
        event = misp.new_event(info="VirusTotal Report")
    misp_event = pymisp.MISPEvent()
    misp_event.load(event)
    return misp_event


def main(misp, config, args):
    '''
    Main program logic

    :misp: PyMISP API object for interfacing with MISP

    :config: Configuration dictionary

    :args: Argparse CLI object
    '''
    if args.indicator:
        misp_objects = generate_report(args.indicator, config["virustotal"]["key"])
        if misp_objects:
            misp_event = get_misp_event(args.event, "VirusTotal Report for {}".format(args.indicator))
            submit_to_misp(misp, misp_event, misp_objects)
    elif args.file:
        try:
            reports = []
            with open(args.file, "r") as ifile:
                for indicator in ifile:
                    try:
                        misp_objects = generate_report(indicator, config["virustotal"]["key"])
                        if misp_objects:
                            reports.append(misp_objects)
                    except pymisp.exceptions.InvalidMISPObject as err:
                        logging.error(err)
            if reports:
                current_time = datetime.now().strftime("%x %X")
                misp_event = get_misp_event(args.event, "VirusTotal Reports: {}".format(current_time))
                for report in reports:
                    submit_to_misp(misp, misp_event, report)
        except OSError:
            logging.error("Couldn't open indicators file at '%s'. Check path", args.file)
    elif args.link:
        # https://www.virustotal.com/#/file/<ioc>/detection
        indicator = args.link.split("/")[5]
        misp_objects = generate_report(indicator, config["virustotal"]["key"])
        if misp_objects:
            misp_event = get_misp_event(args.event, "VirusTotal Report for {}".format(indicator))
            submit_to_misp(misp, misp_event, misp_objects)


def submit_to_misp(misp, misp_event, misp_objects):
    '''
    Submit a list of MISP objects to a MISP event

    :misp: PyMISP API object for interfacing with MISP

    :misp_event: MISPEvent object

    :misp_objects: List of MISPObject objects. Must be a list
    '''
# go through round one and only add MISP objects
    for misp_object in misp_objects:
        template_id = misp.get_object_template_id(misp_object.template_uuid)
        misp.add_object(misp_event.id, template_id, misp_object)
    # go through round two and add all the object references for each object
    for misp_object in misp_objects:
        for reference in misp_object.ObjectReference:
            misp.add_object_reference(reference)


if __name__ == "__main__":
    try:
        args = build_cli()
        config = build_config(args.config)
        # change the 'ssl' value if you want to verify your MISP's SSL instance
        misp = pymisp.PyMISP(url=config["misp"]["url"], key=config["misp"]["key"], ssl=False)
        # finally, let's start checking VT and converting the reports
        main(misp, config, args)
    except KeyboardInterrupt:
        print("Bye Felicia")
    except pymisp.exceptions.InvalidMISPObject as err:
        logging.error(err)
