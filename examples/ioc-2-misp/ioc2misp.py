#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Format description
# @variables : camelCase
# @functions : snake_case

from keys import mispUrl, mispKey, csvTaxonomyFile, iocMispMapping

try:
        from pymisp import PyMISP
except:
        print("you need pymisp form github")
        import sys
        sys.exit(1)

import os
import argparse

try:
        from bs4 import BeautifulSoup
except:
        print("install BeautifulSoup : sudo apt-get install python-bs4 python-lxml")
        import sys
        sys.exit(1)


def misp_init(url, key):
        return PyMISP(url, key, False, 'json')


def check_valid_ioc():

        (filepath, filename) = os.path.split(iocDescriptions["iocfile"])
        (shortname, extension) = os.path.splitext(filename)

        if (("ioc" in extension)) and (sum(1 for _ in open(iocDescriptions["iocfile"])) > 1):
                iocDescriptions['filename'] = filename
                return True
        return False


def get_parse_ioc_file():
        return BeautifulSoup(open(iocDescriptions["iocfile"]), "lxml")


def parse_ioc_search_content(iocContextSearch):
        for k, v in iocMispMapping.items():
                if str(k).lower() == str(iocContextSearch).lower():
                        return v
        return False


def create_attribute_json(iocContextSearch, attributeValue, attributeComment, force=False):
        #####################################
        # force used for description to upload
        if force:
                parseResult = ("Other", "comment")
        else:
                parseResult = parse_ioc_search_content(iocContextSearch)

        if parseResult is False:

                print("/!\ Not implemented :: {0} :: {1} :: Item add as 'Other','Comment'. Add it in your keys.py".format(iocContextSearch, attributeValue))
                ########################################
                # force import to misp
                parseResult = ("Other", "comment")

        comment = ""
        try:
                comment = parseResult[2] + attributeComment
        except:
                comment = attributeComment

        attribute = {"category": parseResult[0],
                     "type": parseResult[1],
                     "value": attributeValue,
                     "timestamp": "0",
                     "to_ids": "0",
                     "distribution": "0",
                     "comment": comment
                     }
        return attribute


def create_attributes_from_ioc_json(soup):
        attributes = []

        IndicatorItemValues = {}
        for item in soup.find_all("indicatoritem"):

                if item.find('context'):
                        IndicatorItemValues["context"] = str(item.find('context')['search'])
                else:
                        IndicatorItemValues["context"] = ""
                if item.find('content'):
                        IndicatorItemValues["content"] = str(item.find('content').text)
                else:
                        IndicatorItemValues["content"] = ""
                if item.find('comment'):
                        IndicatorItemValues["comment"] = str(item.find('comment').text)
                else:
                        IndicatorItemValues["comment"] = ""

                jsonAttribute = create_attribute_json(IndicatorItemValues["context"], IndicatorItemValues["content"], IndicatorItemValues["comment"])
                attributes.append(jsonAttribute)

        return attributes


def create_misp_event_json(attributes):
        import time
        if iocDescriptions["authored_by"]:
                attributes.append(create_attribute_json(None, "authored_by", iocDescriptions["authored_by"], True))
        if iocDescriptions["authored_date"]:
                attributes.append(create_attribute_json(None, "authored_date", iocDescriptions["authored_date"], True))

        ##################################################
        # make short-description in "info field
        # if not exist make description
        # if "info"="short-description" make descrption as comment
        mispInfoFild = ""
        if iocDescriptions["short_description"]:
                mispInfoFild = iocDescriptions["short_description"]
                if iocDescriptions["description"]:
                        attributes.append(create_attribute_json(None, "description", iocDescriptions["description"], True))
        else:
                if iocDescriptions["description"]:
                        mispInfoFild = iocDescriptions["description"]
                else:
                        mispInfoFild = "No description or short_description from IOC find."

        eventJson = {"Event": {"info": mispInfoFild,
                               "timestamp": "1",
                               "attribute_count": 0,
                               "analysis": "0",
                               "date": time.strftime("%Y-%m-%d"),
                               "org": "",
                               "distribution": "0",
                               "Attribute": [],
                               "proposal_email_lock": False,
                               "threat_level_id": "4",
                               }}

        eventJson["Event"]["Attribute"] = attributes

        return eventJson


def get_descriptions(soup, description):
        if soup.find(description.lower()):
                return soup.find(description.lower()).text
        return ""


def save_ioc_description(soup):
        list_description = ["short_description", "authored_by", "authored_date", "description"]

        for description in list_description:
                iocDescriptions[description] = get_descriptions(soup, description)

        return


def get_taxonomy(soup):
        import csv
        taxonomy = []
        reader = csv.reader(open(csvTaxonomyFile, 'rb'), delimiter=';')
        #####################################
        # save file in a dict
        #       r[0] = @link from csv
        #       r[1] = @value from csv
        #               = value
        #       r[2] = @keep
        #               0 : don't creat tag
        #               1 : tag created
        #       r[3] = @taxonomy

        csvdic = {i: r for i, r in enumerate(reader)}

        #########################################
        # find all link with soup
        for n in soup.find_all('link', rel=True):
                rel = str(n.attrs['rel'][0]).lower()

                ##########################
                # build special taxo
                # special string because link if a html value
                relValue = str(n.next_sibling).strip()
                if rel == 'family':
                        if len(relValue) > 0:
                                taxonomy.append("malware_classification:malware-family='" + relValue + "'")
                elif rel == 'threatgroup':
                        if len(relValue) > 0:
                                taxonomy.append("malware_classification:malware-threatgroup='" + relValue + "'")

                #########################
                # build taxo from csv match
                else:
                        taxo = [r[3] for r in {i: r for i, r in csvdic.items() if r[0].lower() == rel and str(r[2]) == "1"}.values() if r[1].lower() == relValue.lower() and str(r[2]) == "1"]

                        # taxo find in correspondance file
                        if (len(taxo) > 0 and taxo[0] != ''):
                                taxonomy.append(taxo[0])
                        # not find
        return taxonomy


def custum_color_tag(tagg):
        color = "#00ace6"
        if ":amber" in tagg:
            color = "#ffc200"
        if ":green:" in tagg:
            color = "#009933"
        if "tlp:green" in tagg:
            color = "#009933"
        if ":red:" in tagg:
            color = "#ff0000"
        if "tlp:red" in tagg:
            color = "#ff0000"
        if "tlp:white" in tagg:
            color = "#fafafa"
        return color


def push_event_to_misp(jsonEvent):
        global misp

        ####################
        # upload json event
        event = misp.add_event(jsonEvent)

        # save event id for file upload and tagg
        iocDescriptions["misp_event_id"] = event["Event"]["id"]

        return


def upload_file():

        # filename,path, eid, distrib, ids, categ, info, ids, analysis, threat
        misp.upload_sample(iocDescriptions['filename'],
                           iocDescriptions["iocfile"],
                           iocDescriptions["misp_event_id"],
                           "0",
                           False,
                           "External analysis",
                           iocDescriptions["short_description"],
                           None,
                           "1",
                           "4",
                           )
        return


def update_tag(listOfTagg):
        for tagg in listOfTagg:
                color = custum_color_tag(tagg)

                #############################
                # creatz tag in MISP

                misp.new_tag(str(tagg), str(color))
                #############################
                # link tag to MISP event
                toPost = {}
                toPost['Event'] = {'id': iocDescriptions["misp_event_id"]}
                misp.add_tag(toPost, str(tagg))
        return


def main():
        global misp
        global iocDescriptions
        iocDescriptions = {}

        ################################
        # parse for valid argments
        parser = argparse.ArgumentParser(description='Get an event from a MISP instance.')
        parser.add_argument("-i", "--input", required=True, help="Input file")
        parser.add_argument("-t", "--tag", help="Add custom tags 'tlp:red,cossi:tmp=test'")
        args = parser.parse_args()

        iocDescriptions["iocfile"] = os.path.abspath(args.input)

        ################################
        # check if file have ioc extention and if he is not empty
        if check_valid_ioc():

                ################################
                # Try to parse file
                iocfileparse = get_parse_ioc_file()
        else:
                print("/!\ Bad format {0}".format(iocDescriptions["iocfile"]))
                return

        ################################
        # save description for create event
        save_ioc_description(iocfileparse)

        ################################
        # parse ioc and buid json attributes
        jsonAttributes = create_attributes_from_ioc_json(iocfileparse)

        ################################
        # create a json misp event and append attributes
        jsonEvent = create_misp_event_json(jsonAttributes)

        ################################
        # try connection
        try:
                misp = misp_init(mispUrl, mispKey)
        except:
                print("/!\ Connection fail, bad url ({0}) or API key : {1}".format(mispUrl, mispKey))
                return

        ################################
        # Add event to MSIP
        push_event_to_misp(jsonEvent)

        ################################
        # Upload the IOC file and close tmpfile
        upload_file()

        ################################
        # Update MISP Event with tag from IOC
        update_tag(get_taxonomy(iocfileparse))

        ################################
        # Add custom Tag (-t)
        if args.tag:
                customTag = args.tag
                update_tag(customTag.split(","))


if __name__ == '__main__':
        main()
