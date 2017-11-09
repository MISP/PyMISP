import json
from pymisp import PyMISP
from pymisp.tools.abstractgenerator import AbstractMISPObjectGenerator
from keys import misp_url, misp_key, misp_verifycert
import argparse

class GenericObject(AbstractMISPObjectGenerator):
    def __init__(self, type, data_dict):
        super(GenericObject, self).__init__(type)
        self.__data = data_dict
        self.generate_attributes()

    def generate_attributes(self):
        for key, value in self.__data.items():
            self.add_attribute(key, value=value)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create a MISP Object selectable by type starting from a dictionary')
    parser.add_argument("-e", "--event", required=True, help="Event ID to update")
    parser.add_argument("-t", "--type", required=True, help="Type of the generic object")
    parser.add_argument("-d", "--dict", required=True, help="Dict ")
    args = parser.parse_args()

    pymisp = PyMISP(misp_url, misp_key, misp_verifycert)
    try:
        template_id = [x['ObjectTemplate']['id'] for x in pymisp.get_object_templates_list() if x['ObjectTemplate']['name'] == args.type][0]
    except IndexError:
        valid_types = ", ".join([x['ObjectTemplate']['name'] for x in pymisp.get_object_templates_list()])
        print ("Template for type %s not found! Valid types are: %s" % (args.type, valid_types))
        exit()

    misp_object = GenericObject(args.type.replace("|", "-"), json.loads(args.dict))
    r = pymisp.add_object(args.event, template_id, misp_object)
