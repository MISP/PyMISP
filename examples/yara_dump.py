#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
YARA dumper for MISP
    by Christophe Vandeplas
'''

import keys
from pymisp import PyMISP
import yara
import re


def dirty_cleanup(value):
    changed = False
    substitutions = (('”', '"'),
                     ('“', '"'),
                     ('″', '"'),
                     ('`', "'"),
                     ('\r', ''),
                     ('Rule ', 'rule ')  # some people write this with the wrong case
                     # ('$ ', '$'),    # this breaks rules
                     # ('\t\t', '\n'), # this breaks rules
                     )
    for substitution in substitutions:
        if substitution[0] in value:
            changed = True
            value = value.replace(substitution[0], substitution[1])
    return value, changed


misp = PyMISP(keys.misp_url, keys.misp_key, keys.misp_verify, 'json')
result = misp.search(controller='attributes', type_attribute='yara')

attr_cnt = 0
attr_cnt_invalid = 0
attr_cnt_duplicate = 0
attr_cnt_changed = 0
yara_rules = []
yara_rule_names = []
if 'response' in result and 'Attribute' in result['response']:
    for attribute in result['response']['Attribute']:
        value = attribute['value']
        event_id = attribute['event_id']
        attribute_id = attribute['id']

        value = re.sub('^[ \t]*rule ', 'rule misp_e{}_'.format(event_id), value, flags=re.MULTILINE)
        value, changed = dirty_cleanup(value)
        if changed:
            attr_cnt_changed += 1
        if 'global rule' in value:  # refuse any global rules as they might disable everything
            continue
        if 'private rule' in value:  # private rules need some more rewriting
            priv_rules = re.findall('private rule (\w+)', value, flags=re.MULTILINE)
            for priv_rule in priv_rules:
                value = re.sub(priv_rule, 'misp_e{}_{}'.format(event_id, priv_rule), value, flags=re.MULTILINE)

        # compile the yara rule to confirm it's validity
        # if valid, ignore duplicate rules
        try:
            attr_cnt += 1
            yara.compile(source=value)
            yara_rules.append(value)
            # print("Rule e{} a{} OK".format(event_id, attribute_id))
        except yara.SyntaxError as e:
            attr_cnt_invalid += 1
            # print("Rule e{} a{} NOK - {}".format(event_id, attribute_id, e))
        except yara.Error as e:
            attr_cnt_invalid += 1
            print(e)
            import traceback
            print(traceback.format_exc())

# remove duplicates - process the full yara rule list and process errors to eliminate duplicate rule names
all_yara_rules = '\n'.join(yara_rules)
while True:
    try:
        yara.compile(source=all_yara_rules)
    except yara.SyntaxError as e:
        if 'duplicated identifier' in e.args[0]:
            duplicate_rule_names = re.findall('duplicated identifier "(.*)"', e.args[0])
            for item in duplicate_rule_names:
                all_yara_rules = all_yara_rules.replace('rule {}'.format(item), 'rule duplicate_{}'.format(item), 1)
                attr_cnt_duplicate += 1
            continue
        else:
            # This should never happen as all rules were processed before separately. So logically we should only have duplicates.
            exit("ERROR SyntaxError in rules: {}".format(e.args))
    break

# save to a file
fname = 'misp.yara'
with open(fname, 'w') as f_out:
    f_out.write(all_yara_rules)

print("")
print("MISP attributes with YARA rules: total={} valid={} invalid={} duplicate={} changed={}.".format(attr_cnt, attr_cnt - attr_cnt_invalid, attr_cnt_invalid, attr_cnt_duplicate, attr_cnt_changed))
print("Valid YARA rule file save to file '{}'. Invalid rules/attributes were ignored.".format(fname))
