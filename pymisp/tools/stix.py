# -*- coding: utf-8 -*-

try:
    from misp_stix_converter.converters.buildMISPAttribute import buildEvent
    from misp_stix_converter.converters import convert
    from misp_stix_converter.converters.convert import MISPtoSTIX
    has_misp_stix_converter = True
except ImportError:
    has_misp_stix_converter = False


def load_stix(stix, distribution=3, threat_level_id=2, analysis=0):
    '''Returns a MISPEvent object from a STIX package'''
    if not has_misp_stix_converter:
        raise Exception('You need to install misp_stix_converter: pip install git+https://github.com/MISP/MISP-STIX-Converter.git')
    stix = convert.load_stix(stix)
    return buildEvent(stix, distribution=distribution,
                      threat_level_id=threat_level_id, analysis=analysis)


def make_stix_package(misp_event, to_json=False, to_xml=False):
    '''Returns a STIXPackage from a MISPEvent.

       Optionally can return the package in json or xml.

    '''
    if not has_misp_stix_converter:
        raise Exception('You need to install misp_stix_converter: pip install git+https://github.com/MISP/MISP-STIX-Converter.git')
    package = MISPtoSTIX(misp_event)
    if to_json:
        return package.to_json()
    elif to_xml:
        return package.to_xml()
    else:
        return package
