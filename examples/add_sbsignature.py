import json
from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
from pymisp.tools import SBSignatureObject

pymisp = PyMISP(misp_url, misp_key, misp_verifycert)
a = json.loads('{"signatures":[{"new_data":[],"confidence":100,"families":[],"severity":1,"weight":0,"description":"AttemptstoconnecttoadeadIP:Port(2uniquetimes)","alert":false,"references":[],"data":[{"IP":"95.101.39.58:80(Europe)"},{"IP":"192.35.177.64:80(UnitedStates)"}],"name":"dead_connect"},{"new_data":[],"confidence":30,"families":[],"severity":2,"weight":1,"description":"PerformssomeHTTPrequests","alert":false,"references":[],"data":[{"url":"http://cert.int-x3.letsencrypt.org/"},{"url":"http://apps.identrust.com/roots/dstrootcax3.p7c"}],"name":"network_http"},{"new_data":[],"confidence":100,"families":[],"severity":2,"weight":1,"description":"Theofficefilehasaunconventionalcodepage:ANSICyrillic;Cyrillic(Windows)","alert":false,"references":[],"data":[],"name":"office_code_page"}]}')
a = [(x['name'], x['description']) for x in a["signatures"]]


b = SBSignatureObject(a)


template_id = [x['ObjectTemplate']['id'] for x in pymisp.get_object_templates_list() if x['ObjectTemplate']['name'] == 'sb-signature'][0]

pymisp.add_object(234111, template_id, b)
