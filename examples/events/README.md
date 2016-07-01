## Explanation

This folder contains scripts made to create dummy events in order to test MISP instances.

* dummy is a containing text only file used as uploaded attachement.
* create\_dummy\_event.py will create a given number of events (default: 1)with a randomly generated domain|ip attribute as well as a copy of dummy file.
* create\_massive\_dummy\_events.py will create a given number of events (default: 1) with a given number of randomly generated attributes(default: 3000).

### Tools description

* randomStringGenerator: generate a random string of a given size, characters used to build the string can be chosen, default are characters from string.ascii\_lowercase and string.digits
* randomIpGenerator: generate a random ip

* floodtxt: add a generated string as attribute of the given event. The added attributes can be of the following category/type:
    - Internal reference/comment
    - Internal reference/text
    - Internal reference/other
    - Payload delivery/email-subject
    - Artifact dropped/mutex
    - Artifact dropped/filename
* floodip: add a generated ip as attribute of the given event. The added attributes can be of the following category/type:
    - Network activity/ip-src
    - Network activity/ip.dst
* flooddomain: add a generated domain-like string as attribute of the given event. The added attributes can be of the following category/type:
    - Network activity/hostname
    - Network activity/domain
* flooddomainip: add a generated domain|ip-like string as attribute of the given event. The added attribute is of the following category/type:
    - Network activity/domain|ip
* floodemail: add a generated email-like string as attribute of the given event. The added attributes can be of the following category/type:
    - Payload delivery/email-src
    - Payload delivery/email-dst
* floodattachmentent: add a dummy file as attribute of the given event. The added attribute is of the following category/type:
    - Payload delivery/attachment

* create\_dummy\_event: create a dummy event named "dummy event" with these caracteristics:
    - Distribution: Your organisation only
    - Analysis: Initial
    - Threat Level: Undefined
    - Number of Attributes: 2
    - Attribute:
        - category/type: Network activity/domain|ip
        - value: Randomly generated
    - Attribute:
        -category/type: Payload delivery/attachment
        - value: 'dummy' file
* create\_massive\_dummy\_events: create a dummy event named "massive dummy event" with these caracteristics:
    - Distribution: Your organisation only
    - Analysis: Initial
    - Threat Level: Undefined
    - Number of Attributes: Given as argument
    - Attribute:
        - category/type: Randomly chosen
        - value: Randomly generated or dummy file
