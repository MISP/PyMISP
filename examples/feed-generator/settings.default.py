# Your MISP's URL
url = ''

# The auth key to the MISP user that you wish to use. Make sure that the
# user has auth_key access
key = ''

# Should the certificate be validated?
ssl = False

# The output dir for the feed. This will drop a lot of files, so make
# sure that you use a directory dedicated to the feed
outputdir = 'output'

# The filters to be used for by the feed. You can use any filter that
# you can use on the event index, such as organisation, tags, etc.
# It uses the same joining and condition rules as the API parameters
# For example:
# filters = {'tags':['tlp:white','feed-export','!privint'],'org':'CIRCL', 'published':1}
# the above would generate a feed for all published events created by CIRCL,
# tagged tlp:white and/or feed-export but exclude anything tagged privint
filters = {'published':'true'}

# Include deleted attributes and objects in the events
include_deleted = False

# By default all attributes will be included in the feed generation
# Remove the levels that you do not wish to include in the feed
# Use this to further narrow down what gets exported, for example:
# Setting this to ['3', '5'] will exclude any attributes from the feed that
# are not exportable to all or inherit the event
#
# The levels are as follows:
# 0: Your Organisation Only
# 1: This Community Only
# 2: Connected Communities
# 3: All
# 4: Sharing Group
# 5: Inherit Event
valid_attribute_distribution_levels = ['0', '1', '2', '3', '4', '5']

# By default, all attribute passing the filtering rules will be exported.
# This setting can be used to filter out any attributes being of the type contained in the list. 
# Warning: Keep in mind that if you propagate data (via synchronisation/feeds/...), recipients
# will not be able to get these attributes back unless their events get updated.
# For example:
# exclude_attribute_types = ['malware-sample']
exclude_attribute_types = []

# Include the distribution and sharing group information (and names/UUIDs of organisations in those Sharing Groups)
# Set this to False if you want to discard the distribution metadata. That way all data will inherit the distribution
# the feed
with_distribution = False

# Include the exportable local tags along with the global tags.  The default is True.
with_local_tags = True
