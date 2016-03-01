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
# filters = {'tag':'tlp:white|feed-export|!privint','org':'CIRCL'}
# the above would generate a feed for all events created by CIRCL, tagged
# tlp:white and/or feed-export but exclude anything tagged privint
filters = {}

