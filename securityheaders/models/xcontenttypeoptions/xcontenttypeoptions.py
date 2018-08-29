from securityheaders.models import SecurityHeader
from securityheaders.models.xcontenttypeoptions import XContentTypeOptionsDirective
from securityheaders.models.annotations import *

@requiredheader
@description('This header stops a browser from trying to MIME-sniff the content type and forces it to stick with the declared content-type. The only valid value for this header is "X-Content-Type-Options: nosniff".')
@headername('x-content-type-options')
@headerref('http://blogs.msdn.com/b/ie/archive/2008/09/02/ie8-security-part-vi-beta-2-update.aspx')
class XContentTypeOptions(SecurityHeader):
    directive = XContentTypeOptionsDirective

    def __init__(self, unparsedstring):
       SecurityHeader.__init__(self, unparsedstring, XContentTypeOptionsDirective)

    def nosniff(self):
        try:
            return XContentTypeOptionsDirective.NOSNIFF in self.parsedstring
        except error:
            return False 
