import os.path
import re
import copy

from securityheaders.models import SecurityHeader
from securityheaders.models.csp import CSPDirective, CSPKeyword, CSPVersion, CSP
from securityheaders.models.annotations import description, headername

@description('This header tests the CSP header. The CSP header protects against XSS attacks. By whitelisting sources of approved content, the browser does not load malicious assets.')
@headername('content-security-policy-report-only')
class CSPReportOnly(CSP):
    directive = CSPDirective
    keyword = CSPKeyword
    

    def __init__(self, unparsedstring):
       self.__class__.required = False
       SecurityHeader.__init__(self, unparsedstring, CSPDirective, CSPKeyword)
