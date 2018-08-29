from securityheaders.checkers import CheckerFactory
from securityheaders import Util

class HeaderEvaluator(object):

    def __init__(self):
        self.factory = CheckerFactory()

    def evaluate(self,in_headers, opt_options=dict()): 
        findings = []
        headers = dict()
        for header in in_headers:
            if len(header) > 1:
                headers[header[0].lower()] = header[1]
            else:
                headers[header[0].lower()] = ''
        if 'checks' in opt_options:
            checks = opt_options['checks']
        else:
            checks = []
            raise Exception("No checks defined")
        for check in checks:
            checker = self.factory.getchecker(check)
            try:
                result = checker.check(headers, opt_options)
            except:
                result = []
            if not result:
                result = []
            findings = findings + result
        return findings
