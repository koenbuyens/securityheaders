from securityheaders.checkers import InfoCollector, FindingType, Finding, FindingSeverity

class InfoHeaderCollector(InfoCollector):

    def check(self, headers, opt_options=dict()):
       if not headers:
           return []
       findings = []
       for header in headers.keys():
           findings.append(Finding(header, FindingType.INFO_HEADER, headers[header],FindingSeverity.NONE, None, None))
       return findings
