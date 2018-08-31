#Collects all used URLs in a policy
from securityheaders.checkers import InfoCollector, Finding, FindingType, FindingSeverity
from securityheaders.models import ModelFactory

class InfoURLCollector(InfoCollector):
    def check(self, headers, opt_options=dict()):
        findings = []
        
        headernames = ModelFactory().getheadernames()
        for header in headernames:
            hdr = ModelFactory().getheader(header)
            try:
                obj = self.extractheader(headers, hdr)
            
                if obj and obj.parsedstring:
                    if hasattr(obj, 'getdirectives') and hasattr(obj,'geturls'):
                        for directive in obj.getdirectives():
                            urls = obj.geturls([directive]) 
                            if not urls:
                                urls = []
                            for url in urls:
                                findings.append(Finding(obj.headerkey, FindingType.INFO_URL, str(url), FindingSeverity.NONE, directive, str(url) ))
            except:
                pass
            
        return findings
