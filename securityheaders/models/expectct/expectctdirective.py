from securityheaders.models import Directive
from securityheaders.models.annotations import requireddirectives, requireddirectivevalues

@requireddirectives('max-age')
@requireddirectivevalues('max-age','report-uri')
class ExpectCTDirective(Directive):
    REPORT_URI = 'report-uri'
    ENFORCE = 'enforce'
    MAX_AGE = 'max-age'


    @classmethod
    def isDirective(cls, directive):
        if isinstance(directive, ExpectCTDirective):
            return True
        return any(directive.lower() == item.value.lower() for item in list(cls))


    @classmethod
    def directiveseperator(cls):
        return ','
    
    @classmethod
    def valueseperator(cls):
        return '='
    
    @classmethod
    def directivevalueseperator(cls):
        return '='
