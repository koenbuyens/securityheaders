import securityheaders
from securityheaders import Util
from securityheaders.checkers import FindingSeverity, Finding
from securityheaders.singleton import Singleton
from tabulate import tabulate
import base64 as base64
import warnings
import io
import csv
import json

Red = '\033[91m'
Green = '\033[92m'
White = '\033[97m'
Yellow = '\033[93m'
Grey = '\033[90m'
Black = '\033[90m'
Default = '\033[99m'
endColor = '\033[0m'


class FindingJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Finding):
            return {
                "_type": "finding",
                "url": str(obj.url) if obj.url else "",
                "severity": str(obj.severity) if obj.severity else "",
                "header": str(obj.header) if obj.header else "",
                "ftype": str(obj.ftype) if obj.ftype else "",
                "directive": str(obj.directive) if obj.directive else "",
                "value": str(obj.value) if obj.value else "",
                "description": str(obj.description) if obj.description else ""
    
        }
        return super(FindingJSONEncoder, self).default(obj)

class FindingFormatter(object):
    def format(self, findings):
        pass

    @classmethod
    def can_format(cls, name):
        pass

    @classmethod
    def get_formats(cls):
        pass

class FindingFormatterTabulated(FindingFormatter):
    
    formats = ["plain","simple","grid","fancy_grid","pipe","orgtbl","jira","presto","psql","rst","mediawiki","moinmoin","youtrack","html","latex","latex_raw","latex_booktabs","textile","markdown","console"]
    
    @classmethod
    def can_format(cls, name):
        return name in FindingFormatterTabulated.formats

    @classmethod
    def get_formats(cls):
        return FindingFormatterTabulated.formats
    
    def __init__(self, tableformat="simple"):
        self.hascolor = False
        if tableformat == "markdown":
            tableformat = "pipe"
        if tableformat == "console":
            tableformat = "simple"
            self.hascolor = True
        self.tableformat = tableformat
    
    def format(self, findings):
        table = []
        for finding in findings:
            url = str(finding.url) if finding.url else ''
            severity = str(finding.severity.name) if finding.severity.name else ''
            header = str(finding.header) if finding.header else ""
            ftype = str(finding.ftype.name.lower()) if finding.ftype.name else ""
            directive = str(finding.directive) if finding.directive else ""
            value = str(finding.value) if finding.value else ""
            description = str(finding.description) if finding.description else ""
            f = finding
            if self.hascolor:
                color = self.getColor(finding.severity)
                endColor = '\033[0m'
            else:
                color = ''
                endColor = ''
            table.append([url, color + severity + endColor +"", header, ftype, directive, value, description])
        return str(tabulate(table, headers=["URL","Severity", "Header", "Finding Type", "Directive", "Value","Description"],tablefmt=self.tableformat))

    def getColor(self, severity):
        if severity == FindingSeverity.MEDIUM or severity == FindingSeverity.MEDIUM_MAYBE:
            color = Yellow
        elif severity == FindingSeverity.HIGH or severity == FindingSeverity.HIGH_MAYBE:
            color = Red
        elif severity == FindingSeverity.LOW:
            color = Green
        elif severity == FindingSeverity.SYNTAX or severity == FindingSeverity.STRICT_CSP or severity == FindingSeverity.INFO:
            color = Grey
        else:
            color = Default
        return color

class FindingFormatterCSV(FindingFormatter):
    
    formats = ['csv']
    
    def __init__(self, format='csv'):
        pass
    
    @classmethod
    def can_format(cls, name):
        return name.lower() in FindingFormatterCSV.formats
    
    @classmethod
    def get_formats(cls):
        return FindingFormatterCSV.formats
    
    def format(self, findings):
        f =  io.BytesIO()
        writer = csv.writer(f)
        writer.writerow(["URL","SEVERITY","HEADER","FINDINGTYPE","DIRECTIVE","DIRECTIVEVALUE","DESCRIPTION"])

        for finding in findings:
            url = str(finding.url) if finding.url else ''
            severity = str(finding.severity.name) if finding.severity.name else ''
            header = str(finding.header) if finding.header else ""
            ftype = str(finding.ftype.name.lower()) if finding.ftype.name else ""
            directive = str(finding.directive) if finding.directive else ""
            value = str(finding.value) if finding.value else ""
            msg = [url, severity ,header, ftype ,directive, value, str(base64.b64encode(finding.description))]
            writer.writerow(msg)
        return f.getvalue()

class FindingFormatterJSON(FindingFormatter):
    
    formats = ['json']
    
    def __init__(self, format='json'):
        pass
    
    @classmethod
    def can_format(cls, name):
        return name.lower() in FindingFormatterJSON.formats
    
    @classmethod
    def get_formats(cls):
        return FindingFormatterJSON.formats
    
    def format(self, findings):
        return json.dumps(findings,cls=FindingJSONEncoder,indent=4, separators=(',', ': '))

class FindingFormatterFactory(Singleton):
    def __init__(self):
        self.clazzes = dict()

    def getformatter(self,formattername):
        if(len(self.clazzes.keys()) == 0):
            self.populate()
        for clazz in self.clazzes.keys():
            if self.clazzes[clazz].can_format(formattername):
                return self.clazzes[clazz](formattername)
        return None

    def getnames(self):
        if(len(self.clazzes.keys()) == 0):
            self.populate()
        result = list()
        for clazz in self.clazzes.keys():
            result.extend(self.clazzes[clazz].get_formats())
        return sorted(set(result))

    def getshortnames(self):
        return self.getnames()

    def populate(self):
        #path = securityheaders.formatters.__path__[0]
        #with warnings.catch_warnings():
        #    warnings.simplefilter("ignore")
        #    Util.load_all_modules_from_dir(path)
        clazzes = list(Util.inheritors(FindingFormatter))
        all_my_base_classes = {cls: cls for cls in clazzes}
        for clazz in all_my_base_classes:
            self.clazzes[clazz.__name__] = clazz
                


