from securityheaders import Util
import six

class Parser(object):
    def __init__(self, directiveclass, directivekeyword = None):
        self.directiveclass = directiveclass
        self.directivekeyword = directivekeyword

    def parse(self, unparsed_string):
        result = {}
        if unparsed_string:
            separator = self.directiveclass.valueseperator()
            directiveTokens = unparsed_string.split(self.directiveclass.directiveseperator())
            for directiveToken in directiveTokens:
                directiveToken.strip();

                """ Split directive tokens into directive name and directive values. """
                if separator and separator in directiveToken:
                    directiveParts = directiveToken.split(separator)
                else:
                    directiveParts = directiveToken.split()
                if isinstance(directiveParts, list) and not isinstance(directiveParts, six.string_types) and len(directiveParts) > 0:
                    directiveName = directiveParts[0].lower().strip()
                    try:
                        directive = self.directiveclass(directiveName)
                    except ValueError:
                        directive = directiveName #koen: parser erorr, unknown directive; should be a finding
                    result[directive] = []
                    for directiveValue in directiveParts[1:]:
                        result[directive].append(self.normalizeDirectiveValue(directiveValue))
        return result;  

    def normalizeDirectiveValue(self, directiveValue):
        directiveValue = directiveValue.strip()
        directiveValueLower = directiveValue.lower()
        if self.directivekeyword:
            if self.directivekeyword.isKeyword(directiveValueLower):
                return self.directivekeyword[directiveValueLower]
            elif self.directivekeyword.isValue(directiveValueLower):
                return self.directivekeyword(directiveValueLower)
            elif  Util.isUrlScheme(directiveValue):
                return directiveValueLower 
        return directiveValue

class Header(object):

    def __init__(self, unparsedstring, directives ,keywords=None):
        """ Constructor for a header

        Args:
            unparsedstring (str): HEADER is created from the given string
        """
        self.parsedstring = Parser(directives, keywords).parse(unparsedstring)



    def __getitem__(self, index):
        """ returns the value of a given directive. If the directive does not exist, None is returned.

        Args:
            unparsedstring (str): HSTS is created from the given string
        """
        if self.parsedstring and index in self.parsedstring:
            return self.parsedstring[index]
        elif index not in self.parsedstring:
            raise KeyError(str(index) + " not part of the header")
        else:
            return None #only happens when self.parsedstring is none

    def keys(self):
        if self.parsedstring and hasattr(self.parsedstring, 'keys'):
            return list(self.parsedstring.keys())
        return []

    def directives(self):
        return self.keys()

    def getdirectives(self):
        return self.keys()    

    def hasdirectives(self):
        return self.parsedstring and not len(self.parsedstring) == 0
