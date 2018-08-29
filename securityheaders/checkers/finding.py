class Finding(object):
    def __init__(self, header, ftype, description, severity, opt_directive=None, opt_value=None, opt_url = None, opt_urlid=None):
        """ Constructor for a finding object.

        Args:
            header (str): the header for which this finding is valid
            ftype (FindingType): the type of finding
            description (str): the description of the finding
            severity (FindingSeverity): the severity of the finding
            opt_directive (Directive): if a header value has multiple keywords, then this is the keyword it was valid for
            opt_value (str): the insecure value   
        """

        self.header = header
        self.ftype = ftype
        self.description = description
        self.severity = severity
        self.directive = opt_directive
        self.value = opt_value
        self.url = opt_url
        self.urlid = opt_urlid

    def __eq__(self, other):
        if not other:
            return False

        if not isinstance(other, self.__class__):
            return False

        return self.header == other.header and self.ftype == other.ftype and self.description == other.description and self.severity == other.severity and self.directive == other.directive and self.value == other.value


    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        """ Returns a string representation of this finding  
        """
        return str(self.header) +"\t" + str(self.ftype) +"\t" + str(self.description) +"\t" + str(self.directive) + "\t" + str(self.value)

    def __repr__(self):
        return self.__str__()
