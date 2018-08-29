import os
import glob
from securityheaders import Util


class Checker(object):

    def options(cls):
        result = cls.myoptions()
        for base in cls.__class__.__bases__:
            if hasattr(base, 'options'):
                opts = base.options(base())
                result.update(opts)
        return result

    def myoptions(cls):
        return {}

    def check(self, tocheck, opt_options=[]):
        pass

    def extractheader(self, headers, headerobject):
        if not headers:
            return None
        headerkey = headerobject.headerkey
        if headerkey in headers.keys():
            return headerobject(headers[headerkey])
        else:
            return None
