from securityheaders.models.cors import CORSDirective

class AccessControlAllowMethodsDirective(CORSDirective):
    GET = 'get'
    HEAD = 'head'
    POST = 'post'
    PUT = 'put'
    DELETE = 'delete'
    CONNECT = 'connect'
    OPTIONS = 'options'
    TRACE = 'trace'
    PATCH = 'patch'

    @classmethod
    def isDirective(cls, directive):

        """ Checks whether a given string is a directive

        Args:
            directive (str): the string to validate
        """
        if isinstance(directive, AccessControlAllowMethodsDirective):
            result = True
        else:
            result= any(directive.lower() == item.value.lower() for item in list(cls))
        return result
