import securityheaders
from securityheaders import Util
from securityheaders.models import Header, Directive, Keyword
from securityheaders.singleton import Singleton

import warnings

class ModelFactory(Singleton):
    def __init__(self):
        self.clazzes = dict()
        self.headers = dict()

    def getmodel(self,modelname):
        if(len(self.clazzes.keys()) == 0):
            self.populate()
        if modelname in self.clazzes.keys():
            return self.clazzes[modelname]()
        return None
    
    def getheadernames(self):
        if(len(self.clazzes.keys()) == 0):
            self.populate()
        return set(self.headers.keys())
            
    def getheader(self, name):
        if(len(self.headers.keys()) == 0):
            self.populate()
        if name in self.headers.keys():
            return self.headers[name]
        return None

    def getnames(self):
        if(len(self.clazzes.keys()) == 0):
            self.populate()
        return self.clazzes.keys()


    def populate(self):
#        path = securityheaders.models.__path__[0]
#        with warnings.catch_warnings():
#            warnings.simplefilter("ignore")
#            Util.load_all_modules_from_dir(path)
        clazzes = list(Util.inheritors(Header))
        clazzes.extend(Util.inheritors(Directive))
        clazzes.extend(Util.inheritors(Keyword))
        for header in list(Util.inheritors(Header)):
            if hasattr(header,'headerkey'):
                self.headers[header.headerkey] = header
    
        all_my_base_classes = {cls: cls for cls in clazzes}
        for clazz in all_my_base_classes:
            self.clazzes[clazz.__name__] = clazz
                
