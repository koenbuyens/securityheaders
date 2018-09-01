import securityheaders
from securityheaders import Util
from securityheaders.checkers import *
from securityheaders.singleton import Singleton
from anytree import Node, RenderTree, AsciiStyle
import anytree

import warnings
import pkgutil
import inspect

class CheckerFactory(Singleton):
    def __init__(self):
        self.clazzes = dict()
        path = securityheaders.checkers.__path__[0]
        root = Node("Checker")
        for loader, module_name, is_pkg in  pkgutil.walk_packages(securityheaders.checkers.__path__):
            module = loader.find_module(module_name).load_module(module_name)
            for name, obj in inspect.getmembers(module):
                if hasattr(obj, "__name__") and obj.__name__ not in self.clazzes.keys() and inspect.isclass(obj) and issubclass(obj, Checker):
                    self.clazzes[obj.__name__] = obj
        self.tree = self.__getnames_as_tree__(self.clazzes)
        
    def getchecker(self,checkername):
        if checkername in self.clazzes.keys():
            return self.clazzes[checkername]()
        return None

    def getleafcheckers(self, checkerstr):
        checkerstrs = anytree.findall_by_attr(self.tree, name="name", value=checkerstr.strip())
        if not checkerstr:
            return []
        checker = checkerstrs[0]
        if checker.is_leaf:
            return [checker.name] 
        descendants = checker.descendants
        result = []
        for check in descendants:
            if check.is_leaf:
                result.append(check.name)
        return result

    def getnames(self):
        return sorted(set(self.clazzes.keys()))

    def getactualcheckers(self, checkers):
        result = set()
        for checker in checkers:
            result = result.union(self.getleafcheckers(checker))
        return list(result)

    def getnames_as_tree(self):
        return self.tree

    def __getnames_as_tree__(self, clazzes):
        root = Node("Checker")
        resultnodes = dict()
        worklist = list()
        clazz = clazzes['Checker']
        setattr(root,"clazz", clazz)
        worklist.append(root)
        while len(worklist) > 0:
            parent = worklist.pop()
            subclasses = [sub for sub in parent.clazz.__subclasses__()   if parent.clazz in sub.__bases__]
            subclasses = [sub for sub in subclasses if sub in clazzes.values()]
            for child in subclasses:
                childpath = "/".join([f.name for f in parent.path]) + "/" + child.__name__
                found = False
                for c in parent.children:
                    if childpath == "/".join([f.name for f in c.path]):
                        found = True
                if not found:
                    childnode = Node(child.__name__, parent)
                    setattr(childnode,"clazz", child)
                    worklist.append(childnode)
                
        return root
                          
                
