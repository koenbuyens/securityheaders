from .checker import Checker
from .checkerfactory import CheckerFactory
from .syntaxchecker import SyntaxChecker
from .infocollector import InfoCollector
from .finding import Finding
from .findingseverity import FindingSeverity
from .findingtype import FindingType
from .headeremptychecker import HeaderEmptyChecker
from .headerevaluator import HeaderEvaluator
from .headerpresentchecker import HeaderPresentChecker
from .infodirectivecollector import InfoDirectiveCollector
from .infoheadercollector import InfoHeaderCollector
from .missingseparatorchecker import MissingSeparatorChecker
from .headerdeprecatedchecker import HeaderDeprecatedChecker
from .infodisclosure import InfoDisclosureChecker
from .infourlcollector import InfoURLCollector
from .headermissingchecker import HeaderMissingChecker
from .directivemissingchecker import MissingDirectiveChecker
from .directiveemptychecker import EmptyDirectiveChecker

from .unknowndirectivechecker import UnknownDirectiveChecker

from .cors.allowcredentials import *
from .cors.alloworigin import *
from .cors.maxage import *
from .cors.exposeheaders import *
from .csp import *
from .featurepolicy import *
from .hsts import *
from .referrerpolicy import *
from .server import *
from .xcontenttypeoptions import *
from .xframeoptions import *
from .xpoweredby import *
from .xxssprotection import *
from .other import *
from .expectct import *
from .xpcdp import *
from .setcookie import *


import pkgutil
import inspect

__all__ = ['Checker','InfoCollector','CheckerFactory','SyntaxChecker','Finding','FindingSeverity','FindingType','HeaderEmptyChecker','HeaderDeprecatedChecker','HeaderEvaluator','HeaderPresentChecker','InfoDirectiveCollector','InfoHeaderCollector','InfoHeaderCollector','MissingSeparatorChecker','UnknownDirectiveChecker','InfoDisclosureChecker','InfoURLCollector','HeaderMissingChecker','MissingDirectiveChecker','EmptyDirectiveChecker']

for loader, module_name, is_pkg in  pkgutil.walk_packages(__path__):
    if "test" not in module_name :
        module = loader.find_module(module_name).load_module(module_name)
        for name, obj in inspect.getmembers(module):
            if hasattr(obj, "__name__") and obj.__name__ not in __all__ and inspect.isclass(obj) and issubclass(obj, Checker):
                __all__.append(obj.__name__)
