from .allowcredentials import *
from .alloworigin import *
from .maxage import *
from .exposeheaders import *

import pkgutil
import inspect

__all__ = []

for loader, module_name, is_pkg in  pkgutil.walk_packages(__path__):
    if "test" not in module_name:
        module = loader.find_module(module_name).load_module(module_name)
        for name, obj in inspect.getmembers(module):
            if hasattr(obj, "__name__") and ("checker" in obj.__name__.lower() or "collector" in obj.__name__.lower()) and obj.__name__ not in __all__ and inspect.isclass(obj):
                __all__.append(obj.__name__)
