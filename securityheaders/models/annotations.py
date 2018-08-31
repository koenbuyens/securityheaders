def requiredheader(cls):
    cls.required = True
    return cls

def requireddirective(cls):
    cls.requireddirective = True
    return cls

def anydirective(cls):
    cls.anydirective = True
    return cls

class requireddirectives:
    def __init__(self, *args):
        self.values = list(args)
    
    def __call__(self, fn, *args, **kwargs):
        fn.requireddirectives = self.values
        return fn

class requireddirectivevalues:
    def __init__(self, *args):
        self.values = list(args)
    
    def __call__(self, fn, *args, **kwargs):
        fn.requireddirectivevalues = self.values
        return fn

class description:
    def __init__(self, value):
        self.value = value
    
    def __call__(self, fn, *args, **kwargs):
        fn.description = self.value
        return fn

class headername:
    def __init__(self, value):
        self.value = value
    
    def __call__(self, fn, *args, **kwargs):
        fn.headerkey = self.value
        return fn


class headerref:
    def __init__(self, value):
        self.value = value
    
    def __call__(self, fn, *args, **kwargs):
        if not hasattr(fn, 'headerrefs'):
            fn.headerrefs = []
        fn.headerrefs.append(self.value)
        return fn
