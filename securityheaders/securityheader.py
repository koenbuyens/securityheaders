try:
    import httplib
    from urlparse import urlparse
except ModuleNotFoundError:
    import http.client as httplib
    from urllib.parse import urlparse #python3

import socket
import ssl
import random
from functools import partial
from anytree import ContStyle, RenderTree     

try:
    from multiprocessing import Pool, freeze_support
except ImportError:
    Pool = None

from .checkers import HeaderEvaluator, CheckerFactory, Finding, FindingSeverity, FindingType
from .models import ModelFactory

from securityheaders.formatters import FindingFormatterFactory
from .optionparser import OptionParser




def _pickle_method(method):
    func_name = method.im_func.__name__
    obj = method.im_self
    cls = method.im_class
    if func_name.startswith('__') and not func_name.endswith('__'): #deal with mangled names
        cls_name = cls.__name__.lstrip('_')
        func_name = '_' + cls_name + func_name
    return _unpickle_method, (func_name, obj, cls)

def _unpickle_method(func_name, obj, cls):
    for cls in cls.__mro__:
        try:
            func = cls.__dict__[func_name]
        except KeyError:
            pass
        else:
            break
    return func.__get__(obj, cls)

try: 
    import copy_reg
except ModuleNotFoundError:
    import copyreg as copy_reg

import types
copy_reg.pickle(types.MethodType, _pickle_method, _unpickle_method)
                                  

class SecurityHeaders(object):
    def __init__(self):
        self.options = OptionParser()


    def load_options_from_file(self, filepath):
        self.options.parse(filepath)

    def set_option(self, key, value):
        self.options.set(key, value)

    def get_options_for(self, checker):
        return self.get_options_for(checker)

    def get_option(self, checker, key):
        return self.get_option(checker, key)

    def get_options(self):
        return self.options.result()

    def get_all_checker_names(self):
        return CheckerFactory().getnames()
    
    def get_all_header_names(self):
        return sorted(ModelFactory().getheadernames())

    def get_all_formatter_names(self):
        return FindingFormatterFactory().getshortnames()

    def get_formatter(self, formattername):
        return FindingFormatterFactory().getformatter(formattername)

    def format_findings(self, formatter, findings):
        return self.get_formatter(formatter).format(findings)

    def get_all_checker_names_as_tree(self):
        return CheckerFactory().getnames_as_tree()

    def get_all_checker_names_as_tree_string(self):
        return RenderTree(self.get_all_checker_names_as_tree(), style=ContStyle(), childiter=lambda items: sorted(items, key=lambda item: item.name)).by_attr("name")


    def enable_checker(self, checker):
        self.__enable_checker__(checker, True)

    def disable_checker(self, checker):
        self.__enable_checker__(checker, False)

    def check_headers_from_string(self, headers, options=None):
        if not options:
            options= self.options.result()
        return self.check_headers_with_list(headers.splitlines())

    def check_headers_from_file(self, fp, options=None):
        if not options:
            options= self.options.result()
        headers = []
        with fp as f:
            f.readline() # Skip status line
            for line in f.readlines():
                if line.strip() == '':
                    break
                headers.append(line.strip())
        return self.check_headers_with_list(headers)

    def check_headers_with_list(self, resheaders, options=None):
        if not options:
            options= self.options.result()
        headers = list()
        for header in resheaders:
            s = header.split(':', 1)
            if(len(s) == 2):
                headers.append((s[0].lower(),s[1]))
            else:
                headers.append((s[0].lower(),''))
        return self.check_headers_with_map(headers, options)

    def check_headers_with_map(self, headermap, options=None):
        if not options:
            options= self.options.result()
        if not 'checks' in options.keys():
            options['checks'] = []
        if not 'unwanted' in options.keys():
            options['unwanted'] = []
        checks = CheckerFactory().getactualcheckers(options['checks'])     
        unwanted = CheckerFactory().getactualcheckers(options['unwanted'])
        options['checks'] = [e for e in checks if e not in unwanted]
        options['unwanted'] = None
        #propagate down
        for checker in options['checks']:
            leafs = CheckerFactory().getleafcheckers(checker)
            for leaf in leafs:
                if checker in options.keys():
                    for check in options[checker].keys():
                        if leaf not in options.keys():
                            options[leaf]=dict()
                        options[leaf][check] = options[checker][check]      
        return HeaderEvaluator().evaluate(headermap,options)

    def check_headers_parallel(self, urls, options=None, callback=None):
        if not options:
            options= self.options.result()

        if Pool:
            results = []
            freeze_support()
            pool = Pool(processes=100)
            for url in urls:
                result = pool.apply_async(self.check_headers, args=(url, options.get('redirects'), options), callback=callback)
                results.append(result)
            pool.close()
            pool.join() 
            return results
        else:
            raise Exception('no parallelism supported')

    def check_headers(self, url, follow_redirects = 3, options=None):
        """ Make the HTTP request and check if any of the pre-defined
        headers exists.

        Args:
            url (str): Target URL in format: scheme://hostname/path/to/file
            follow_redirects (Optional[str]): How deep we follow the redirects, 
            value 0 disables redirects.
        """
        if not options:
            options= self.options.result()

        urlid = 1
        if(len(url) > 1 and not isinstance(url, str)):
            urlid = url[0]
            url = url[1]

        url = url.strip('"')
        if not urlparse(url).scheme:
           if 'defaultscheme' in options:
               url = options['defaultscheme'] + '://' + url
           else:
               url = 'https://' + url.strip()

        parsed = urlparse(url) 
        hostname = parsed.netloc
        if not hostname:
            return []
        path = parsed[2].strip()
        if not path:
            path = "/"
        protocol = parsed.scheme
        url = protocol + "://"+hostname
        #some sites do not like url lib (403, if not a 'real' browser
        agents= [
            'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko)',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)',
            'Mozilla/5.0 (Windows NT 6.4; WOW64) AppleWebKit/537.36 (KHTML, like Gecko)',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0']
        headers =  {"User-Agent":random.choice(agents)}


        try:
            if (protocol == 'http'):
                conn = httplib.HTTPConnection(hostname)
            elif (protocol == 'https'):
                # on error, retry without verifying cert
                # in this context, we're not really interested in cert validity
                conn = httplib.HTTPSConnection(hostname, context = ssl._create_unverified_context() )
            else:
                """ Unknown protocol scheme """
                return {}
     
            conn.request('GET', path, None, headers)
            res = conn.getresponse()
            headers = res.getheaders()

            """ Follow redirect """
            if (res.status >= 300 and res.status < 400  and follow_redirects > 0):
                for header in headers:
                    if (header[0] == 'location'):
                        return self.check_headers((urlid, header[1]), follow_redirects - 1, options) 
                
            """ Loop through headers and evaluate the risk """
            result = self.check_headers_with_map(headers, options)
            for finding in result:
                finding.url = url
                finding.urlid = urlid
            
            return result
        except Exception as e:
            return [Finding(None, FindingType.ERROR, str(e), FindingSeverity.ERROR, None, None,url , urlid)]
