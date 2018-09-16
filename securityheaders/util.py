try:
    from urlparse import urlparse
except ModuleNotFoundError:
    from urllib.parse import urlparse #python3

import re
import os
import pkgutil
import inspect
import sys

class Util(object):


    @staticmethod
    def load_all_modules_from_dir(dirname):
        for importer, package_name, _ in pkgutil.iter_modules([dirname]):
            full_package_name = '%s.%s' % (dirname, package_name)
            if full_package_name not in sys.modules:
                module = importer.find_module(package_name
                        ).load_module(full_package_name)
    @staticmethod
    def inheritors(klass):
        subclasses = set()
        work = [klass]
        while work:
            parent = work.pop()
            for child in parent.__subclasses__():
                if child not in subclasses:
                    subclasses.add(child)
                    work.append(child)
        return subclasses

    @staticmethod
    def get_all_subclasses(cls):
        all_subclasses = []

        for subclass in cls.__subclasses__():
            all_subclasses.append(subclass)
            all_subclasses.extend(Util.get_all_subclasses(subclass))

        return all_subclasses

    @staticmethod
    def search_files(directory='.', extension=''):
        result = []
        extension = extension.lower()
        for dirpath, dirnames, files in os.walk(directory):
            for name in files:
                if extension and name.lower().endswith(extension):
                    result.append(os.path.join(dirpath, name))
                elif not extension:
                    result.append(os.path.join(dirpath, name))
        return result

    @staticmethod
    def isUrlScheme(urlScheme):
        """ Checks whether a string is an url scheme

        Args:
            urlScheme (str): string to check whether it is an url scheme
        """
        if not urlScheme:
            return False
        
        #an urlscheme can be anything that starts with alfanumeric charaters followed by a colon. 
        pattern = re.compile('^[a-zA-Z][+a-zA-Z0-9.-]*:$')
        return bool(pattern.search(str(urlScheme)))

    @staticmethod
    def getSchemeFreeUrl(url):
        """ Removes the scheme from the url. E.g. https://www.google.com becomes www.google.com

        Args:
            url (str): string from which to remove the scheme
        """
        if not url:
            return None

        tmp = re.sub("^\w[+\w.-]*:\/\/", "", str(url), flags=re.IGNORECASE)
        tmp = re.sub("^\/\/", "", tmp, flags=re.IGNORECASE)  
        return tmp

    @staticmethod
    def matchWildcardUrls(url, listOfUrls):
        """ Checks whether wildcard host matches one of the given urls

        Args:
            url (str): host with potential wild card
            listOfUrls(list): list of urls that might be part of the host.
        """
        if not url or not listOfUrls:
            return None
        pattern = re.compile('^[a-zA-Z][+a-zA-Z0-9.-]*:.*')
        if not pattern.search(str(url)) and not url.startswith('//'):
            url = '//' + url
        cspUrl = urlparse(str(url))            
        host = cspUrl.netloc.lower() or ""
        hostHasWildcard = host.startswith("*.")
        wildcardFreeHost = re.sub("^\*", "", host, flags=re.IGNORECASE)
        path = cspUrl.path or ''
        hasPath = len(cspUrl.path) > 0 

        for url2 in listOfUrls:
            url = urlparse(str(url2))
            domain = url.netloc.lower() or ""
            domainHasWildCard =  domain.startswith("*.")
            if (not domainHasWildCard):
                if (not domain.endswith(wildcardFreeHost) ): 
                    continue
                if (not hostHasWildcard and host != domain):
                    continue
            else:
                domainparts = list(reversed(domain.split('.')))
                hostparts = list(reversed(host.split('.')))
                stop = False
                domainlen = len(domain.split('.'))
                hostlen = len(host.split('.'))
                
                for idx, domainpart in enumerate(domainparts):
                    if idx < hostlen:
                        hostpart = hostparts[idx]
                        if hostpart != domainpart and (domainpart != '*' and hostpart != '*'):
                            stop = True
                if stop:
                    continue
            if (hasPath):
                if (path.endswith('/')): 
                    if (not url.path.startswith(path)):
                        continue
                elif (url.path != path):
                    continue

            return url

        return None
