try:
    import ConfigParser
    from ConfigParser import NoOptionError
except ModuleNotFoundError:
    import configparser
    from configparser import NoOptionError

from distutils.util import strtobool

class OptionParser(object):
    def __init__(self, methods=None):
        self.options = dict()

    def __getitem__(self, argument):
        return self.options.__getitem__(argument)

    def get_options_for(self, checker):
        if checker not in self.options.keys():
            return dict()
        return self.options[checker]

    def get_option(self, checker, key):
        checkeroptions =  self.get_options_for(checker)
        if key not in checkeroptions.keys():
            return []
        return checkeroptions[key]

    def parse(self, filepath=None):
        result = dict()
        result['errors'] = list()
        if filepath:
            appconf = filepath
        else:
            appconf =None
        if appconf:
            try:
                appconfig = ConfigParser.ConfigParser()
                appconfig.readfp(open(appconf))
                self.__add_checks__(appconfig, result) 
                self.__read_config__(appconfig, result)
            except Exception:
                raise Exception('Cannot read config file ' + str(appconf))
        self.options = result
        return self

    def set(self, key, value):
        self.options[key] = value
        return self

    def get(self, key):
        if key not in self.options.keys():
            return None
        return self.options[key]

    def result(self):
        return self.options

    def __enable_checker__(self, checker, value):
       if not 'checks' in self.options.keys():
           self.options['checks'] = []
       if not 'unwanted' in self.options.keys():
           self.options['unwanted'] = []
       if(value):
           self.options['checks'].append(checker)
       else:
           self.options['unwanted'].append(checker)

    def enable_checker(self, checker):
        self.__enable_checker__(checker, True)

    def disable_checker(self, checker):
        self.__enable_checker__(checker, False)

    def __read_config__(self, appconfig, result):
        for checker in result['checks']:
            if checker not in result.keys():
                result[checker] = dict()
            for option in appconfig.options(checker):
                value = appconfig.get(checker, option)
                if value.startswith('file://'):
                    try:
                        fname = value.split('file://',1)[1]
                        with open(fname, 'r') as f:
                            value = f.read().splitlines()
                    except IOError as e:
                        result['errors'].append(str(e))
                result[checker][option] = value 


    def __add_checks__(self, appconfig, result):
        checks = []
        unwanted = []
        for checker in appconfig.sections():
            if "checker" in checker.lower() or "collector" in checker.lower():
                try: 
                    enabled=not strtobool(appconfig.get(checker, 'disabled'))
                except NoOptionError:
                    enabled=True
                try: 
                    enabled=strtobool(appconfig.get(checker, 'enabled'))
                except NoOptionError:
                    enabled=True
                if enabled:
                    checks.append(checker)
                else:
                    unwanted.append(checker)
        result['checks'] = checks
        result['unwanted'] = unwanted
