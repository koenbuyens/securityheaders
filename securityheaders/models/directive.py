from enum import Enum

class Directive(Enum):

    @classmethod
    def __new__(cls, *values):
        obj = object.__new__(cls)
        # first value is canonical value
        obj._value_ = values[1].lower()
        for other_value in values[1:]:
            cls._value2member_map_[other_value.lower()] = obj
        obj._all_values = values
        return obj

    def __repr__(self):
        return self.__str__()

    def endswith(self, value):
        return str(self).endswith(value)

    def startswith(self, value):
        return str(self).startswith(value)

    def __str__(self):
        """ Returns a string representaiton of this CSP Directive   
        """
        return str(self._value_).lower() 

    def lower(self):
        return str(self).lower()

    def find(self, value):
        return str(self).find(value) 

    @classmethod
    def keys(cls):
        return cls._value2member_map_.keys()

    @classmethod
    def directiveseperator(cls):
        return ';'


    @classmethod
    def directivevalueseperator(cls):
        return ':'

    @classmethod
    def valueseperator(cls):
        return None

    @classmethod
    def isDirective(cls):
        pass

    def getDefaultValue(self):
        pass
