# -*- coding: utf-8 -*-
class Structure:
    def __init__(self):
        self.majorAttributes = []
        self.modifyMsgs = []

    def is_all_zero(self):
        for attr in self.majorAttributes:
            if getattr(self, attr, None):
                return False
        else:
            return True

    def __str__(self):
        s = ''
        maxlen = max([len(x) for x in self.majorAttributes])
        s += '%-*s | %16s | %s\n%s\n' % (maxlen, 'Field Name', 'high <- low  ', 'Value', '-' * 56)
        for f in self.majorAttributes:
            attr = getattr(self, f)
            attr = attr if attr is not None else 'None'
            s += '%-*s | %16s | %s\n' % (maxlen, f, attr[:8].encode('hex') if isinstance(attr, str) else hex(attr), attr)
        s += '%s\n%-*s | %16s | %s\n' % ('-' * 56, maxlen, 'Field Name', 'high <- low  ', 'Value')
        return s

    def __setattr__(self, key, value):
        if key in self.__dict__ and key in self.majorAttributes and self.__dict__[key] is not None:
            old_value = self.__dict__[key]
            if isinstance(old_value, str):
                self.__dict__['modifyMsgs'].append('{clazz}.{attr}: 0x{old} -> 0x{new}'.format(clazz=self.__class__, attr=key, old=repr(self.__dict__[key]), new=repr(value)))
            else:
                self.__dict__['modifyMsgs'].append('{clazz}.{attr}: 0x{old:x} -> 0x{new:x}'.format(clazz=self.__class__, attr=key, old=self.__dict__[key], new=value))
        self.__dict__[key] = value

    def dump_modify_msgs(self):
        for msg in self.modifyMsgs:
            print msg