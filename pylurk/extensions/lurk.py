#from construct import *
#from construct.lib import *
from pylurk.core.lurk_struct import LURKCapabilitiesResponsePayload
from pylurk.core.lurk import InvalidFormat, ImplementationError,\
                      ConfError, LurkConf, Payload, LINE_LEN
from pylurk.core.conf import default_conf
from textwrap import indent
from copy import deepcopy

"""
Various classes associated to the extension. This module considers LURK
speciifc packets as an extension. While the header is handled by the
core lurk class. One motivation was to make a clear split between the
treatment of the LURK Header and the treatment of the LURK Payload. 
    
Note that extensions only consider the payload of the request or
response.
"""

class LurkCapabilitiesResponsePayload(Payload):
    """ Class with methods related to the capabilities responses
  
    """
    def __init__(self, conf=deepcopy(default_conf)):
        """ Initialize the capabilities payload response

        Args:
            conf (dict): the configuration associated to the payload. In
            the case of capabilities the full configuration is necessary as
            the response will reflect the configuration. Default value
            is the default_conf
        """
        self.conf = LurkConf(conf)
        self.struct = LURKCapabilitiesResponsePayload
        self.struct_name = 'LURKCapabilitiesResponsePayload'

    def build_payload(self, **kwargs):
        """ builds the payload 

        """
        if 'supported_extensions' in kwargs.keys():
            supported_extensions = kwargs['supported_extensions']
        else:
            supported_extensions = []
            for ext in self.conf.get_supported_ext():
                supported_extensions.append({'designation':ext[0], 'version':ext[1]}) 
        if 'lurk_state' in kwargs.keys():
            lurk_state = kwargs['lurk_state']
        else:
            lurk_state = self.conf.get_state()
        return {'supported_extensions':supported_extensions, \
                 'lurk_state':lurk_state} 

    def check(self, payload):
        """ Checks the payload """
        for ext in payload['supported_extensions']:
            ext = (ext['designation'], ext['version']) 
            if ext not in self.conf.get_supported_ext():
                raise InvalidExtension(ext, "Expected:%s"% \
                          self.conf.supported_extensions)

    def serve(self, request):
        """ Responds to a Capbilities request """
        if len(request) != 0:
            raise InvalidFormat(kwargs, "Expected {}")
        return self.build_payload(**request)


class LurkVoidPayload:
    """Class associated to void payload 

    This class is shared by the requests or responses with a empty
    payload
    """

    def build_payload(self, **kwargs):
        if len(kwargs.keys()) != 0:
            raise InvalidFormat(kwargs, "Expected {}")
        return {}

    def build(self, **kwargs):
        if len(kwargs.keys()) != 0:
            raise InvalidFormat(kwargs, "Expected {}")
        return b''

    def serve(self, request):
        return {}

    def parse(self, pkt_bytes):
        if pkt_bytes != b'':
            raise InvalidFormat(request, "Expected b'' ")
        return {}

    def check(self, payload):
        if payload != {}:
            raise InvalidFormat(payload, "Expected {}") 
    
    def show(self, pkt_bytes, prefix="", line_len=LINE_LEN):
        print(indent("Void Payload", prefix)) 

class LurkExt:
    """ Module Interface

    This class handles the communication between the core lurk and
    the extension. The relation between the core/lurk and the
    extension/lurk is that core/lurk steer request to the extension/lurk
    with the corresponding payload, the extension/lurk responds with the
    corresponding response payload. When an erorr is generated, the
    extension/lurk signals an error occurs as well as the error code 
    associated.

    Extensions are called by the core/lurk and as such Extension need to
    conform to such interface. This means using the generic fucntions
    called by core/lurk
    """
    def __init__(self, conf=deepcopy(default_conf)):
        self.conf = LurkConf(conf)
        self.ext_class = self.get_ext_class() 

    
    def get_ext_class(self):
        ext_class = {}
        if 'ping' in self.conf.get_mtypes()['lurk', 'v1']:
            ext_class[('request', 'ping')] = LurkVoidPayload()
            ext_class[('success', 'ping')] = LurkVoidPayload() 
        if 'capabilities' in self.conf.get_mtypes()['lurk', 'v1']:
            ext_class[('request', 'capabilities')] = LurkVoidPayload() 
            ext_class[('success', 'capabilities')] = \
                LurkCapabilitiesResponsePayload(conf=self.conf.conf) 
        return ext_class


    def check_conf(self, conf):
        for k in conf.keys():
            if k is 'role':
                if conf[k] not in ['client', 'server']:
                    raise ConfError(conf, "Expecting role in  'client'" +\
                                           "'server'")
            elif k in ['ping', 'capabilities']:
                if type(conf[k]) != list:
                    raise ConfError(conf[k], "Expected list")
                if len(conf[k]) > 1:
                    raise ConfError(conf[k], "Only len = 1 is currently " +\
                                                "supported")
                else:
                    raise ConfError(conf, "unexpected key %s"%k)


    def parse(self, status, mtype, pkt_bytes):
        """ parse the byte array into containers. The same status code
            is used are used and response is indicated by "success" """
        return self.ext_class[(status, mtype)].parse(pkt_bytes)

    def build(self, status, mtype, **kwargs):
        return self.ext_class[(status, mtype)].build(**kwargs)

    def serve(self, mtype, request):
        return self.ext_class[('success', mtype)].serve(request)

    def check(self, status, mtype, payload):
        return self.ext_class[(status, mtype)].check(payload)

    def show(self, status, mtype, pkt_bytes, prefix="", line_len=LINE_LEN):
        return self.ext_class[(status, mtype)].show(pkt_bytes,\
                   prefix=prefix, line_len=line_len)


