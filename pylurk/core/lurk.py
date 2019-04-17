"""
We need to provide an explaination on how to add a new extension.

"""
from copy import deepcopy
from time import time
from textwrap import indent
from secrets import randbits
from socketserver import ThreadingMixIn, UDPServer, TCPServer, BaseRequestHandler
#from concurrent.futures import ThreadPoolExecutor
from http.server import HTTPServer, BaseHTTPRequestHandler
from select import select
#from socket import error as SocketError

import socket
import os
import selectors
import errno
import urllib.request
import ssl
import binascii
#import threading
import pkg_resources

from pylurk.core.conf import default_conf
from pylurk.core.lurk_struct import LURKHeader, LURKErrorPayload

from Cryptodome.Hash import SHA256
#from os.path import join

HEADER_LEN = 16
LINE_LEN = 60

DATA_DIR = pkg_resources.resource_filename(__name__, '../data/')

def wrap(text, line_len=LINE_LEN):
    """ Wrap text so it does not exceeds line_len

    Args:
        text (str): the text that can be multilines
        line_len (int): the maximum len for a line

    Returns:
        wrap (str): the wrapped text.
    """
    lines = text.split('\n')
    wrap = ""
    for line in lines:
        if len(line) < line_len:
            wrap += line
            wrap += '\n'
            continue
        margin = "    "
        for c in line:
            if c.isspace():
                margin += c
            else:
                break
        wrap += line[: line_len] + '\n'
        line = margin + line[line_len :]
        while len(line) >= line_len:
            wrap += line[: line_len] + '\n'
            line = margin + line[line_len :]
        wrap += line[:]
        wrap += '\n'
    return wrap



class Error(Exception):
    """ Generic Error class
    """
    def __init__(self, expression, message):
        self.expression = expression
        self.message = message
        self.status = None

## system error
class ConfError(Error):
    """ Configuration Error
    """
    pass

class ImplementationError(Error):
    """ Implementation Error
    """
    pass


## LURK Error
class UndefinedError(Error):
    """ LURK Undefined Error
       
    This Error is returned by the LURK server to the LURK Client. 
    The Error is not specified.  
    """
    def __init__(self, expression, message):
        super().__init__(expression, message)
        self.status = "undefined_error"
class InvalidFormat(Error):
    """ LURK Invalid Format Error

    This Error is returned by the LURK server to the LURK Client.
    This Error indicates an unexpected packet that cannot be parsed.
    """
    def __init__(self, expression, message):
        super().__init__(expression, message)
        self.status = "invalid_format"
class InvalidExtension(Error):
    """ LURK Invalid Format Error

    This Error is returned by the LURK server to the LURK Client.
    This Error indicates the mentionned Extension is not recognized by
    the LURK Server. Recognized LURK extensions are indicated in the 
    conf file..
    """
    def __init__(self, expression, message):
        super().__init__(expression, message)
        self.status = "invalid_extension"
class InvalidType(Error):
    """ LURK Invalid Type

    This Error is returned by the LURK server to the LURK Client.
    This Error indicates the type has not been recognized, by the LURK
    Server. The recognized Extension and types are indicated in the 
    conf file.  
    """
    def __init__(self, expression, message):
        super().__init__(expression, message)
        self.status = "invalid_type"
class InvalidStatus(Error):
    """ LURK Invalid Status

    This Error is returned by the LURK server to the LURK Client.
    The LURK Server is expected to receive request, and reject any other
    status. An unrecognized or unexpected status returns this error. 
    """
    def __init__(self, expression, message):
        super().__init__(expression, message)
        self.status = "invalid_status"
class TemporaryFailure(Error):
    """ LURK Tenporary Failure

    This Error is returned by the LURK server to the LURK Client.
    This error is returned when the LURK serve ris not able to serve a
    request due to a temporary lake of resource.Upon receipt of such error,
    a LURK Client is expect to wait some time and retry the request  
    """
    def __init__(self, expression, message):
        super().__init__(expression, message)
        self.status = "temporary_failure"


class LurkConf():

    """ Lurk Configuration class

    This class provides tools to check and to validates a given
    configuration. Checks are relatively high level, and do not go in to
    the detail of each extension. However, a lot of functions are shared
    with configurations specific to each extension, methods.  
    """
    def __init__(self, conf=deepcopy(default_conf)):
        """ Initlizes the LurkConf class
        
        Args:
            conf (dict): a representation of the configuration. Default
                values are default_conf.
        """
        self.conf = self.check_conf(conf)

    def check_conf(self, conf=None):
        """Checks the format of the configuration file

        If the configuration file is not provided, checks are performed
        on self.conf.

        Args:
            conf (dict): the configuration dictionary. When not
                provided, checks applies to self.conf.

        Returns:
            conf (dict): the configuration dictionary. In some case,
                some changes have been performed such as removing non
                necessary data.

        Raises:
            ConfError when an configuration error is detected.
        """
        if conf is None:
            conf = self.conf

        if not isinstance(conf, dict):
#        if type(conf) is not dict:
            raise ConfError(conf, "Expecting dict")
        self.check_key(conf, ['role', 'connectivity', 'extensions'])
        if conf['role'] not in ['client', 'server']:
            raise ConfError(conf['role'], "Expecting role as 'client' " + \
                                            "or 'server'")
        connectivity = conf['connectivity']
        if connectivity['type'] not in ["local", "udp", "udp+dtls", \
                                        "tcp", "tcp+tls", "http", "https"]:
            raise ConfError(connectivity, "Expected type as 'local' "+\
                                            "or 'udp' or 'tcp' or 'http'")
#        if type(conf['extensions']) is not list:
        if not isinstance(conf['extensions'], list):
            raise ConfError(conf['connectivity'], "Expected 'list'")
        id_bytes = randbits(8)
        for ext in conf['extensions']:
            ## validation between of ('designation', 'version', 'type'
            ## is tested by building a LURKHeader
            try:
                LURKHeader.build({'designation' : ext['designation'],
                                  'version' : ext['version'],
                                  'type' : ext['type'],
                                  'status' : "request",
                                  'id' : id_bytes,
                                  'length' : HEADER_LEN})
            except:
                raise ConfError(ext, "Unexpected values for designation, " +\
                                      "version type")
        return self.check_crypto_keys(conf)

    def check_crypto_keys(self, conf=None):
        """  Removes unecessary keys depending on roles, connectivity type

        The default configuration is provided for a server with a secure
        connectivity between the client and the server. A client or a
        server not using a secure communication do not need to be provisioned
        with such keys. This functions removes such keys are removed.
        Similarly, a client does not needs the private keys associated to
        extensions. This function also removes such keys.

        On the other hand, when the keys are necessary and are missing,
        this function raises a ConfError.

        The function also checks when possible that the 'role' matches
        the keys provided to secure the channel between the client and the
        server. It is assumed that 'server' and 'client' are mentioned
        in the cert and key files. However, the function does not remove
        the private key of the peer. This is left to the set_role
        function.

        Args:
            conf (dict): the configuration dictionary. When not
                provided, checks applies to self.conf.

        Returns:
            conf (dict): the configuration dictionary. In some case,
                some changes have been performed such as removing non
                necessary data.

        Raises:
            ConfError when private keys or cerrtificates  are missing.
        """

        if conf is None:
            conf = self.conf
        conn_type = conf['connectivity']['type']
        if conn_type not in ['udp+dtls', 'tcp+tls', 'https']:
            try:
                del conf['connectivity']['key']
                del conf['connectivity']['cert']
                del conf['connectivity']['key_peer']
                del conf['connectivity']['cert_peer']
            except KeyError:
                pass
        else:
            for k in ['key', 'cert', 'cert_peer']:
                if k not in conf['connectivity'].keys():
                    raise ConfError(conf['connectivity'],\
                        "Connectivity type %s requires "%conn_type +\
                        "credentials to secure the client server " +\
                        "communication. 'key', 'cert' and 'cert_peer'" +\
                        "are expected")
        if conf['role'] == 'client':
            for ext_index in range(len(conf['extensions'])):
                try:
                    del conf['extensions'][ext_index]['key']
                except KeyError:
                    pass
        elif conf['role'] == 'server':
            for ext in conf['extensions']:
                if ext['type'] in ['ping', 'capabilities']:
                    continue
                try:
                    ext['key']
                except KeyError:
                    raise ConfError(ext, "Private key Expected with " +\
                        "server role (role: %s)"%conf['role'])
        return conf

    def set_role(self, role):
        """ set the role of the configuration

        The main difference between the two roles is that the client
        does not need private keys, while the server needs private keys to
        perform some cryptographic operations. The function does not proceed
        to such checks. It is always recommended to perform a self.check
        after changes have been performed.

        Args:
            role (str) the designation of the role. Expected values are
                'client' or 'server'

        Raises:
            ConfError
        """

        if role not in ['client', 'server']:
            raise ConfError(role, "Expected 'client' or 'server'")
        self.conf['role'] = role
        ## if we have the default configuration, make sure it is
        ## correct
        try:
            role = self.conf['role']
            if role == 'server':
                role_peer = 'client'
            else:
                role_peer = 'server'
            key = self.conf['connectivity']['key']
            cert = self.conf['connectivity']['cert']
            ## key_peer may not be present. If not a Key Error is raised
            ## and no further key is performed. The check is only
            ## intended to switch keys according to role. It is based on
            ## the heuristics that 'clients' and 'servers' are indicated
            ## in the key files.
            key_peer = self.conf['connectivity']['key_peer']
            cert_peer = self.conf['connectivity']['cert_peer']
            if (role in key_peer and role_peer in key) or \
               (role in cert_peer and role_peer in cert):
                self.conf['connectivity']['key'] = key_peer
                self.conf['connectivity']['cert'] = cert_peer
                self.conf['connectivity']['key_peer'] = key
                self.conf['connectivity']['cert_peer'] = cert
        except KeyError:
            ## no key_peer. may not be an issue
            pass
        try:
            del self.conf['connectivity']['key_peer']
        except KeyError:
            pass
        if self.conf['role'] == 'client':
            for ext_index in range(len(self.conf['extensions'])):
                try:
                    del self.conf['extensions'][ext_index]['key']
                except KeyError:
                    pass

    def set_connectivity(self, **kwargs):
        """Configures the channel between the client and the server

        Connectivity is set by setting arguments provided by kwargs
        first. When not provided the connectivity is configured with
        parameters provided in self.conf. When these are missing the
        value from default_conf are considered.

        Args:
            role:
            type :
            ip_address:
            port:
            key:
            cert:
            cert_peer:

        """
        for k in ['type', 'ip_address', 'port', 'key', 'cert', \
                  'key_peer', 'cert_peer']:
            try:
                self.conf['connectivity'][k] = kwargs[k]
            except KeyError:
                try:
                    self.conf['connectivity'][k]
                except KeyError:
                    self.conf['connectivity'][k] = deepcopy(default_conf['connectivity'][k])
        try:
            self.conf['role'] = kwargs['role']
        except KeyError:
            try:
                self.conf['role']
            except KeyError:
                try:
                    self.conf['role']
                except KeyError:
                    self.conf['role'] = deepcopy(default_conf['role'])

        self.set_role(self.conf['role'])

    def get_conf(self):
        """Returns the configuration

        Checks self.conf and returns it.

        Returns:
            conf (dict): the dictionary with all configuration parameters.

        """

        self.set_role(self.conf['role'])
        self.check_conf()
        return self.conf


    def get_mtypes(self):
        """ returns the list of types associated to each extentions
             {(designation_a, version_a) : [type_1, ..., type_n],
               (designation_n, version_n) : [type_1, ..., type_n]}
        """

        mtype = {}
##        id_bytes = randbits(8)
        for ext in self.conf['extensions']:
            k = (ext['designation'], ext['version'])
            try:
                if ext['type'] not in mtype[k]:
                    mtype[k].append(ext['type'])
            except KeyError:
                mtype[k] = [ext['type']]
        return mtype


    def get_supported_ext(self):
        """ returns the list of extensions
          [(designation_a, version_a), ... (designation_n, version_n)]
        """
        sup_ext = []
        for extension in self.conf['extensions']:
            ext = (extension['designation'], extension['version'])
            if ext not in sup_ext:
                sup_ext.append(ext)
        return sup_ext

    def get_ext_conf(self, designation, version, \
            exclude=['designation', 'version', 'type']):
        """ returns the configuration associated to an extension.
            conf = {'role' : "server"
                      'ping' : [ []. ...  []],
                     'rsa_master' : [{conf1_rsa}, {conf2_rsa}, ...]}
        """
        conf = {}
        ## conf['role'] = self.conf['role']
        type_list = []
        for ext in self.conf['extensions']:
            if ext['designation'] == designation and \
               ext['version'] == version:
                type_list.append(ext['type'])
        type_list = list(set(type_list))
        for mtype in type_list:
            conf[mtype] = self.get_type_conf(designation, version, \
                                mtype, exclude=exclude)
        return conf




    def get_type_conf(self, designation, version, mtype, \
            exclude=['designation', 'version', 'type']):
        """ returns the configuration parameters associated to a given
            type. It has the 'role' value and removes parameters value
            provided by exclude.  """
        type_conf = []
        for ext in self.conf['extensions']:
            if ext['designation'] == designation and \
               ext['version'] == version and \
               ext['type'] == mtype:
                conf = dict(ext)
                conf['role'] = self.conf['role']
                for k in exclude:
                    if k in conf.keys():
                        del conf[k]
                type_conf.append(conf)
        return type_conf

    def get_server_address(self):
        """ Returns the IP address of the LURK Server
        """
        return self.conf['connectivity']['ip_address'], \
               self.conf['connectivity']['port']

    def get_connection_type(self):
        """ Returns the type of connectivity
        """
        return self.conf['connectivity']['type']

    def get_tls_context(self):
        """ builds TLS context from configuration

        Returns:
            tls_ctx : the TLS context to establish a TLS session between the
                client and the server.
        """

        conn_conf = self.conf['connectivity']
        if conn_conf['type'] not in ['udp+dtls', 'tcp+tls', 'https']:
            return None
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.load_cert_chain(certfile=conn_conf['cert'], keyfile=conn_conf['key'])
        if self.conf['role'] == 'server':
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(cafile=conn_conf['cert_peer'])
        return context


    ### function used by classes using this ConfLurk class
    def check_key(self, payload, keys):
        """ checks payload got the expected keys"""
        if set(payload.keys()) != set(keys):
            raise InvalidFormat(str(payload.keys()),   \
                      "Missing or extra key found. Expected %s"%keys)

    def check_extension(self, designation, version):
        ext = (designation, version)
        if ext  not in self.get_mtypes().keys():
            raise InvalidExtension(ext, "Expected %s"%self.get_mtypes().keys())

    def check_type(self, designation, version, mtype):
        if mtype not in self.get_mtypes()[(designation, version)]:
            raise InvalidType(self.get_mtypes(), "Expected: %s"%
                              self.get_mtypes()[(designation, version)])

    def get_state(self):
        state = "state" +  str(self.get_supported_ext())
        return SHA256.new(str.encode(state)).digest()[:4]

    def check_error(self, error_payload):
        if error_payload == {}:
            return True
        self.check_key(error_payload, ['lurk_state'])
        self.check_error_bytes(error_payload['lurk_state'])

    def check_error_bytes(self, error_payload_bytes):
        error = error_payload_bytes
        if isinstance(error, bytes):
            raise InvalidFormat(type(error), "Expected bytes")
        if len(error) != 4:
            raise InvalidFormat(len(error), "Expected 4 byte len")





class Payload:
    def __init__(self, conf):
        """Generic class for lurk payload

        Lurk designates as Payloads the bytes associated to a specific
        extension. In other words, a payload is all bytes after the Lurk
        Header. The Payload class provides an abstraction for programming
        extensions as it deals with the convertion between the binary
        representation of th3 payload and the representation of the payload
        structure using a dictionary.
        The Payload class is closely tided with the Struct instance that
        describes the object.
        """
        self.conf = conf
        self.struct = None
        self.struct_name = 'EmptyPayload'

    def build_payload(self, **kwargs):
        """ returns the container that describes the payload """
        return {}

    def build(self, **kwargs):
        """ converts the container describing the payload into a byte
            format """
        payload = self.build_payload(**kwargs)
        self.check(payload)
        return self.struct.build(payload)

    def parse(self, pkt_bytes):
        """ returns payload described in byte format (pkt_bytes) into a
            container """
        try:
            payload = self.struct.parse(pkt_bytes)
            self.check(payload)
            return payload
        except Exception as e:
            self.treat_exception(e)

    def treat_exception(self, e):
        """ Translate internal error into Lurk Errors
 
        Args:
            e MappingError returns by construct

        Raises:
            corresponding LURK Error
        """
        if isinstance(e, MappingError):
            value = e.args[0].split()[4]
            if "designation" in e.args[0]:
                raise InvalidExtension(value, "unvalid extension")
            elif "version" in e.args[0]:
                raise InvalidExtension(value, "unvalid extension")
            elif "status" in e.args[0]:
                raise InvalidStatus(value, "unexpected status")
            elif "type" in e.args[0]:
                raise  InvalidType(value, "unexpected message type")
        else:
            raise InvalidFormat(type(e), e.args)

    def check(self, payload):
        pass

    def show(self, payload, prefix="", line_len=LINE_LEN):
        """ shows the pkt_bytes. Similar to parse but without any
            control of the configuration and uses the structure
            visualization facilities.

        Args:
            payload (bytes or dict) represents the payload. The payload
                format can be bytes or a dictionary
            prefix (str): the begining of the printed line. It can be a
                indentation with a number of white spaces or a specific mark
            line_len (int): the maximum len for a line
        """
        print(indent("%s"%self.struct_name, prefix))

        if isinstance(payload, bytes):
            pkt_bytes = payload
        elif isinstance(payload, dict):
            pkt_bytes = self.struct.build(payload)
        s = wrap("%s"%self.struct.parse(pkt_bytes), line_len=line_len)
        print(indent(s, prefix))




class LurkMessage(Payload):

    def __init__(self, conf=deepcopy(default_conf)):
        self.conf = LurkConf(conf)
        self.struct = LURKHeader
        self.struct_name = 'Lurk Header'
        self.lurk = self.import_ext()

    def import_ext(self):
        lurk_ext = {}
        mtypes = self.conf.get_mtypes()
        for ext in mtypes.keys():
            if ext == ("lurk", "v1"):
                import pylurk.extensions.lurk
                ## ext_lurk is a special option. It needs the list of
                ## extensions which are parameters outside lurkext. We
                # provide the  full configuration file.
                lurk_ext[ext] = pylurk.extensions.lurk.LurkExt(self.conf.conf)
            elif ext == ("tls12", "v1"):
                ## this is how future extensions are expected to be handled.
                import pylurk.extensions.tls12
                lurk_ext[ext] = pylurk.extensions.tls12.LurkExt(
                    self.conf.get_ext_conf('tls12', 'v1'))
            else:
                raise ConfError(ext, "unknown extension")
        return lurk_ext

    def get_ext(self, message):
        """ returns the LurkExt object from a message or header """
        ext = (message['designation'], message['version'])
        return  self.lurk[ext]

    def get_header(self, message):
        return {'designation' : message['designation'], \
                 'version' : message['version'], \
                 'type' : message['type'], \
                 'status' : message['status'], \
                 'id' : message['id'], \
                 'length' :  message['length']}

    def build_ext_payload(self, header, **kwargs):
        status = header['status']
        mtype = header['type']
        if status not in ['request', 'success']:
            raise ImplementationError(status, "Expected 'request' or 'success'")
        return self.get_ext(header).build(status, mtype, **kwargs)

    def check_ext_payload(self, header, payload):
        status = header['status']
        mtype = header['type']
        if status not in ['request', 'success']:
            raise ImplementationError(status, "Expected 'request' or 'success'")
        self.get_ext(header).check(status, mtype, payload)


    def parse_ext_payload(self, header, payload_bytes):
        status = header['status']
        mtype = header['type']
        if status not in ['request', 'success']:
            raise ImplementationError(status, "Expected 'request' or 'success'")
        return  self.get_ext(header).parse(status, mtype, payload_bytes)

    def show_ext_payload(self, header, payload_bytes, prefix="", line_len=LINE_LEN):
        status = header['status']
        mtype = header['type']
        if status not in ['request', 'success']:
            raise ImplementationError(status, "Expected 'request' or 'success'")
        return  self.get_ext(header).show(status, mtype, payload_bytes, \
                                            prefix=prefix, line_len=line_len)


    def serve_ext_payload(self, header, request):
        mtype = header['type']
        return self.get_ext(header).serve(mtype, request)


    def build_payload(self, **kwargs):
        """ builds the lurk header. Missing arguments are replaced by
            default values. Additional keys may be:
                payload_bytes: that describes the payload carried by the
                lurk header. It is used to derive the length.
        """
        if 'designation' in kwargs.keys():
            designation = kwargs['designation']
        else:
            designation = "lurk"
        if 'version' in kwargs.keys():
            version = kwargs['version']
        else:
            version = "v1"
        if 'type' in kwargs.keys():
            mtype = kwargs['type']
        else:
            mtype = "ping"
        if 'status' in kwargs.keys():
            status = kwargs['status']
        else:
            status = "request"
        if 'id' in kwargs.keys():
            hdr_id = kwargs['id']
        else:
            hdr_id = randbits(8 * 8)
        if 'length' in kwargs.keys():
            length = kwargs['length']
        else:
            length = HEADER_LEN
        header = {'designation' : designation, 'version' : version, \
                   'type' : mtype, 'status' : status, 'id' : hdr_id, \
                   'length' : length}
        if 'payload' in kwargs.keys():
            payload = kwargs['payload']
            if status in ['request', 'success']:
                payload_bytes = self.build_ext_payload(header, **payload)
                payload = self.parse_ext_payload(header, payload_bytes)
            else: ## if the message is an error message
                payload_bytes = LURKErrorPayload.build(payload)
                payload = LURKErrorPayload.parse(payload_bytes)
            header['length'] += len(payload_bytes)
            return {**header, 'payload' : payload}
        else:
            if 'payload_bytes' in kwargs.keys():
                payload_bytes = kwargs['payload_bytes']
            else:
                payload_bytes = b''
            header['length'] += len(payload_bytes)
            return {**header, 'payload_bytes' : payload_bytes}



    def build(self, **kwargs):
        message = self.build_payload(**kwargs)
        self.check(message)
        header = self.get_header(message)
        if 'payload' in message.keys():
            payload = message['payload']
            if header['status'] in ["success", "request"]:
                payload_bytes = self.build_ext_payload(header, **payload)
            else: ## the payload is an error payload
                payload_bytes = LURKErrorPayload.build(payload)
        elif 'payload_bytes' in message.keys():
            payload_bytes = message['payload_bytes']
        header['length'] = HEADER_LEN + len(payload_bytes)
        return self.struct.build(header) + payload_bytes

    def check(self, message):
        header = ['designation', 'version', 'type', 'status', 'id', 'length']
        try:
            header.append('payload')
            self.conf.check_key(message, header)
        except InvalidFormat:
            header.remove('payload')
            header.append('payload_bytes')
            self.conf.check_key(message, header)
        header = self.get_header(message)

        self.conf.check_extension(header['designation'], header['version'])
        self.conf.check_type(header['designation'], header['version'], \
                              header['type'])
        if 'payload' in message.keys():
            payload = message['payload']
            if header['status'] in ["success", "request"]:
                self.check_ext_payload(header, payload)
            else:
                self.conf.check_error(payload)
        elif 'payload_bytes' in message.keys():
            payload = message['payload_bytes']
            if header['status'] in ["success", "request"]:
                pass
            else:
                self.conf.check_error_bytes(message['payload_bytes'])
        else:
            raise ImplementationError(message, \
                      "Expecting 'payload or 'payload_bytes' key")

    def parse(self, pkt_bytes):
        """ parse the first packet, ignores remaining bytes. """
        if len(pkt_bytes) < HEADER_LEN:
            raise InvalidFormat(len(pkt_bytes), \
                  "bytes packet length too short for LURK header. " +\
                  "Expected length %s bytes"%HEADER_LEN)
        try:
            header = self.struct.parse(pkt_bytes)
        except Exception as e:
            self.treat_exception(e)
        payload_bytes = pkt_bytes[HEADER_LEN : header['length']]
        if header['status'] in ["success", "request"]:
            payload = self.parse_ext_payload(header, payload_bytes)
        else: ## the payload is an error payload
            payload = LURKErrorPayload.parse(payload_bytes)
        message = {**header, 'payload' : payload}
        self.check(message)
        return message


    def serve(self, request):
        try:
            if request['status'] != "request":
                raise InvalidStatus(request['status'], "Expected 'request'")
        except KeyError:
            raise ImplementationError(request, "No key status")
        header = self.get_header(request)
        try:
            if 'payload_bytes' in request.keys():
                req_payload = self.parse_ext_payload(header, request['payload_bytes'])
            elif 'payload' in request.keys():
                req_payload = request['payload']
            else:
                raise ImplementationError(request, "Expected 'payload'" +\
                                           "or 'payload_bytes' keys")
            resp_payload = self.serve_ext_payload(header, req_payload)
            header['status'] = "success"
            resp_bytes = self.build_ext_payload(header, **resp_payload)
            header['length'] = HEADER_LEN + len(resp_bytes)
            return {**header, 'payload' : resp_payload}
        except Exception as e:
            try:
                resp_payload = {'lurk_state' : self.conf.get_state(header)}
                resp_bytes = LURKErrorPayload.build(resp_payload)
                header['status'] = e.status
                header['length'] = HEADER_LEN + len(resp_bytes)
                return {**header, 'payload' : resp_payload}
            except Exception as e:
                raise ImplementationError(e, "implementation Error")


    def show(self, pkt_bytes, prefix="", line_len=LINE_LEN):
        print(indent("%s"%self.struct_name, prefix))
#        if type(pkt_bytes) == dict:
        if isinstance(pkt_bytes, dict):
            self.check(pkt_bytes)
            pkt_bytes = self.build(**pkt_bytes)
        if len(pkt_bytes) < HEADER_LEN:
            print("Not enough bytes, cannot parse LURK Header")
            print("Expecting %s, got %s"%(HEADER_LEN, len(pkt_bytes)))
            print("pkt_bytes: %s"%pkt_bytes)
        else:
            print(indent("%s"%self.struct.parse(pkt_bytes[:HEADER_LEN]), \
                       prefix))
            header = self.struct.parse(pkt_bytes[: HEADER_LEN])
            if len(pkt_bytes) >= header['length']:
                payload_bytes = pkt_bytes[HEADER_LEN : header['length']]
            else:
                raise InvalidFormat((header, pkt_bytes), \
                          "pkt_bytes too short %s bytes"%len(pkt_bytes))
            if header['status'] in ["success", "request"]:

                self.show_ext_payload(header, payload_bytes, \
                               prefix=prefix, line_len=line_len)
            else: ## the payload is an error payload
                LURKErrorPayload.parse(payload_bytes)


class LurkServer():
    """ Basic Lurk Server

    This server takes bytes as input and returns bytes. It does not
    provides any transport such as UDP, TCP. These transport layers are
    left to dedicated servers.
    """
    def __init__(self, conf=deepcopy(default_conf)):
        """ Initiates the Lurk Server
        
        Args:
            conf (dict): the configuration of teh server. Default value
                is default_conf.
        """
        self.init_conf(conf)
        self.conf = LurkConf(conf)
        self.conf.set_role('server')
        self.message = LurkMessage(conf=self.conf.conf)

    def init_conf(self, conf):
        """ Provides minor changes to conf so the default conf can be used

        Args:
            conf (dict): the dictionary representing the configuration
                arguments

        Returns:
            conf (dict): the updated conf dictionary
        """
        conf['role'] = 'server'
        return conf


    def byte_serve(self, pkt_bytes):
        """ read the HEADER_LEN bytes of pkt_bytes. If an error occurs, it
        associated to the errors encountered by reading the payload part.
        """
        response_bytes = b''
        while len(pkt_bytes) >= HEADER_LEN:
            try:
                request = self.message.parse(pkt_bytes)
                response = self.message.serve(request)
                response_bytes += self.message.build(**response)
                pkt_bytes = pkt_bytes[request['length'] :]
            except:
                ## stop when an error is encountered
                return response_bytes
        return response_bytes



MAX_ATTEMPTS = 10

class LurkBaseClient:
    """ Basis Lurk Client

    This class provides the interface for all specific clients. Client
    usually interacts with a server so the basic client sets some
    communications with the server using sockets. The reason for
    integrating some communication is that UDP/TCP communications shares
    quite a lot of functionalities. 

    Clients are more complex than servers, as they are stateful and need
    to coordinate the response and the request. Different kind of client
    are invisionned (stub resolver, resolver, ...)
    """
    def __init__(self, conf, resolver_mode='stub'):
        """ Initiates the Lurk CLient
        
        Args:
            conf (dict): the dictionary representing the configuration
                arguments
            resolver_mode (str): the type of resolver 
        """
        self.conf = LurkConf(conf)
        self.resolver_mode = resolver_mode
        self.server_address = self.conf.get_server_address()
        self.connection_type = self.conf.get_connection_type()
        self.message = LurkMessage(conf=self.conf.get_conf())
        if self.connection_type is not 'local': 
            self.set_up_server_session()
            self.selector = selectors.DefaultSelector()
            self.selector.register(fileobj=self.sock, \
                               events=selectors.EVENT_READ, \
                               data="accept")


    def init_conf(self, conf):
        """ Provides minor changes to conf so the default conf can be used

        Args:
            conf (dict): the dictionary representing the configuration
                arguments

        Returns:
            conf (dict): the updated conf dictionary
        """
        self.conf.set_role('client')
        self.conf_check_conf()

    def conf_check(self):
        """ Checks configuration
        """

    def unpack_bytes(self, bytes_pkt):
        """splits concatenation of lurk message

        bytes_request can be the concatenation of one or multiple
        requests. This function lists the each individual request. This
        is used to define later if all requests have been answered.

        Args:
            bytes_pkt (bytes): one or a concatenation of one or multiple
            packets in a byte format. packets can be requests or responses.

        Returns:
            pkt_bytes_dict (dict): a dictionary of every subpackets
                indexed with their id {pkt['id']: pkt}
        """
        bytes_pkt_dict = {}
        while len(bytes_pkt) != 0:
            header = LURKHeader.parse(bytes_pkt)
            bytes_nbr = HEADER_LEN + header['length']
            bytes_pkt_dict[header['id']] = bytes_pkt[: bytes_nbr]
            bytes_pkt = bytes_pkt[bytes_nbr :]
        return bytes_pkt_dict


    def set_up_server_session(self):
        """ Sets a session with the server 
        """
        if self.connection_type in ['tcp', 'tcp+tls', 'http', 'https']:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif self.connection_type in ['udp', 'udp+dtls']:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if self.resolver_mode == 'resolver':
            self.sock.setblocking(False)
        else:
            self.sock.setblocking(True)
        if self.connection_type in ['tcp+tls', 'https']:
            context = self.conf.get_tls_context()
            self.sock = context.wrap_socket(self.sock, server_side=False,\
                            do_handshake_on_connect=False,\
                            server_hostname=self.server_address[0])
        attempt_nbr = 0
        error_nbr = -1
        while attempt_nbr <= MAX_ATTEMPTS:
            error_nbr = self.sock.connect_ex(self.server_address)
            if error_nbr == 0:
                break
            error_str = errno.errorcode[error_nbr]
            print("Connecting tcp socket (%s): %s, %s"%\
                      (error_nbr, error_str, \
                       os.strerror(error_nbr)))
            if error_str == 'EISCONN':
                break
            if error_str == 'ECONNREFUSED':
                ImplementationError(self.sock, "Cannot CONNECT")
            attempt_nbr += 1
            if attempt_nbr == MAX_ATTEMPTS:
                raise ImplementationError(attempt_nbr, "TCP connection" +\
                      "attempts exceeds MAX_ATTEMPTS " +\
                      "= %s"%MAX_ATTEMPTS +\
                      "TCP session not established")
        if self.connection_type == 'tcp+tls':
            attempt_nbr = 0
            error_nbr = -1
            while attempt_nbr <= MAX_ATTEMPTS:
                try:
                    attempt_nbr += 1
                    self.sock.do_handshake()
                    break
                except ssl.SSLError as err:
                    if err.args[0] == ssl.SSL_ERROR_WANT_READ:
                        select([self.sock], [], [], 5)
                    elif err.args[0] == ssl.SSL_ERROR_WANT_WRITE:
                        select([], [self.sock], [], 5)
                    else:
                        raise
                if attempt_nbr == MAX_ATTEMPTS:
                    raise ImplementationError(attempt_nbr, "TLS Handshake" +\
                          "attempts exceeds MAX_ATTEMPTS " +\
                          "= %s"%MAX_ATTEMPTS +\
                          "TLS session not established")

    def closing(self):
        """ Closing the connection

        """
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()

    def resolve(self, request_list):
        """ Resolve a list of requests

        Selects the appropriated resolver according to the expected
        resolver type and proceeds accordingly to teh resolution of 
        a list of request. In fact, a byte stream may be composed of 
        the concatenation of multiple requests.

        Args:
            request_list (list): contains a list of requests. Each
                request is represented by a dictionary. The dictionary 
                contains the element necessary to build the LURK request. 
                Missing are derived from default values. Each dictionary
                is taken as a **kwargs to build the associated request
        Returns:
            resolutions_list (list): the list of (request, repsonse).
                request and response are represented as dictionaries.
            error_list (list): the list of non resolved requested.
        """
        if self.resolver_mode == 'stub':
            return self.stub_resolve(request_list)
        elif self.resolver_mode == 'resolver':
            return self.resolver_resolve(request_list)
        else:
            raise ConfError(resolver_mode, "Unexpected value for " +\
                            "resolver_mode. Expected values are " +\
                            "'stub' or 'resolver'")

    def resolver_resolve(self, request_list):
        """ Resolve with a list of payloads

        The code is based on non blocking sockets and is intended to
        read and write simultaneously on the same socket.

        Todo:
            The resolver function is not finished and the code is only
            there as a starting point for a resolver. Invoking select
            resulted in poor performances for a single
            resolution.

        Args:
            request_list (list): contains a list of requests. Each
                request is represented by a dictionary. The dictionary contains
                the element necessary to build the LURK request. Missing
                are derived from default values. Each dictionary
                is taken as a **kwargs to build the associated request

        Returns:
            resolutions_list (list): the list of (request, repsonse).
                request and response are represented as dictionaries.
            error_list (list): the list of non resolved requested.
        """
        bytes_requests = b''
        for input_request in request_list:
##            print(" --- resolve : input_request: %s"%input_request)
            request = self.message.build_payload(**input_request)
            bytes_requests += self.message.build(**request)
        bytes_resolutions, bytes_errors = self.bytes_resolve(bytes_requests)
        resolutions_list = []
        for resol in bytes_resolutions:
            resolutions_list.append((self.message.parse(resol[0]), \
                                     self.message.parse(resol[1])))
        errors_list = []
        for error in bytes_errors:
            errors_list.append(self.message.parse(error))
        return resolutions_list, errors_list


    def bytes_resolver_resolve(self, bytes_request):
        """ sends bytes_request and returns bytes_responses

        Takes the bytes_requests and evaluate whether their is one
        request or multiple requests and builds an dictionnary
        {id:bytes_request}. This dictionary is latter used to determine
        if all queries have been answered.


        The code is based on non blocking sockets and is intended to
        read and write simultaneously on the same socket.

        Todo:
            The resolver function is not finished and the code is only
            there as a starting point for a resolver. Invoking select
            resulted in poor performances for a single
            resolution.

        Args:
            bytes_request (bytes): the request in byte format. This can
                include a single request or a serie of concatenated
                requests in byte format.

        Returns:
            bytes_resolutions (lst): list of (bytes_response,
                bytes_request) elements where bytes_request the requests
                included in bytes_request and bytes_responses the
                corresponding responses. Typically
        """
        self.bytes_send(bytes_request)
        bytes_requests_dict = self.unpack_bytes(bytes_request)
        bytes_responses = self.bytes_receive(bytes_requests_dict)
        bytes_responses_dict = self.unpack_bytes(bytes_responses)
        bytes_resolutions = []
        bytes_errors = []
        for req_id in bytes_requests_dict.keys():
            try:
                bytes_resolutions.append((bytes_requests_dict[req_id], \
                                      bytes_responses_dict[req_id]))
            except KeyError:
                ## including void responses, i.e not provided by the
                ## server
                ##bytes_resolutions.append((bytes_requests_dict[req_id],b''))
                bytes_errors.append(bytes_requests_dict[req_id])
        return bytes_resolutions, bytes_errors

    def stub_resolve(self, request_list):
        """ Resolve wit ha list of payloads

        Args:
            request_list (list): contains a list of requests. Each
                request is represented by a dictionary. The dictionary contains
                the element necessary to build the LURK request. Missing
                are derived from default values. Each dictionary
                is taken as a **kwargs to build the associated request

        Returns:
            resolutions_list (list): the list of (request, repsonse).
                request and response are represented as dictionaries.
            error_list (list): the list of non resolved requested.
        """
        bytes_requests = b''
        for input_request in request_list:
##            print(" --- resolve : input_request: %s"%input_request)
            request = self.message.build_payload(**input_request)
            bytes_requests += self.message.build(**request)
        bytes_resolutions, bytes_errors = self.bytes_stub_resolve(bytes_requests)
        resolutions_list = []
        for resol in bytes_resolutions:
            resolutions_list.append((self.message.parse(resol[0]), \
                                     self.message.parse(resol[1])))
        errors_list = []
        for error in bytes_errors:
            errors_list.append(self.message.parse(error))
        return resolutions_list, errors_list

    def bytes_stub_resolve(self, bytes_request):
        """ Simple resolution in blocking mode

            Implements a stub resolver
        """
        sent_status = self.sock.sendall(bytes_request)
        if sent_status != None:
            print("Not all data (%s) has been sent: %s"(len(bytes_request), \
                                   binascii.hexlify(bytes_request)))
            bytes_resolutions = []
            bytes_errors = [bytes_request]
        else:
            bytes_response = self.sock.recv(4096)
            bytes_resolutions = [(bytes_request, bytes_response)]
            bytes_errors = []
        return bytes_resolutions, bytes_errors

    def is_response(self, bytes_response, bytes_requests_dict):
        """ Match bytes against expected responses
      
        Match bytes_response to bytes_request_dict and returns True is
        the bytes_response corresponds to an expected response, 
        False otherwise.

        Args:
            bytes_response (bytes): bytes corresponding to a response
            bytes_request_dict (dict): dictionary of bytes_requests
                indexed by their id. 

        Returns:
            True is the response matches a request, False otherwise.
        """
        if bytes_requests_dict == None:
            return True
        ## server does not respond
        if bytes_response == b'':
            return True
        try:
            header_response = LURKHeader.parse(bytes_response)
            header_request = LURKHeader.parse(bytes_requests_dict[\
                                 header_response['id']])
            for key in ['designation', 'version', 'type']:
                if header_request[key] != header_response[key]:
                    return False
            if header_response['status'] == 'request':
                return False
            return True

        except KeyError:
            return False

    def bytes_send(self, bytes_request):
        """ sending bytes_pkt bytes

        """
        rlist, wlist, xlist = select([], [self.sock], [])
        sent_status = self.sock.sendall(bytes_request)
##        if sent_status == None:
##            print("bytes_request sent (%s): %s"%(len(bytes_request), \
##                                             binascii.hexlify(bytes_request)))
##        else:
        if sent_status != None:
            print("Not all data (%s) has been sent: %s"(len(bytes_request), \
                                   binascii.hexlify(bytes_request)))

class LurkUDPClient(LurkBaseClient):

    def bytes_receive(self, bytes_requests_dict=None):
        """ receiving response_nbr packets

        The main difference between the UDP and TCP is that recv read
        the full buffer in UDP. As a result, this function reads the
        full buffer and does not red progressively the responses. responses that
        are missing will never be received.

        A response may be composed of multiple UDP packets. This case is
        not handled by the UDPClient.

        Args:
            bytes_Requests_dict (dict): the dictionary that associated
                to the id the byte representation of the request (bytes_request)
                {id : bytes_request}
        Returns:
            bytes_response (bytes): the corresponding bytes_responses.
                When bytes_requests is composed of multiple bytes_request
                concatenated, the responses are concatenated as well.
        """
        bytes_responses = b''
        if bytes_requests_dict == None:
            response_nbr = 1
        else:
            response_nbr = len(bytes_requests_dict.keys())
        rlist, wlist, xlist = select([self.sock], [], [], 5)
        if len(rlist) == 0:
            return bytes_responses
        bytes_pkt = self.sock.recv(4096)
        ## make sure, there is a correct number of bytes
        while len(bytes_pkt) >= HEADER_LEN:
            try:
                bytes_nbr = HEADER_LEN + LURKHeader.parse(bytes_pkt)['length']
                bytes_response = bytes_pkt[: bytes_nbr]
                if self.is_response(bytes_response, bytes_requests_dict) is False:
                    continue
                bytes_responses += bytes_response
                bytes_pkt = bytes_pkt[bytes_nbr :]
            except:
                break
        return bytes_responses

"""
From https://docs.python.org/3.5/library/socketserver.html:

Creating a server requires several steps. First, you must create a request handler class by subclassing the BaseRequestHandler class and overriding its handle() method; this method will process incoming requests. Second, you must instantiate one of the server classes, passing it the server’s address and the request handler class. Then call the handle_request() or serve_forever() method of the server object to process one or many requests. Finally, call server_close() to close the socket.

When inheriting from ThreadingMixIn for threaded connection behavior, you should explicitly declare how you want your threads to behave on an abrupt shutdown. The ThreadingMixIn class defines an attribute daemon_threads, which indicates whether or not the server should wait for thread termination. You should set the flag explicitly if you would like threads to behave autonomously; the default is False, meaning that Python will not exit until all threads created by ThreadingMixIn have exited.
"""
class BaseUDPServer(UDPServer):

    def __init__(self, lurk_conf, RequestHandlerClass):
        self.conf = LurkConf(deepcopy(lurk_conf))
        self.lurk = LurkServer(self.conf.get_conf())
        self.server_address = self.conf.get_server_address()
        self.connection_type = self.conf.get_connection_type()
        super().__init__(self.server_address, RequestHandlerClass)

    def byte_serve(self, data):
        return self.lurk.byte_serve(data)


class ThreadedUDPServer(ThreadingMixIn, BaseUDPServer):
    pass

class UDPHandle(BaseRequestHandler):
    """
    """

    def handle(self):
        """ treat the request
        From https://docs.python.org/3.5/library/socketserver.html

	This function must do all the work required to service a
        request. The default implementation does nothing. Several
        instance attributes are available to it; the request is
        available as self.request; the client address as
        self.client_address; and the server instance as self.server,
        in case it needs access to per-server information.

        The type of self.request is different for datagram or stream
        services. For datagram services, self.request is a pair of
        string and socket.
        """
        data = self.request[0]
        socket = self.request[1]
        socket.sendto(self.server.byte_serve(data), self.client_address)

class LurkUDPServer:

    def __init__(self, conf=deepcopy(default_conf), thread=True):
        if thread is False:
            self.server = BaseUDPServer(conf, UDPHandle)
        else:
            self.server = ThreadedUDPServer(conf, UDPHandle)
        self.server.serve_forever()

class PoolMixIn(ThreadingMixIn):
    pass


## interesting links on TCP sockets:
## https://www.scottklement.com/rpg/socktut/tutorial.html
## https://docs.python.org/3/howto/sockets.html
## https://docs.python.org/3/library/socket.html
## https://docs.python.org/3/library/socketserver.html
## https://docs.python.org/3/library/ssl.html#ssl.SSLContext.wrap_socket
## https://github.com/eliben/python3-samples/blob/master/async/selectors-async-tcp-server.py
## https://hg.python.org/cpython/rev/b763c1ba5589

class BaseTCPServer(TCPServer):

    def __init__(self, lurk_conf, RequestHandlerClass):
        """Basic TCP Server

        The main difference with the TCPServer class is that TCPServer
        class accepts a TCP session for a request, process the request
        and close the TCP session. The advantage is that it prevents
        management or tracking of unused TCP session with a timeout
        for example. The downside is that it also rpevents a TCP
        session to be used for multiple requests.

        This class modify the TCPServer class by 1) not shuting down and
        closing the socket after the initial request has been treated by
        the RequestHandlerClass. 2) listen to events happening on the
        listening socket (self.socket) as well as those accepted sockets
        (self.accept()). The latest are used when further requests are
        sent over the established TCP session. 3) sockets needs to be
        managed and eventually closed when timeout occurs.

        """
        self.conf = LurkConf(deepcopy(lurk_conf))
        self.lurk = LurkServer(self.conf.get_conf())
        self.server_address = self.conf.get_server_address()
        self.connection_type = self.conf.get_connection_type()
        self.allow_reuse_address = True
        super().__init__(self.server_address, RequestHandlerClass)
#        if self.connection_type == 'tcp+tls':
#            context = self.conf.get_tls_context()
#            self.socket = context.wrap_socket(self.socket, server_side=True)
        self.selector = selectors.DefaultSelector()
        self.selector.register(fileobj=self.socket, \
                               events=selectors.EVENT_READ, \
                               data="accept")
        self.fd_timeout = 3600
        self.fd_time = {}

        self.fd_busy = {}

    def byte_serve(self, data):
        return self.lurk.byte_serve(data)

    def shutdown_request(self, request):
        """ actions after the RequestHandlerClass is called.

        TCPServer closes the socket used by the handler. This results in
        having socket being used for a single transaction. As we are
        looking to be able to re-use a socket that has been accepted
        for further transactions, the socket needs to be left open.
        The current function prevents shutingdown and closing the socket.

        Args:
            request: a socket object.
        """
        pass


    def serve_forever(self, poll_interval=None):
        """ serves incoming request

        This function listen to events on the listening socket
        (self.socket) as well as other sockets associated to accepted
        communications (sock = self.sock.accept()).

        The main difference with the original function is the original
        function only listened to events on the main socket (self.socket).
        As a result, even though (self.shutdown_request) does not close
        or shutdown the socket used for the transaction (sock), further
        communications using this socket are not possible. Events happening
        on the socket - typically incoming packets - are just ignored.
        The results in the situation where only the initial requests
        provided at the creation of the socket are responded, other
        are not treated.
        """
        print("staring serve_forever")
        self._BaseServer__is_shut_down.clear()
        previous_time = 0
        try:
            while not self._BaseServer__shutdown_request:
                events = self.selector.select(poll_interval)
                for selector_key, event in events:
                    if self._BaseServer__shutdown_request:
                        break
                    try:
                        self.fd_busy[selector_key.fileobj.fileno()]
                    except KeyError:
                        self._handle_request_noblock(selector_key, event)
                        self.service_actions()
                current_time = time()
                if current_time - previous_time > 1:
                    previous_time = current_time
                    for fd in self.selector.get_map():
                        key = self.selector._fd_to_key[fd]
                        try:
                            delta_time = current_time - self.fd_time[fd]
                            if delta_time > self.fd_timeout and key.data == 'establish':
                                self.close_request(key.fileobj)
                        except KeyError as e:
                            ## time of self.socket is not monitored
                            ## while it triggers events
                            continue
        finally:
            self._BaseServer__shutdown_request = False
            self._BaseServer__is_shut_down.set()

    def _handle_request_noblock(self, selector_key, event):

        try:
            request, client_address = self.get_request(selector_key, event)
        except OSError:
            return
        if self.verify_request(request, client_address):
            try:
                self.process_request(request, client_address)
            except Exception:
                self.handle_error(request, client_address)
                self.shutdown_request(request)
            except:
                self.shutdown_request(request)
                raise
        else:
            self.shutdown_request(request)


    def get_request(self, selector_key, event):
        """Provides connectivity information to the RequestHandlerClass

        Returns the appropriated socket (request) and address
        (client_address) to the RequestHandlerClass. The parameters are
        passed via the finish_request method.
        serve_forever() --> _handle_request_noblock() -->
        process_request(self, request, client_address) -->
        finish_request(self, request, client_address)

        Args:
           selector_key: SelectorKey object (fileobj, fd, events, data).
               It is returned by the selector.select()
           event:
        """
        if selector_key.data == "accept":
            request, client_address = self.socket.accept()
            request.setblocking(False)
            if self.connection_type == 'tcp+tls':
                context = self.conf.get_tls_context()
                request = context.wrap_socket(request, server_side=True,\
                                              do_handshake_on_connect=False)
            self.selector.register(fileobj=request, \
                                   events=selectors.EVENT_READ,\
                                   data="establish")
        elif selector_key.data == "establish":
            request = selector_key.fileobj
            client_address = request.getpeername()
        self.fd_time[request.fileno] = time()
        return request, client_address

    def close_request(self, request):
        self.selector.unregister(request)
        request.close()

class ThreadedTCPServer(ThreadingMixIn, BaseTCPServer):
    pass

class TCPHandle(BaseRequestHandler):
    """
    """

    def handle(self):
        """ treat the request
        From https://docs.python.org/3.5/library/socketserver.html

	This function must do all the work required to service a
        request. The default implementation does nothing. Several
        instance attributes are available to it; the request is
        available as self.request; the client address as
        self.client_address; and the server instance as self.server,
        in case it needs access to per-server information.

        The type of self.request is different for datagram or stream
        services.  For stream services, self.request is a socket object.


        """
        try:
            self.server.fd_busy[self.request.fileno()]
            return
        except KeyError:
            self.server.fd_busy[self.request.fileno()] = time()

        try:
            bytes_recv = self.request.recv(HEADER_LEN)
        except:
            del self.server.fd_busy[self.request.fileno()]
            return
        if bytes_recv == b'':
            return
        header = LURKHeader.parse(bytes_recv)
        bytes_nbr = header['length']

        while len(bytes_recv) < bytes_nbr:
            try:
                bytes_recv += self.request.recv(min(bytes_nbr - len(bytes_recv), 1024))
            except ssl.SSLError as err:
                if err.args[0] == ssl.SSL_ERROR_WANT_READ:
                    select([self.request], [], [])
                elif err.args[0] == ssl.SSL_ERROR_WANT_WRITE:
                    select([self.request], [], [])
                else:
                    raise
            except BlockingIOError:
                select([self.request], [], [], 5)
        attempt_nbr = 0
        while attempt_nbr <= MAX_ATTEMPTS:
            try:
                self.request.sendall(self.server.byte_serve(bytes_recv))
                break
            except ssl.SSLError as err:
                if err.args[0] == ssl.SSL_ERROR_WANT_WRITE:
                    select([], [self.request], [])
                else:
                    raise
            except BlockingIOError:
                select([], [self.request], [])
            if attempt_nbr == MAX_ATTEMPTS:
                return
                raise ImplementationError(attempt_nbr, "Reading Header" +\
                      "attempts exceeds MAX_ATTEMPTS " +\
                      "= %s"%MAX_ATTEMPTS +\
                      "Lurk Header not read")
        del self.server.fd_busy[self.request.fileno()]
        return

class LurkTCPServer:

    def __init__(self, conf=deepcopy(default_conf), thread=True):
        if thread is False:
            self.server = BaseTCPServer(conf, TCPHandle)
        else:
            self.server = ThreadedTCPServer(conf, TCPHandle)
        self.server.serve_forever()


class LurkTCPClient(LurkBaseClient):

    def bytes_receive(self, bytes_requests_dict=None):
        """ receiving response_nbr packets

        Args:
            bytes_Requests_dict (dict): the dictionary that associated
                to the id the byte representation of the request (bytes_request)
                {id : bytes_request}
        Returns:
            bytes_response (bytes): the corresponding bytes_responses.
                When bytes_requests is composed of multiple bytes_request
                concatenated, the responses are concatenated as well.
        """
        bytes_responses = b''
        if bytes_requests_dict == None:
            response_nbr = 1
        else:
            response_nbr = len(bytes_requests_dict.keys())
        while response_nbr > 0:
            bytes_response = self.bytes_receive_single_response()
            if self.is_response(bytes_response, bytes_requests_dict) is False:
                continue
            bytes_responses += bytes_response
            response_nbr -= 1
        return bytes_responses

    def bytes_receive_single_response(self):
        bytes_recv = b''
        while len(bytes_recv) < HEADER_LEN:
            rlist, wlist, xlist = select([self.sock], [], [])
            if len(rlist) > 0:
                bytes_recv = self.sock.recv(HEADER_LEN)
        header = LURKHeader.parse(bytes_recv)
        bytes_nbr = header['length']

        bytes_recv += self.sock.recv(min(bytes_nbr - len(bytes_recv), 4096))
        return bytes_recv


class LurkHTTPServer:

    def __init__(self, conf=deepcopy(default_conf), thread=True):
        if thread is False:
            self.server = BaseHTTPServer(conf, HTTPHandle)
        else:
            self.server = ThreadedHTTPServer(conf, HTTPHandle)
        self.server.serve_forever()


class  BaseHTTPServer(HTTPServer):
    '''
    This class represnts and HTTPS server having LurkServer and HTTPServer functionality
    '''
    def __init__(self, lurk_conf, RequestHandlerClass):
        self.conf = LurkConf(deepcopy(lurk_conf))
        self.lurk = LurkServer(self.conf.get_conf())
        self.server_address = self.conf.get_server_address()
        self.connection_type = self.conf.get_connection_type()
        super().__init__(self.server_address, RequestHandlerClass)
        self.allow_reuse_address = True
        HTTPServer.__init__(self, self.server_address, RequestHandlerClass)

        if self.connection_type == 'https':
            context = self.conf.get_tls_context()
            self.socket = context.wrap_socket(self.socket, server_side=True)


class ThreadedHTTPServer(ThreadingMixIn, BaseHTTPServer):
    pass

class HTTPHandle(BaseHTTPRequestHandler):
    '''
    This class handles HTTP GET and HTTP POST requests
    '''
    def do_GET(self):
        '''
        This method handles get requests by the client
        Currently not used and implemented with basic response
        :return:
        '''
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Successfull GET request and response ')

    def do_POST(self):
        '''
        This method handles the post requests
        :return:
        '''

        # get the length of the data sent by the client
        content_length = int(self.headers['Content-Length'])

        # read the data sent by the client before sending any response
        data = self.rfile.read(content_length)

       # send response
        self.send_response(200)
        self.end_headers()
        self.server.lurk.byte_serve(data)
        #send the response bytes to the client
        self.wfile.write(self.server.lurk.byte_serve(data))

    def log_message(self, format, *args):
        pass

class LurkHTTPClient(LurkTCPClient):

    def __init__(self, conf, resolver_mode='stub'):
        self.conf = LurkConf(conf)
        self.resolver_mode = resolver_mode
        self.server_address = self.conf.get_server_address()
        self.connection_type = self.conf.get_connection_type()
        self.message = LurkMessage(conf=self.conf.get_conf())
        self.pending_resp = []

    def set_up_server_session(self):
        pass

    def closing(self):
        """ Closing the connection

        """
        self.pending_resp = []


    def bytes_stub_resolve(self, bytes_request):
        """ Simple resolution in blocking mode

            Implements a stub resolver
        """
        url = self.connection_type + '://' + str(self.server_address[0]) + \
                                     ':' + str(self.server_address[1])
        req = urllib.request.Request(url, bytes_request, method='POST')

        if self.connection_type == 'https':
            tls_context = self.conf.get_tls_context()
        else:
            tls_context = None

        resp = urllib.request.urlopen(req, context=tls_context)
        bytes_response = b''
        bytes_response = bytes_response + resp.read(4096)
        bytes_resolutions = [(bytes_request, bytes_response)]
        bytes_errors = []
        return bytes_resolutions, bytes_errors


    def bytes_send(self, bytes_request):
        """ sending bytes_pkt bytes

        """
        url = self.connection_type + '://' + str(self.server_address[0]) + \
                                     ':' + str(self.server_address[1])
        req = urllib.request.Request(url, bytes_request, method='POST')

        if self.connection_type == 'https':
            tls_context = self.conf.get_tls_context()
        else:
            tls_context = None

        resp = urllib.request.urlopen(req, context=tls_context)
        self.pending_resp.append(resp)

    def  bytes_receive(self, bytes_requests_dict=None):
        for resp_index in range(len(self.pending_resp)):
            resp = self.pending_resp[resp_index]
            response_bytes = b''
            response_bytes = response_bytes + resp.read(4096)
        return response_bytes
