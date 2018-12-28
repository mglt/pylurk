"""
We need to provide an explaination on how to add a new extension. 

"""
import os
from  os.path import join
import pkg_resources
from textwrap import indent
from secrets import randbits
from Cryptodome.Hash import HMAC, SHA256
from pylurk.core.conf import default_conf
from pylurk.core.lurk_struct import *
from socketserver import ThreadingMixIn, UDPServer, TCPServer, BaseRequestHandler
from concurrent.futures import ThreadPoolExecutor
from http.server import HTTPServer,  BaseHTTPRequestHandler

import socket
from socket import error as SocketError
from time import time

import selectors
from select import select
import errno
import urllib.request
import ssl
import binascii

import threading
HEADER_LEN = 16 
LINE_LEN = 60

data_dir = pkg_resources.resource_filename( __name__, '../data/')

def wrap( text, line_len=LINE_LEN):
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
#        print("line: %s"%line )
        if len( line ) < line_len:
            wrap += line
            wrap += '\n'
            continue
        margin = "    "
        for c in line:
            if c.isspace():
                margin += c
            else:
                break
        wrap += line[ : line_len ] + '\n'
        line = margin + line[ line_len :]
#        print("    init wrap: %s"%wrap )
#        print("    init line: %s"%line )
        while len( line ) >= line_len:
            wrap += line[ : line_len ] + '\n'
            line = margin + line[ line_len : ]
#            print("    wrap: %s"%wrap )
#            print("    line: %s"%line )
        wrap += line[:]
        wrap += '\n'
#        print("    final wrap: %s"%wrap )
    return wrap



class Error(Exception):
    def __init__(self, expression, message):
        self.expression = expression
        self.message = message
        self.status = None

## system error
class ConfError(Error):
    pass
class ImplementationError(Error):
    pass


## LURK Error
class UndefinedError(Error):
    def __init__(self, expression, message):
        super().__init__(expression, message )
        self.status = "undefined_error"
class InvalidFormat(Error):
    def __init__(self, expression, message):
        super().__init__(expression, message )
        self.status = "invalid_format"
class InvalidExtension(Error):
    def __init__(self, expression, message):
        super().__init__(expression, message )
        self.status = "invalid_extension"
class InvalidType(Error):
    def __init__(self, expression, message):
        super().__init__(expression, message )
        self.status = "invalid_type"
class InvalidStatus(Error):
    def __init__(self, expression, message):
        super().__init__(expression, message )
        self.status = "invalid_status"
class TemporaryFailure(Error):
    def __init__(self, expression, message):
        super().__init__(expression, message )
        self.status = "temporary_failure"


class LocalServerConf:
    def __init__( self):
        pass

class UDPServerConf:
    def __init__( self, conf=default_conf[ 'connectivity' ] ):
        self.keys = [ 'type', 'ip_address', 'port', 'keys', 'certs' ]
        self.check_key( conf )
        self.ip_address = conf[ 'ip_address' ]
        self.port = conf[ 'port' ]
        self.tls_keys = conf['keys']
        self.tls_certs = conf['certs']
## mglt: maybe we should check role and transport here. 
## I am also wandering if that should not be a function 
## associated to the LurkConf() rather than a class.

    def check_key( self, conf ):
        if set( conf.keys() ) != set( self.keys ) :
            raise ConfError( conf, "Expected keys: %s"%self.keys )

class TCPServerConf(UDPServerConf):pass
class HTTPServerConf(TCPServerConf):pass #will extend TCP since HTTP is based on TCP

class LurkConf():

    def __init__(self, conf=default_conf ):
        self.check_conf( conf )
        self.conf = conf 
        self.role = self.conf[ 'role' ]
        self.supported_extensions = self.get_supported_ext( ) 
        # message type supported by the server#        
        self.mtype = self.get_mtypes( )
        self.server = self.get_server( )
        
    ### functions dealing with configuration provided to init

    def check_conf(self, conf ):
        if type( conf ) is not dict:
            raise ConfError( conf, "Expecting dict" )
        self.check_key( conf, [ 'role', 'connectivity', 'extensions' ] )
        if conf[ 'role' ] not in [ 'client', 'server' ]:
            raise ConfError( conf['role' ], "Expecting role as 'client' " + \
                                            "or 'server'" )
        connectivity = conf[ 'connectivity' ]
        if connectivity[ 'type' ] not in [ "local", "udp", "tcp", "http" ]:
            raise ConfError( connectivity, "Expected type as 'local' "+\
                                            "or 'udp' or 'tcp' or 'http'" )
        if type( conf[ 'extensions' ] ) is not list:
            raise ConfError( conf[ 'connectivity' ], "Expected 'list'")
        id_bytes = randbits(8)
        for ext in conf[ 'extensions' ]:
            ## validation between of ( 'designation', 'version', 'type'
            ## is tested by building a LURKHeader
            try:
                LURKHeader.build( { 'designation' : ext[ 'designation' ],
                                    'version' : ext[ 'version' ],
                                    'type' : ext[ 'type' ],
                                    'status' : "request",
                                    'id' : id_bytes,
                                    'length' : HEADER_LEN } )
            except :
                raise ConfError( ext, "Unexpected values for designation, " +\
                                      "version type" )

## mglt: I think that get is unclear. maybe list is more appropriated. 
    def get_mtypes( self ):
        """ returns the list of types associated to each extentions
             { ( designation_a, version_a) : [ type_1, ..., type_n ],
               ( designation_n, version_n) : [ type_1, ..., type_n ] }
        """

        mtype = {}
        id_bytes = randbits(8)
        for ext in self.conf[ 'extensions' ]:
            k = ( ext[ 'designation' ], ext[ 'version' ] )
            try:
                if ext[ 'type' ] not in mtype[ k ]:
                    mtype[ k ].append( ext[ 'type' ] )
            except KeyError:
                mtype[ k ] = [ ext[ 'type' ] ]
        return mtype


    def get_supported_ext( self ):
        """ returns the list of extensions 
          [ ( designation_a, version_a ), ... (designation_n, version_n ) ] 
        """
        sup_ext = []
        for extension in self.conf[ 'extensions' ]:
            ext = ( extension[ 'designation' ], extension[ 'version' ] )
            if ext not in sup_ext:
                sup_ext.append( ext )
        return sup_ext

    def get_ext_conf( self, designation, version, \
            exclude=[ 'designation', 'version', 'type' ] ):
        """ returns the configuration associated to an extension.
            conf = { 'role' : "server" 
                      'ping' : [  []. ...  [] ], 
                     'rsa_master' : [ { conf1_rsa }, { conf2_rsa }, ... ] }
        """
        conf = {}
        ## conf[ 'role' ] = self.conf[ 'role' ]
        type_list = []
        for ext in self.conf[ 'extensions' ] :
            if ext[ 'designation' ] == designation and \
               ext[ 'version' ] == version :
                type_list.append( ext[ 'type' ] )
        type_list = list( set( type_list ) )
        for mtype in type_list:
            conf[ mtype ] = self.get_type_conf( designation, version, \
                                mtype, exclude=exclude )
        return conf  

    def get_type_conf( self, designation, version, mtype, \
            exclude=['designation', 'version', 'type'] ):
         """ returns the configuration parameters associated to a given
             type. It has the 'role' value and removes parameters value 
             provided by exclude.  """
         type_conf = []
         for ext in self.conf[ 'extensions' ] :
             if ext[ 'designation' ] == designation and \
                ext[ 'version' ] == version and \
                ext[ 'type' ] == mtype:
                 conf = dict( ext )
                 conf[ 'role' ] =  self.conf[ 'role' ]
                 for k in exclude:
                     if k in conf.keys():
                         del conf[ k ]
                 type_conf.append( conf )
         return type_conf

## mglt: we should probably have somthing simplier without classes.
    def get_server( self ):
        con = self.conf[ 'connectivity' ]
        if con[ 'type' ] == "local" :
            return LocalServerConf( )
        if con[ 'type' ] == "udp" :
            return UDPServerConf( conf=con )
        if con[ 'type' ] == "tcp" :
            return TCPServerConf( conf=con )
        if con['type'] == "http":
            return HTTPServerConf(conf=con)

    def set_role( self, role ):
        if role not in [ 'client', 'server' ]:
            raise ConfError( role, "Expected 'client' or 'server'" )
        self.conf[ 'role' ] = role

    def set_connectivity( self, **kwargs ):
        if 'type' not in kwargs:
            raise ConfError( kwargs, "Expecting key 'type' " )
        if kwargs[ 'type' ] == "local":
            self.conf[ 'connectivity' ] = { 'type' : "local" }
        elif kwargs[ 'type' ] == "udp":
            con = {}
            con[ 'type' ] = 'local'
            if 'ip_address' in kwargs.keys():
                ip =  kwargs[ 'ip_address' ]
            else: 
                ip = "127.0.0.1"
            if 'port' in kwargs.keys():
                port = kwargs[ 'port' ]
            else: 
                port = 6789
            if 'keys' in kwargs.keys():
                keys = kwargs[ 'keys' ]
            else:
                keys = {
                    'client': join( data_dir, 'key_tls12_rsa_client.key'),
                    'server': join( data_dir, 'key_tls12_rsa_server.key'),
                }
            if 'certs' in kwargs.keys():
                certs = kwargs ['certs']
            else:
                certs = {
                    'client': join( data_dir, 'cert_tls12_rsa_client.crt'),
                    'server': join( data_dir, 'cert_tls12_rsa_server.crt'),
                }
            self.conf[ 'connectivity' ] = \
                { 'type' : "udp", 'ip_address' : ip, 'port' : port, 'keys' : keys, 'certs' : certs}
        elif kwargs[ 'type' ] == "tcp":
            con = {}
            con[ 'type' ] = 'tcp'
            if 'ip_address' in kwargs.keys():
                ip =  kwargs[ 'ip_address' ]
            else:
                ip = "127.0.0.1"
            if 'port' in kwargs.keys():
                port = kwargs[ 'port' ]
            else:
                port = 6789
            if 'keys' in kwargs.keys():
                keys = kwargs['keys']
            else:
                keys = {
                        'client': join(data_dir, 'key_tls12_rsa_client.key'),
                        'server': join(data_dir, 'key_tls12_rsa_server.key'),
                       }
            if 'certs' in kwargs.keys():
                certs = kwargs['certs']
            else:
                certs = {
                         'client': join(data_dir, 'cert_tls12_rsa_client.crt'),
                         'server': join(data_dir, 'cert_tls12_rsa_server.crt'),
                        }
            self.conf['connectivity'] = \
                {'type': 'tcp', 'ip_address': ip, 'port': port, 'keys': keys, 'certs': certs}
        elif kwargs['type'] == "http":
            con = {}
            con['type'] = 'http'
            if 'ip_address' in kwargs.keys():
                ip = kwargs['ip_address']
            else:
                ip = "127.0.0.1"
            if 'port' in kwargs.keys():
                port = kwargs['port']
            else:
                port = 6789
            if 'keys' in kwargs.keys():
                keys = kwargs['keys']
            else:
                keys = { 'client': join(data_dir, 'key_tls12_rsa_client.key'),
                         'server': join(data_dir, 'key_tls12_rsa_server.key'),
                       }
            if 'certs' in kwargs.keys():
                certs = kwargs['certs']
            else:
                certs = {
                         'client': join(data_dir, 'cert_tls12_rsa_client.crt'),
                         'server': join(data_dir, 'cert_tls12_rsa_server.crt'),
                        }
            self.conf['connectivity'] = \
                {'type': 'http', 'ip_address': ip, 'port': port, 'keys': keys, 'certs': certs}
        else: 
            raise ConfError( kwargs[ 'type' ], "Expecting 'local', 'udp', 'tcp', 'http' ")


    ### function used by classes using this ConfLurk class 
    def check_key( self, payload, keys):
        """ checks payload got the expected keys"""
        if set( payload.keys() ) != set( keys ):
            raise InvalidFormat( str(payload.keys()),   \
                      "Missing or extra key found. Expected %s"%keys)

    def check_extension( self, designation, version ):
        ext = ( designation, version )
        if ext  not in self.mtype.keys():
           raise InvalidExtension( ext, "Expected %s"%self.mtype.keys() )

    def check_type( self, designation, version,  mtype):
       if mtype not in self.mtype[ ( designation, version ) ]:
           raise InvalidType(self.mtype, "Expected: %s"% 
                              self.mtype[ (designation, version ) ] ) 

    def get_state(self, ext ):
        state = "state" +  str( self.supported_extensions )
        return SHA256.new( str.encode( state ) ).digest()[:4]

    def check_error( self, error_payload ):
        if error_payload == {} :
            return True
        self.check_key( error_payload, [ 'lurk_state'] )
        self.check_error_bytes( error_payload[ 'lurk_state'] )

    def check_error_bytes( self, error_payload_bytes ):
        error = error_payload_bytes
        if type( error ) != bytes :
            raise InvalidFormat( type(error) , "Expected bytes" )
        if len( error ) != 4 :
            raise InvalidFormat( len(error) , "Expected 4 byte len" )


         


class Payload:
    def __init__( self, conf ):
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

    def build_payload( self, **kwargs ):
        """ returns the container that describes the payload """
        return {}

    def build(self, **kwargs ):
        """ converts the container describing the payload into a byte
            format """
        payload = self.build_payload( **kwargs )
        self.check( payload )
        return self.struct.build( payload )

    def parse(self, pkt_bytes):
        """ returns payload described in byte format (pkt_bytes) into a
            container """
        try:
            payload = self.struct.parse( pkt_bytes )
            self.check( payload )
            return payload
        except Exception as e:
            self.treat_exception( e )
        
    def treat_exception( self, e ):
        if type(e) == MappingError:
            value = e.args[0].split()[4]
            if "designation" in e.args[0]:
                raise InvalidExtension( value, "unvalid extension")
            elif "version" in e.args[0]:
                raise InvalidExtension( value, "unvalid extension")
            elif "status" in e.args[0]: 
                raise InvalidStatus(value, "unexpected status")
            elif "type" in e.args[0]:                
                raise  InvalidType(value, "unexpected message type")
        else:
            raise InvalidFormat(type(e), e.args)

    def check( self, payload ):
        pass

    def show(self, pkt_bytes, prefix="", line_len=LINE_LEN):
        """ shows the pkt_bytes. Similar to parse but without any
            control of the configuration and uses the structure
            visualization facilities. """
#print( indent( "%s"%self.struct.__class__.__name__, prefix ) )
        print( indent( "%s"%self.struct_name, prefix ) )
        s = wrap( "%s"%self.struct.parse( pkt_bytes ), line_len=line_len )
        print( indent( s, prefix ) )




class LurkMessage( Payload ):

    def __init__( self, conf=default_conf ):
        self.conf = LurkConf( conf )
        self.struct = LURKHeader
        self.struct_name = 'Lurk Header'
        self.lurk = self.import_ext()

    def import_ext( self ):
        lurk_ext = {}
        for ext in self.conf.mtype.keys():
            if ext == ( "lurk", "v1" ):
                import pylurk.extensions.lurk 
                ## ext_lurk is a special option. It needs the list of
                ## extensions which are parameters outside lurkext. We
                # provide the  full configuration file.
                lurk_ext[ ext ] = pylurk.extensions.lurk.LurkExt( self.conf.conf )
            elif ext == ( "tls12", "v1" ):
                ## this is how future extensions are expected to be handled.
                import pylurk.extensions.tls12 
                lurk_ext[ ext ] = pylurk.extensions.tls12.LurkExt( 
                                      self.conf.get_ext_conf( 'tls12', 'v1' ) )
            else :
                raise ConfError( ext, "unknown extension" ) 
        return lurk_ext

## mglt: I believe that *_ext* fucntion could be integrated with other
## function so message is closer to payload. Woudl probably more
## readable.
## we need to clarify the position of Payload versus Message
## The reason to have message is that it combines two independent data
## structures header and payload and only the payload is delegated to
## the modules. 

    def get_ext( self, message ):
         """ returns the LurkExt object from a message or header """
         ext = ( message [ 'designation' ], message[ 'version' ] )
         return  self.lurk[ ext ]

    def get_header( self, message ):
        return { 'designation' : message[ 'designation' ], \
                 'version' : message[ 'version' ], \
                 'type' : message[ 'type' ], \
                 'status' : message[ 'status' ], \
                 'id' : message[ 'id' ], \
                 'length' :  message[ 'length' ] }

    def build_ext_payload( self, header, **kwargs ):   
        status = header[ 'status' ]
        mtype = header[ 'type' ]
        if status not in [ 'request', 'success' ]:
            raise ImplementationError( status, "Expected 'request' or 'success'")
        return self.get_ext( header).build( status, mtype, **kwargs )

    def check_ext_payload( self, header, payload ):   
        status = header[ 'status' ]
        mtype = header[ 'type' ]
        if status not in [ 'request', 'success' ]:
            raise ImplementationError( status, "Expected 'request' or 'success'")
        self.get_ext( header ).check( status, mtype, payload ) 


    def parse_ext_payload( self, header, payload_bytes ):
        status = header[ 'status' ]
        mtype = header[ 'type' ]
        if status not in [ 'request', 'success' ]:
            raise ImplementationError( status, "Expected 'request' or 'success'")
        return  self.get_ext( header ).parse( status, mtype, payload_bytes )

    def show_ext_payload( self, header, payload_bytes, prefix="", line_len=LINE_LEN):
        status = header[ 'status' ]
        mtype = header[ 'type' ]
        if status not in [ 'request', 'success' ]:
            raise ImplementationError( status, "Expected 'request' or 'success'")
        return  self.get_ext( header ).show( status, mtype, payload_bytes, \
                                            prefix=prefix, line_len=line_len )


    def serve_ext_payload( self, header, request ):
        mtype = header[ 'type' ]
        return self.get_ext( header).serve( mtype, request )


    def build_payload( self, **kwargs ):
        """ builds the lurk header. Missing arguments are replaced by
            default values. Additional keys may be:
                payload_bytes: that describes the payload carried by the 
                lurk header. It is used to derive the length.
        """
        if 'designation' in kwargs.keys():
            designation = kwargs[ 'designation' ]
        else:
            designation = "lurk"
        if 'version' in kwargs.keys():
            version = kwargs[ 'version' ]
        else:
            version = "v1"
        if 'type' in kwargs.keys():
            mtype = kwargs[ 'type' ]
        else :
            mtype = "ping"
        if 'status' in kwargs.keys():
            status = kwargs[ 'status' ]
        else: 
            status = "request"
        if 'id' in kwargs.keys():
            hdr_id = kwargs[ 'id' ]
        else:
            hdr_id = randbits( 8 * 8 )
        if 'length' in kwargs.keys():
            length = kwargs[ 'length' ]
        else:
            length = HEADER_LEN
        header = { 'designation' : designation, 'version' : version, \
                   'type' : mtype, 'status' : status, 'id' : hdr_id, \
                   'length' : length }
        if 'payload' in kwargs.keys():
            payload = kwargs[ 'payload' ]
            if status in [ 'request', 'success' ]:
                payload_bytes = self.build_ext_payload( header, **payload )
                payload = self.parse_ext_payload( header, payload_bytes )
            else: ## if the message is an error message
                payload_bytes = LURKErrorPayload.build( payload )
                payload = LURKErrorPayload.parse( payload_bytes )
            header[ 'length' ] += len ( payload_bytes )
            return { **header, 'payload' : payload }
        else:
            if 'payload_bytes' in kwargs.keys():
                payload_bytes = kwargs[ 'payload_bytes' ] 
            else: 
                payload_bytes = b''
            header[ 'length' ] += len( payload_bytes )
            return { **header, 'payload_bytes' : payload_bytes }

           

    def build( self,  **kwargs ):
        message = self.build_payload( **kwargs )
        self.check( message )
        header = self.get_header( message )
        if 'payload' in message.keys():
            payload = message[ 'payload' ]
            if header[ 'status' ] in [ "success", "request" ]:
                payload_bytes = self.build_ext_payload( header, **payload )
            else: ## the payload is an error payload
                payload_bytes = LURKErrorPayload.build( payload )
        elif 'payload_bytes' in message.keys():
            payload_bytes = message[ 'payload_bytes' ]
        header[ 'length' ] = HEADER_LEN + len( payload_bytes )
        return self.struct.build( header ) + payload_bytes

    def check( self, message ):
        header = [ 'designation', 'version','type', 'status', 'id', 'length' ]
        try :
            header.append( 'payload' )
            self.conf.check_key( message, header )
        except ( InvalidFormat ) : 
            header.remove( 'payload' )
            header.append( 'payload_bytes' )
            self.conf.check_key( message, header)
        header = self.get_header( message )

        self.conf.check_extension( header[ 'designation' ], header[ 'version' ] )
        self.conf.check_type( header[ 'designation' ], header[ 'version'], \
                              header[ 'type' ] )
        if 'payload' in message.keys():
            payload = message[ 'payload' ]
            if header[ 'status' ] in [ "success", "request" ]:
                self.check_ext_payload( header, payload )   
            else:
                self.conf.check_error( payload )
        elif 'payload_bytes' in message.keys():
            payload = message[ 'payload_bytes' ]
            if header[ 'status' ] in [ "success", "request" ]:
                pass
            else:
                self.conf.check_error_bytes( message[ 'payload_bytes' ] )
        else: 
            raise ImplementationError( message, \
                      "Expecting 'payload or 'payload_bytes' key")
         
    def parse(self, pkt_bytes):
        """ parse the first packet, ignores remaining bytes. """
        if len( pkt_bytes ) < HEADER_LEN:
            raise InvalidFormat(len ( pkt_bytes ), \
                  "bytes packet length too short for LURK header. " +\
                  "Expected length %s bytes"%HEADER_LEN  )
        try:
            header = self.struct.parse( pkt_bytes )
        except Exception as e:
            self.treat_exception( e )
        payload_bytes = pkt_bytes[ HEADER_LEN : header[ 'length' ] ] 
        if header[ 'status' ] in [ "success", "request" ]:
            payload = self.parse_ext_payload( header, payload_bytes )
        else: ## the payload is an error payload
            payload = LURKErrorPayload.parse( payload_bytes )
        message =  { **header, 'payload' : payload }
        self.check( message )
        return message


    def serve(self, request):
        try: 
            if request[ 'status' ] != "request":
                raise InvalidStatus(request[ 'status' ], "Expected 'request'")
        except KeyError:
            raise ImplementationError( request, "No key status" )
        header = self.get_header( request )
        try :
            if 'payload_bytes' in request.keys(): 
                req_payload = self.parse_ext_payload( header, request[ 'payload_bytes' ] )
            elif 'payload' in request.keys():
                 req_payload = request[ 'payload' ]
            else:
                raise ImplementationError( request, "Expected 'payload'" +\
                                           "or 'payload_bytes' keys" )
            resp_payload = self.serve_ext_payload( header, req_payload )
            header[ 'status' ] = "success"
            resp_bytes = self.build_ext_payload( header, **resp_payload )
            header[ 'length' ] = HEADER_LEN + len( resp_bytes )
            return { **header, 'payload' : resp_payload }
        except Exception as e :
            try :
                resp_payload = { 'lurk_state' : self.conf.get_state( header ) }
                resp_bytes = LURKErrorPayload.build( resp_payload )
                header[ 'status' ] = e.status
                header[ 'length' ] = HEADER_LEN + len( resp_bytes )
                return { **header, 'payload' : resp_payload }
            except Exception as e : 
                raise ImplementationError( e, "implementation Error")
            
            
    def show(self, pkt_bytes, prefix="", line_len=LINE_LEN):
        print( indent( "%s"%self.struct_name, prefix ) )
        if type ( pkt_bytes ) == dict:
            self.check( pkt_bytes )
            pkt_bytes = self.build( **pkt_bytes )
        if len( pkt_bytes) < HEADER_LEN :
            print("Not enough bytes, cannot parse LURK Header" )
            print("Expecting %s, got %s"%( HEADER_LEN, len( pkt_bytes) ) )
            print("pkt_bytes: %s"%pkt_bytes )
        else: 
            print( indent( "%s"%self.struct.parse(pkt_bytes[:HEADER_LEN] ), \
                       prefix ) )
            header = self.struct.parse(pkt_bytes[ : HEADER_LEN ] )
            if len( pkt_bytes ) >= header[ 'length' ]:
                payload_bytes = pkt_bytes[ HEADER_LEN : header[ 'length'] ]
            else:
                raise InvalidFormat( ( header, pkt_bytes ), \
                          "pkt_bytes too short %s bytes"%len (pkt_bytes ) )
            if header[ 'status' ] in [ "success", "request" ]:
                 
                self.show_ext_payload( header, payload_bytes, \
                               prefix=prefix, line_len=line_len) 
            else: ## the payload is an error payload
                LURKErrorPayload.parse( payload_bytes )


class LurkServer():
## mglt: I do not think that secureTLS should be mentionned here.
## However it might be good to have the threads=1. We need to clarify
## whether having multithreading here will not solve all multithreading
## issues. 

    def __init__(self, conf=default_conf, secureTLS_connection=False ):
        self.init_conf( conf )
        self.conf = LurkConf( conf )
        self.conf.set_role( 'server' )
        self.message = LurkMessage( conf=self.conf.conf )

        # specify that we need to use TCP TLS
        self.secureTLS_connection = secureTLS_connection

## mglt: we need to check if that relevent to have this function here
## while LurkConf has the equivalent mehtod.
    def init_conf( self, conf ):
        """ Provides minor changes to conf so the default conf can be used
 
        Args:
            conf (dict): the dictionary representing the configuration
                arguments
 
        Returns:
            conf (dict): the updated conf dictionary
        """
        conf[ 'role' ] = 'server' 
        return conf
         

    def byte_serve(self, pkt_bytes):
        """ read the HEADER_LEN bytes of pkt_bytes. If an error occurs, it
        associated to the errors encountered by reading the payload part.
        """
        response_bytes = b''
        while len( pkt_bytes ) >= HEADER_LEN :
            try:
                request = self.message.parse( pkt_bytes )
                response = self.message.serve ( request )
                response_bytes += self.message.build( **response ) 
                pkt_bytes = pkt_bytes[ request['length' ] : ]  
            except:
                ## stop when an error is encountered
                return response_bytes
        return response_bytes


## mglt: LurkServer - As I understand it - has nothing to do with the
## TLS session between Lurk Client and Server. I think this function
## should be in TCPTLSLurkServer/Client. not here. 

    def get_context(self):
        '''
        This method sets the ssl context for a secure connection with the client.
        To do: enhance this method to load the certificates from the configuration.

        :return: ssl context object
        '''

        #path to server certificate
        server_cert = self.conf.server.tls_certs['server']

        #path to server key
        server_key = self.conf.server.tls_keys['server']

        #path to client certificates
        client_certs = self.conf.server.tls_certs['client']

        # context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)#in case we want to use  a default context chosen by ssl

        #set the context to use TLS1.2 protocol
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)

        #set the server to verify clients certificates (the hostname when wrapping the socket should be specified in this case on client side)
        context.verify_mode = ssl.CERT_REQUIRED

        #load the server certificate and key
        context.load_cert_chain(certfile= server_cert, keyfile= server_key)

        #allo the server to also authenticate the client
        context.load_verify_locations(cafile= client_certs)

        return context

class LurkBaseClient:
    pass


class LurkClient:
## mglt - idem: we should probably have multithreading. It is not clear
## to me why we have TLS
    def __init__( self, conf=default_conf, secureTLS_connection=False,\
                  thread=True):
        self.init_conf( conf )
        self.conf = LurkConf( conf )
        self.waiting_queries = {}
        self.server = self.get_server()
        self.message = LurkMessage( conf = self.conf.conf )

        #specify that we need to use TCP TLS
        self.secureTLS_connection = secureTLS_connection

## mglt: should be in LurkConf while checking the role.
    def init_conf( self, conf ):
        """ Provides minor changes to conf so the default conf can be used
 
        Args:
            conf (dict): the dictionary representing the configuration
                arguments
 
        Returns:
            conf (dict): the updated conf dictionary
        """
        conf[ 'role' ] = 'client' 
        for i in range( len( conf[ 'extensions' ] ) ):
            ext = conf[ 'extensions' ][ i ]
            if ext[ 'designation' ] in [ 'tls12' ] and \
               ext[ 'version' ] in [ 'v1' ] and \
               ext[ 'type' ] in [ 'rsa_master', 'rsa_extended_master', \
                   'rsa_master_with_poh', 'rsa_extended_master_poh', \
                   'ecdhe', 'ecdhe_with_poh' ] :
                try:
                    del conf[ 'extensions' ][ i ][ 'key' ]
                except KeyError:
                    pass
        return conf

## mglt: we need to look at udp, tcp... but it seems we could have
## somthing simplier. We know LurkServer needs to be returned and
## appropriated conf can be set according to functions from LurkConf.
    def get_server( self ):
        conf_class = self.conf.server.__class__.__name__ 
        if conf_class == 'LocalServerConf' :
            srv_conf = LurkConf( self.conf.conf )
            srv_conf.set_role( 'server' )
            return LurkServer(conf=srv_conf.conf )
        else:
            raise ConfError( conf_class, "Expected 'LocalServerConf' " )

    def send(self, request_bytes):
        return self.server.byte_serve( request_bytes )

    def resolve( self, **kwargs ):
        request = self.message.build_payload( **kwargs )
        ## adding query to the waiting list
        self.waiting_queries[ request[ 'id' ] ] = request
        ## get_response
        request_bytes = self.message.build( **request )
        response_bytes = self.send( request_bytes )
        max_retry = 3
        retry = 0
        while response_bytes == None and retry < max_retry:
            response_bytes = self.send( request_bytes )
            retry += 1
        if response_bytes == None:
            print("Resolution Failed")
        response = self.message.parse( response_bytes )
        return request, response

## mglt: not sure we are using this fucntion. our current client looks
## like a stub client. This is fine for now, but to avoid layer
## violation, we will probably need to define a communication between 
## stub client (in the TLS software and our Lurk*Client) using RPC
## communications.
##    def is_response(self, response):
##        try:
##            query = self.waiting_queries[ response [ 'id' ] ]
##            del self.waiting_queries[ response [ 'id' ] ]
##            return True
##        except KeyError:
##            return False

    def get_context(self):
        '''
        This method sets the ssl context for a secure connection with the server.
        To do: enhance this method to load the certificates from the configuration.

        :return: ssl context object
        '''

        # path to client key
        client_key = self.conf.server.tls_keys['client']

        # path to client certificates
        client_certs = self.conf.server.tls_certs['client']

        # context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=join( data_dir, 'server.crt' )) #used for default context selected by ssl

        #set the context to use TLS12
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)

        #load the client key and certificate
        context.load_cert_chain(certfile= client_certs, keyfile=client_key)

        return context


class LurkUDPClient(LurkClient):

    def __init__(self, conf=default_conf, secureTLS_connection=False ):
        self.init_conf( conf )
        self.conf = LurkConf( conf )
        self.waiting_queries = {}
        self.secureTLS_connection = secureTLS_connection
        self.server = self.get_server()
        self.message = LurkMessage( conf = self.conf.conf )


    def connect(self, conf):
         self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
         self.sock.settimeout(1.0)
        
## mglt: is this an appropriated terminology ? I think what we want toi
## say is something like set_server_channel 
    def get_server( self):
         sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
         sock.settimeout(1.0)

        #DTLS not supported With Python 3.6- this is kept for future use
         #if (self.secureTLS_connection):
            # context = self.get_context()
            # sock = context.wrap_socket(sock, server_side=False, server_hostname=self.conf.server.ip_address)  # server_hostname='example.com' (this is the common name when generating the certificate)

         return sock

    def send(self, bytes_pkt):
        try:
            ip = self.conf.server.ip_address
            port = self.conf.server.port
            self.server.sendto( bytes_pkt, ( ip, port ) )
            response_bytes, addr = self.server.recvfrom(4096)
            waiting = True
            while waiting == True:
                response_bytes, server = server.recvfrom(4096)
                response = self.message.parse( response_bytes )
                if  self.is_response( response ) == True:
                    waiting = False
            return response 
        except:
            try :
                return response_bytes
            except: 
                ImplementationError( '', "Unable resolve" )

### merge ###<<<<<<< HEAD
### merge ###class LurkUDPServer(UDPServer, LurkServer):
### merge ###
### merge ###    def __init__(self,conf=default_conf, secureTLS_connection=False):
### merge ###
### merge ###        LurkServer.__init__(self, conf, secureTLS_connection)
### merge ###
### merge ###        # this will allow reusing the same address for multiple connections
### merge ###        self.allow_reuse_address = True
### merge ###
### merge ###        # initialize the UDPserver
### merge ###        server_address = (self.conf.server.ip_address, self.conf.server.port)
### merge ###        UDPServer.__init__(self, server_address, UDPRequestHandler )
### merge ###
### merge ###        #DTLS not supported with python 3.6 -- this is kept for future use
### merge ###        #if (secureTLS_connection):
### merge ###            # secure connection by setting the context
### merge ###           # context = self.get_context()
### merge ###            # updating the httpserver socket after wrapping it with ssl context
### merge ###           # self.socket = context.wrap_socket(self.socket, server_side=True)
### merge ###
### merge ###class PoolMixIn(ThreadingMixIn):
### merge ###
### merge ###    def process_request(self, request, client_address):
### merge ###        '''
### merge ###        Override the process_request () in ThreadingMixIn
### merge ###        This method is called by handle_request() pre-defined in BaseServer(in out case; ThreadedUDPServer, ThreadedTCPServer) class which is the superclass of UDPServer and TCPServer
### merge ###        :param request:
### merge ###        :param client_address:
### merge ###        '''
### merge ###
### merge ###        #call the process_request_thread () defined in ThreadingMixIn for each request in the pool
### merge ###        self.pool.submit(self.process_request_thread, request, client_address)
### merge ###
### merge ###
### merge ###class ThreadedLurkUDPServer(PoolMixIn, LurkUDPServer):
### merge ###    '''
### merge ###     This class represents a UDPServer which launches a new thread (for each request) when a client gets connected
### merge ###     This default behavior is modified by extending the PoolMixIn class instead of ThreadingMixIn to handle a specific number of requests(max_workers) in parallel
### merge ###    '''
### merge ###    def __init__(self, conf=default_conf, secureTLS_connection = False, max_workers=40):
### merge ###        '''
### merge ###         This is a constructor to initialize an UDP server that handles multiple requests at the same time.
### merge ###         The code is a copy of the LurkUDPserver constructor (Note: calling the super constructor calls the LurkServer constructor which causes an error)
### merge ###         :param conf: the configuration
### merge ###         :param secureTLS_connection: if set to true will wrap the socket to use DTLS - currently not supported
### merge ###         :param max_workers: max number of HTTPS requests to handle in parallel
### merge ###         '''
### merge ###        LurkServer.__init__(self, conf, secureTLS_connection)
### merge ###
### merge ###        # set the pool attribute to allow multithreading
### merge ###        self.pool = ThreadPoolExecutor(max_workers)
### merge ###=======
##class LurkUDPServer:
##
##    def __init__(self,conf=default_conf):
##        self.lurk = LurkServer( conf )
##
##    def serve_client(self):
##        """
##        This method is used to serve a single client without invoking any threading functionaliy
##        """
##        #create and bind socket
##        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
##        ip = self.lurk.conf.server.ip_address
##        port = self.lurk.conf.server.port
##        sock.bind((ip, port))
##
##        #recieve client request and reply
##        while True:
##          data, address = sock.recvfrom(4096)
##          sock.sendto( self.lurk.byte_serve(data), address)
##
##        #close socket
##        sock.close()
##
#### mglt: this function does not seem to be used here. 
##    def get_thread_udpserver(self, max_workers=40):
##
##       """
##       This method is used whenever we want to use threding for UDPServer.
##       :param max_workers: maximum number of threads (requests) to handle at a time
##       :return: an instance of the ThreadedUDPServer from which we can have access to the server socket and client data
##       """
##       ip = self.lurk.conf.server.ip_address
##       port = self.lurk.conf.server.port
##
##       #create a UDP server (socket) bind the host (ip) to the port (port)
##       server = ThreadedUDPServer((ip, port), UDPHandler, self.lurk, max_workers)
##       return server

"""
From https://docs.python.org/3.5/library/socketserver.html: 

Creating a server requires several steps. First, you must create a request handler class by subclassing the BaseRequestHandler class and overriding its handle() method; this method will process incoming requests. Second, you must instantiate one of the server classes, passing it the server’s address and the request handler class. Then call the handle_request() or serve_forever() method of the server object to process one or many requests. Finally, call server_close() to close the socket.

When inheriting from ThreadingMixIn for threaded connection behavior, you should explicitly declare how you want your threads to behave on an abrupt shutdown. The ThreadingMixIn class defines an attribute daemon_threads, which indicates whether or not the server should wait for thread termination. You should set the flag explicitly if you would like threads to behave autonomously; the default is False, meaning that Python will not exit until all threads created by ThreadingMixIn have exited.
"""
class BaseUDPServer(UDPServer):

    def __init__(self, lurk_conf, RequestHandlerClass ):
        self.lurk = LurkServer( lurk_conf )
        host = lurk_conf[ 'connectivity' ][ 'ip_address' ]
        port = lurk_conf[ 'connectivity' ][ 'port' ]
        server_address = (host, port) 
        super().__init__(server_address, RequestHandlerClass)

    def byte_serve(self, data):
        return self.lurk.byte_serve(data)


class ThreadedUDPServer(ThreadingMixIn, BaseUDPServer):
    pass

###        # this will allow reusing the same address for multiple connections
###        self.allow_reuse_address = True

### merge ###<<<<<<< HEAD
### merge ###        # initialize the UDPserver
### merge ###        server_address = (self.conf.server.ip_address, self.conf.server.port)
### merge ###        UDPServer.__init__(self, server_address, UDPRequestHandler)
### merge ###
### merge ###        #DTLS not supported for python 3.6 This is kept for future implementation
### merge ###        #if (secureTLS_connection):
### merge ###            # secure connection by setting the context
### merge ###           # context = self.get_context()
### merge ###            # updating the httpserver socket after wrapping it with ssl context
### merge ###            #self.socket = context.wrap_socket(self.socket, server_side=True)
### merge ###
### merge ###
### merge ###class UDPRequestHandler(BaseRequestHandler):
### merge ###=======
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
### merge ###<<<<<<< HEAD
### merge ###
### merge ###        #manipulate the data and send it to the client
### merge ###        #self.server is a ThreadedLurkUDPServer
### merge ###        socket.sendto(self.server.byte_serve(data), self.client_address)
### merge ###
### merge ###        #socket.close()
### merge ###=======
        socket.sendto(self.server.byte_serve(data), self.client_address)
        print("{} data:".format(threading.current_thread().name))

class LurkUDPServer:

    def __init__(self, conf=default_conf, thread=True):
        ## self.conf = conf
        ## host = self.conf[ 'connectivity' ][ 'ip_address' ]
        ## port = self.conf[ 'connectivity' ][ 'port' ]
        ## self.lurk = LurkServer( conf )
        if thread == False:
           self.server = BaseUDPServer(conf, UDPHandler )
        else:
           self.server = ThreadedUDPServer(conf, UDPHandle)
        self.server.serve_forever()

#    def serve_forever(self):
#        self.server.serve_forever()

class PoolMixIn(ThreadingMixIn):
    pass

#####
#####    def process_request(self, request, client_address):
#####        '''
#####        Override the process_request () in ThreadingMixIn
#####        This method is called by handle_request() pre-defined in BaseServer(in out case; ThreadedUDPServer, ThreadedTCPServer) class which is the superclass of UDPServer and TCPServer
#####        :param request:
#####        :param client_address:
#####        '''
#####
#####        #call the process_request_thread () defined in ThreadingMixIn for each request in the pool
#####        self.pool.submit(self.process_request_thread, request, client_address)
#####
#####
#####class ThreadedUDPServer(PoolMixIn, UDPServer):
#####    '''
#####     This class represents a UDPServer which launches a new thread (for each request) when a client gets connected
#####     This default behavior is modified by extending the PoolMixIn class instead of ThreadingMixIn to handle a specific number of requests(max_workers) in parallel
#####    '''
#####    def __init__(self, server_info, udp_handler, lurkserver, max_workers=40):
#####        """
#####        Override the method to pass the lurk serversince it is needed to be able to call the byte_serve in UDPHandler.handle()
#####        :param server_info:(ip, port) on which the UDP server is listening
#####        :param UDPHandler: object of the UDPHandler class
#####        :param lurkserver: object of the LurkServer
#####        :param max_workers: maximum number of threads (requests) to handle at a time
#####        """
#####        #super(UDPServer, self).__init__(server_info, udp_handler)
#####        super(PoolMixIn, self).__init__(server_info, udp_handler)
#####        self.lurkServer = lurkserver
#####        self.pool = ThreadPoolExecutor(max_workers)
#####

##class UDPHandler(BaseRequestHandler):
##    """
##     This class works similar to the TCP handler class, except that
##    self.request consists of a pair of data and client socket, and since
##    there is no connection, the client address must be given explicitly
##    when sending data back via sendto().
##    An object of this class is instantiated whenever there is a new client request
##    """
#### mglt: maybe lurkServer should be instantiated here. 
#### 
##    def handle(self):
##        """
##             This method handles the processing for each request
##        """
##        #get data sent by the client to the server up to 8192 bytes
##        data = self.request[0]
##
##        #get the server socket
##        socket = self.request[1]
##
##        #manipulate the data and send it to the client
##        #self.server is a ThreadedUDPServer
##        socket.sendto(self.server.lurkServer.byte_serve(data), self.client_address)
##
##        #socket.close()
##        print("{} data:".format(threading.current_thread().name))
##        print(data)


## interesting links on TCP sockets:
## https://www.scottklement.com/rpg/socktut/tutorial.html
## https://docs.python.org/3/howto/sockets.html
## https://docs.python.org/3/library/socket.html
## https://docs.python.org/3/library/socketserver.html
## https://github.com/eliben/python3-samples/blob/master/async/selectors-async-tcp-server.py

class BaseTCPServer(TCPServer):

    def __init__(self, lurk_conf, RequestHandlerClass ):
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
        self.lurk = LurkServer( lurk_conf )
        host = lurk_conf[ 'connectivity' ][ 'ip_address' ]
        port = lurk_conf[ 'connectivity' ][ 'port' ]
        server_address = (host, port) 
        super().__init__(server_address, RequestHandlerClass)
        print("--- self.socket: %s"%self.socket)
        self.selector = selectors.DefaultSelector()
        self.selector.register(fileobj=self.socket, \
                               events=selectors.EVENT_READ, \
                               data="accept")
        self.fd_timeout = 3600       
        self.fd_time = {}

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


    def serve_forever(self, poll_interval=0.5):
        """ serves incoming request 

        This function listen to events on the listening socket
        (self.socket) as well as other sockets associated to accepted
        communications ( sock = self.sock.accept()). 

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
        self._BaseServer__is_shut_down.clear()
        previous_time = 0
        try:
            while not self._BaseServer__shutdown_request:
                events = self.selector.select(poll_interval)
                print(" --- events: %s"%events)
                for selector_key, event in events:
                    if self._BaseServer__shutdown_request:
                        break
                    self._handle_request_noblock(selector_key, event)
                    self.service_actions()
                current_time = time()
                if current_time - previous_time > 1:
                    previous_time = current_time
                    for fd in self.selector.get_map():
                        print(" --- fd: %s"%fd)
                        key = self.selector._fd_to_key[fd]
                        print(" --- key: %s"%str(key))
                        try:
                            delta_time = current_time - self.fd_time[fd]
                            if delta_time > self.fd_timeout and key.data == 'establish': 
                                self.close_request(key.fileobj)                        
                        except KeyError:
                            ## time of self.socket is not monitored
                            ## while it triggers events  
                            continue
        finally:
            self._BaseServer__shutdown_request = False
            self._BaseServer__is_shut_down.set()

## need to check if that could work by passing variables to object
## or any other ways. 
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
        print("--- selector_key: %s"%str(selector_key))
        print("--- event: %s"%str(event))
        if selector_key.data == "accept":
            request, client_address = self.socket.accept()
            request.setblocking(False)
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

### merge ###<<<<<<< HEAD
### merge ###        # initialize the TCPserver
### merge ###        server_address = (self.conf.server.ip_address, self.conf.server.port)
### merge ###        TCPServer.__init__(self, server_address, TCPRequestHandler)
### merge ###
### merge ###        if (secureTLS_connection):
### merge ###            # secure connection by setting the context
### merge ###            context = self.get_context()
### merge ###            # updating the TCPserver socket after wrapping it with ssl context
### merge ###            self.socket = context.wrap_socket(self.socket, server_side=True)
### merge ###
### merge ###=======
        try:
            bytes_recv = self.request.recv(HEADER_LEN)
        except BlockingIOError:
            return 
        if bytes_recv == b'':
            return 
        header = LURKHeader.parse(bytes_recv)
        bytes_nbr = header[ 'length' ]
        while len(bytes_recv) < bytes_nbr:
            bytes_recv += self.request.recv(min(bytes_nbr - len(bytes_recv), 1024))
        self.request.sendall(self.server.byte_serve(bytes_recv))
        print("{} data:".format(threading.current_thread().name))

class LurkTCPServer:

    def __init__(self, conf=default_conf, thread=True):
        if thread == False:
           self.server = BaseTCPServer(conf, TCPHandle )
        else:
           self.server = ThreadedTCPServer(conf, TCPHandle)
        self.server.serve_forever()



MAX_CONNECT_ATTEMPTS = 3




class LurkTCPClient(LurkClient):

    def __init__(self, conf=default_conf):
        self.con_type = conf['connectivity']['type']
        self.host = conf[ 'connectivity' ][ 'ip_address' ]
        self.port = conf[ 'connectivity' ][ 'port' ]
        if self.con_type not in [ 'tcp', 'tcp+tls' ]:
            self.con_type = 'tcp'
        print("tcp client: %s:%s"%(self.host, self.port))
        self.message = LurkMessage( conf = conf )
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setblocking(False)
        self.connect() 
        print("init: self.sock: %s"%self.sock) 
      
    def connect(self):
        attempt_nbr = 0
        error_nbr = -1
        while error_nbr != 0 and error_nbr != 106 : 
            error_nbr = self.sock.connect_ex((self.host, self.port))
            if error_nbr != 0:
                print("Connecting tcp socket (%s): %s, %s"%\
                      (error_nbr, errno.errorcode[error_nbr], \
                       os.strerror(error_nbr)))
            attempt_nbr += 1
            if attempt_nbr > MAX_CONNECT_ATTEMPTS:
                raise ImplementationError(attempt_nbr, "TCP connection" +\
                      "attempts exceeds MAX_CONNECT_ATTEMPTS " +\
                      "= %s"%MAX_CONNECT_ATTEMPTS +\
                      "TCP session not established" )

        if self.con_type == 'tcp+tls' :
            context = self.get_context()
            self.sock = context.wrap_socket(sock, server_side=False,server_hostname=host) 

            #server_hostname='example.com' 


###    def send(self, bytes_pkt):
###         '''
###         This method will connect the client to the server and send the bytes_pkt and recieve the response
###         Important notes:
###             1- We prevent the client to reconnect each time it tries to send a request.
###             For that, we start by trying to send the bytes, if connection is lost of no connection is established a socket exception will be thrown and hence, the client will try to connect to server and re-send the bytes
###             2- Use a buffer of 4096
###             It is important to keep the buffer = 4096 and not less (i.e. 1024) to prevent a timeout error and a failure to reconnect when trying to send an 'rsa_extended_master' and capabilities
###
###         :param bytes_pkt: bytes to send t server
###         :return: recieved bytes (parsed)
###         '''
###         self.outgoing.append(bytes_pkt)
###         return None
###
###         while True:
###            try:
###                #try to send first to check if there is a connection established
###                self.server.sendall(bytes_pkt)
###                response_bytes = self.server.recv(4096)
###                waiting = True
###                while waiting == True:
###                    response_bytes = self.server.recv(4096)
###                    response = self.message.parse(response_bytes)
###                    if self.is_response(response) == True:
###                       waiting = False
###                return response
###            #catch any error mainly if no connection exists
###            except socket.error:
###                try:
###                    return response_bytes
###                except:
###                    ImplementationError('', "Unable resolve")
###
###                # set connection status and recconnect
###                connected = False
###
###                while not connected:
###                    #attempt to reconnect
###                    try:
###                        ip = self.conf.server.ip_address
###                        port = self.conf.server.port
###                        self.server.connect( ( ip, port ) )
###                        connected = True
###                    except socket.timeout:
###                        print("timeout")
###
###         self.server.close()

    def unpack_bytes(self, bytes_pkt):
        """ stores al requests of bytes_request in self.request
        
        bytes_request can be the concatenation of one or multiple
        requests. This function lists the each individual request. This
        is used to define later if all requests have been answered.

        Args:
            bytes_pkt (bytes): one or a concatenation of one or multiple
            packets in a byte format. packets can be requests or responses. 

### merge ###<<<<<<< HEAD
### merge ###    def __init__(self, conf=default_conf, secureTLS_connection = False, max_workers=40):
### merge ###        '''
### merge ###        This is a constructor to initialize an TCP server that handles multiple requests at the same time.
### merge ###        The code is a copy of the LurkHTTPSserver constructor (Note: calling the super constructor calls the LurkServer constructor which causes an error)
### merge ###        :param conf: the configuration
### merge ###        :param secureTLS_connection: if set to true will wrap the socket to use TLS1.2
### merge ###        :param max_workers: max number of HTTPS requests to handle in parallel
### merge ###        '''
### merge ###=======
        Returns:
            pkt_bytes_dict (dict): a dictionary of every subpackets
                indexed with their id { pkt['id']: pkt }
        """
        bytes_pkt_dict = {}
        while len(bytes_pkt) != 0: 
            header = LURKHeader.parse(bytes_pkt)
            bytes_nbr =  HEADER_LEN + header['length'] 
            bytes_pkt_dict[ header['id'] ] = bytes_pkt[: bytes_nbr ]
            bytes_pkt = bytes_pkt[bytes_nbr :] 
        return bytes_pkt_dict

    def resolve( self, **kwargs ):
        ## we shoudl be able to pass a list of **kwargs
        request = self.message.build_payload( **kwargs )
        bytes_requests = self.message.build( **request )
        bytes_resolutions = self.bytes_resolve(bytes_requests) 
        resolutions = []
        for resol in bytes_resolutions:
            resolutions.append((self.message.parse(resol[0]), \
                                self.message.parse(resol[1])))
        return resolutions[0]


##?gc        max_retry = 3
##?gc        retry = 0
##?gc        while bytes_resolutions == None and retry < max_retry:
##?gc            response_bytes = self.send( request_bytes )
##?gc            retry += 1
##?gc        if response_bytes == None:
##?gc            print("Resolution Failed")
##?gc        response = self.message.parse( response_bytes )
##?gc        return request, response

    def bytes_resolve(self, bytes_request):
        """ sends bytes_request and returns bytes_responses

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
        ##self.connect(status='init')
        self.bytes_send(bytes_request)
        bytes_requests_dict = self.unpack_bytes(bytes_request)
        bytes_responses = self.bytes_receive(bytes_requests_dict)
        bytes_responses_dict = self.unpack_bytes(bytes_responses)
##        while set(self.requests.keys()) != set(self.responses.keys()):        
##            read_s, write_s, error_s = select.select([self.sock] , [], [])
##            if self.sock in read_s:
##                self.receiving()
        bytes_resolutions = []
        for req_id in bytes_requests_dict.keys():
            try:
                bytes_resolutions.append((bytes_requests_dict[req_id], \
                                      bytes_responses_dict[req_id]))
            except KeyError:
                ## including void responses, i.e not provided by the
                ## server
                bytes_resolutions.append((bytes_requests_dict[req_id],b''))

        ##self.closing()
        return bytes_resolutions

    def is_response(self, bytes_response, bytes_requests_dict):
        if bytes_requests_dict == None:
            return True
        ## server does not respond
        if bytes_response == b'':
            return True
        try:
            header_response = LURKHeader.parse(bytes_response)
            header_request = LURKHeader.parse(bytes_requests_dict[\
                                 header_response['id'] ])
            for key in [ 'designation', 'version', 'type' ]:
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
        print("bytes_send: self.sock: %s"%self.sock) 
        rlist, wlist, xlist = select([], [self.sock], [])
        sent_status = self.sock.sendall(bytes_request)
        if sent_status == None:
            print("bytes_request sent (%s): %s"%(len(bytes_request), \
                                             binascii.hexlify(bytes_request)))
        else: 
            print("Not all data (%s) has been sent: %s"(len(bytes_request), \
                                   binascii.hexlify(bytes_request)))


    def bytes_receive(self, bytes_requests_dict=None):
        """ receiving response_nbr packets

        Args:
            bytes_Requests_dict (dict): the dictionary that associated
                to the id the byte representation of the request (bytes_request) 
                { id : bytes_request }
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
           if self.is_response(bytes_response, bytes_requests_dict) == False:
               continue  
           bytes_responses += bytes_response
           response_nbr -= 1

        return bytes_responses
 
    def bytes_receive_single_response(self):
        print("bytes_receive_single_response")
        rlist, wlist, xlist = select([self.sock], [], [])
        bytes_recv = b''
        print("--rlist: %s, xlist: %s"%(rlist, xlist))
        while len(bytes_recv) < HEADER_LEN :
            rlist, wlist, xlist = select([self.sock], [], [])
##            try:
            bytes_recv = self.sock.recv(HEADER_LEN)
##        if bytes_recv == b'':
##            self.connect() 
##            return bytes_recv
                ##print("reading header: %s"%binascii.hexlify(bytes_recv))
##            except (OSError, BlockingIOError) as err:
##                print("socket connection broken. Cannot read header") 
##                print("OS error: {0}".format(err))
##                raise err
            ##if bytes_recv == b'':
        print("bytes_recv (header): %s"%binascii.hexlify(bytes_recv))
        print("len(bytes_recv): %s, %s"%(len(bytes_recv), HEADER_LEN))
        header = LURKHeader.parse(bytes_recv)
        bytes_nbr = header[ 'length' ]
      
        while len(bytes_recv) < bytes_nbr:
           rlist, wlist, xlist = select([self.sock], [], [])
           bytes_recv += self.sock.recv(min(bytes_nbr - len(bytes_recv), 4096))
           print("bytes_recv (%s): %s"%(len(bytes_recv), \
                 binascii.hexlify(bytes_recv)))
        return bytes_recv 


    def closing(self):
        """ Closing the connection

        """
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()
        

##class LurkTCPServer(LurkServer, TCPServer):
##
##    def __init__(self,conf=default_conf, secureTLS_connection=False):
##        conf['connectivity']['type'] = 'tcp'
##        LurkServer.__init__(self, conf, secureTLS_connection)
##
##        # this will allow reusing the same address for multiple connections
##        self.allow_reuse_address = True
##
##        # initialize the httpserver
##        server_address = (self.conf.server.ip_address, self.conf.server.port)
##        TCPServer.__init__(self, server_address, TCPRequestHandler)
##
##        if (secureTLS_connection):
##            # secure connection by setting the context
##            context = self.get_context()
##            # updating the httpserver socket after wrapping it with ssl context
##            self.socket = context.wrap_socket(self.socket, server_side=True)
##
##    def serve_client(self):
##        """
##        This method is used to serve a single client without invoking any threading functionality
##        It only allows the connection of one client to the server.
##        Unlike UDP where multiple clients can be handled sequentially, with TCP, for the server to handle multiple clients threading is needed.
##        https://stackoverflow.com/questions/10810249/python-socket-multiple-clients/46980073
##        """
##        #create and bind socket
##        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
##        ip = self.conf.server.ip_address
##        port = self.conf.server.port
##
##        #allow address reuse to prevent OS error that the address is already in use when binding
##       # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
##
##        sock.bind((ip, port))
##        sock.listen(1)
##
##
##        #conn: a new socket object used to send and recv data; addr address of the client
##        conn, addr = sock.accept()
##
##        if (self.secureTLS_connection):
##            context = self.get_context()
##            conn =context.wrap_socket(conn, server_side=True)
##
##        #recieve client request and reply
##        while True:
##          data = conn.recv(4096)
##          conn.sendall( self.byte_serve(data))
##
##        #close socket
##        conn.close()
##
##        sock.close()
##
##class ThreadedLurkTCPServer(PoolMixIn, LurkTCPServer):
##    '''
##    This class represents a TCPServer which launches a new thread (for each request) when a client gets connected
##    This default behavior is modified by extending the PoolMixIn class instead of ThreadingMixIn to handle a specific number of requests(max_workers) in parallel
##    '''
##
##    def __init__(self, conf=default_conf, secureTLS_connection = False, max_workers=40):
##        '''
##        This is a constructor to initialize an TCP server that handles multiple requests at the same time.
##        The code is a copy of the LurkHTTPSserver constructor (Note: calling the super constructor calls the LurkServer constructor which causes an error)
##        :param conf: the configuration
##        :param max_workers: max number of HTTPS requests to handle in parallel
##        '''
##
##        # set the pool attribute to allow multithreading
##        self.pool = ThreadPoolExecutor(max_workers)
##
##        conf['connectivity']['type'] = 'tcp'
##        LurkServer.__init__(self, conf, secureTLS_connection)
##
##        # this will allow reusing the same address for multiple connections
##        self.allow_reuse_address = True
##
##        # initialize the httpserver
##        server_address = (self.conf.server.ip_address, self.conf.server.port)
##        TCPServer.__init__(self, server_address, TCPRequestHandler)
##
##        if (secureTLS_connection):
##            # secure connection by setting the context
##            context = self.get_context()
##            # updating the httpserver socket after wrapping it with ssl context
##            self.socket = context.wrap_socket(self.socket, server_side=True)
##
##class TCPRequestHandler(BaseRequestHandler):
##
##    def handle(self):
##        '''
##        this function handles all the processing of a request
##        '''
##        # recieve client request and reply
##        print("{}".format(threading.current_thread().name))
##
##        while True:
##            data = self.request.recv(4096)
##            self.request.sendall(self.server.byte_serve(data))
##
##
##        # close the client socket
##        self.request.close()
##
##

class LurkHTTPClient(LurkClient):

    def __init__(self, conf=default_conf, secureTLS_connection=False):
        conf['connectivity']['type'] = 'http'

        # could not call super constructor as it was throwing an init_conf error
        self.init_conf(conf)
        self.conf = LurkConf(conf)
        self.waiting_queries = {}

        #set the server to None as we do not interact directly with the client socket
        self.server = self.get_server()
        self.message = LurkMessage(conf=self.conf.conf)

        self.secureTLS_connection = secureTLS_connection


    def get_server( self ):
        '''
        This should return a TCP client socket.
        However, as we do not directly interact with the client socket since we are using urllib, we will just set the
        server attribute to none
        :return: None
        '''
        return None

    def send(self, bytes_pkt):
        '''
        This method represents the HTTP POSt request of the client and the response recieved from the HTTP server
        :param bytes_pkt: bytes to send to the HTTP server
        :return: bytes reqponse of the server
        '''
        try:

            protocol = 'http'

            if (self.secureTLS_connection):
                protocol = 'https'

            # try to send first to check if there is a connection established
            url = protocol+'://' + str(self.conf.server.ip_address) + ':' + str(self.conf.server.port)

            #prepare client request to post the bytes_pkt
            req = urllib.request.Request(url,bytes_pkt , method='POST')

            #request the url, post the data and set up the ssl context
            if (self.secureTLS_connection):
                response = urllib.request.urlopen(req, context=self.get_context())
            else:
                response = urllib.request.urlopen(req, context=None)

            #start by reading the server response
            response_bytes = response.read(4096)

            waiting = True
            while waiting == True:

                #keep reading until the end of the response (until exception is thrown)
                response_bytes = response_bytes+ response.read(4096)

                #make sure the response is in the correct format
                response = self.message.parse(response_bytes)

                #check if this is the correct response (this is never executed!!!!)
                if self.is_response(response) == True:
                    waiting = False
            return response
        # catch any error mainly thrown at the end of reading the response
        except:
            try:
                return response_bytes
            except:
                ImplementationError('', "Unable resolve")



class  LurkHTTPserver(LurkServer, HTTPServer):
    '''
    This class represnts and HTTPS server having LurkServer and HTTPServer functionality
    '''
    def __init__(self,conf=default_conf, secureTLS_connection=False):
        conf['connectivity']['type'] = 'http'


        LurkServer.__init__(self, conf, secureTLS_connection)

        # this will allow reusing the same address for multiple connections
        self.allow_reuse_address = True

        #initialize the httpserver
        server_address  = (self.conf.server.ip_address, self.conf.server.port)
        HTTPServer.__init__(self,server_address, HTTPRequestHandler)

        #secure connection by setting the context
        if (secureTLS_connection):
            context = self.get_context()
            #updating the httpserver socket after wrapping it with ssl context
            self.socket = context.wrap_socket(self.socket, server_side=True)

class ThreadedLurkHTTPserver(PoolMixIn, LurkHTTPserver):
    '''
    This class represents an HTTPSserver (based on TCPServer) which launches a new thread (for each request) when a client gets connected
    This default behavior is modified by extending the PoolMixIn class instead of ThreadingMixIn to handle a specific number of requests(max_workers) in parallel
    '''

    def __init__(self, conf=default_conf,  max_workers=40, secureTLS_connection=False):
        '''
        This is a constructor to initialize an HTTP server that handles multiple requests at the same time.
        The code is a copy of the LurkHTTPserver constructor (Note: calling the super constructor calls the LurkServer constructor which causes an error)
        :param conf: the configuration
        :param max_workers: max number of HTTP requests to handle in parallel
        '''

        #set the pool attribute to allow multithreading
        self.pool = ThreadPoolExecutor(max_workers)

        conf['connectivity']['type'] = 'http'


        LurkServer.__init__(self, conf, secureTLS_connection)

        # this will allow reusing the same address for multiple connections
        self.allow_reuse_address = True

        # initialize the httpserver
        server_address = (self.conf.server.ip_address, self.conf.server.port)
        HTTPServer.__init__(self, server_address, HTTPRequestHandler)

        # secure connection by setting the context
        if (self.secureTLS_connection):
            context = self.get_context()
            # updating the httpserver socket after wrapping it with ssl context
            self.socket = context.wrap_socket(self.socket, server_side=True)



class HTTPRequestHandler (BaseHTTPRequestHandler):
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

        #send the response bytes to the client
        self.wfile.write(self.server.byte_serve(data))
        print("{}".format(threading.current_thread().name))
