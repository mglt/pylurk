import socket
from textwrap import indent
from secrets import randbits
from Cryptodome.Hash import HMAC, SHA256
from pylurk.core.conf import default_conf
from pylurk.core.lurk_struct import *
from socketserver import ThreadingMixIn, UDPServer, TCPServer, BaseRequestHandler
from concurrent.futures import ThreadPoolExecutor
from http.server import HTTPServer, BaseHTTPRequestHandler
import http.client
import ssl
from  os.path import join
import pkg_resources

import threading
HEADER_LEN = 16 
LINE_LEN = 60

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
        self.keys = [ 'type', 'ip_address', 'port' ]
        self.check_key( conf )
        self.ip_address = conf[ 'ip_address' ]
        self.port = conf[ 'port' ]

    def check_key( self, conf ):
        if set( conf.keys() ) != set( self.keys ) :
            raise ConfError( conf, "Expected keys: %s"%self.keys )

class TCPServerConf(UDPServerConf):pass

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
        if connectivity[ 'type' ] not in [ "local", "udp", "tcp" ]:
            raise ConfError( connectivity, "Expected type as 'local' "+\
                                            "or 'udp' or 'tcp'" )
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


    def get_server( self ):
        con = self.conf[ 'connectivity' ]
        if con[ 'type' ] == "local" :
            return LocalServerConf( )
        if con[ 'type' ] == "udp" :
            return UDPServerConf( conf=con )
        if con[ 'type' ] == "tcp" :
            return TCPServerConf( conf=con )

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
            self.conf[ 'connectivity' ] = \
                { 'type' : "udp", 'ip_address' : ip, 'port' : port }
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
            self.conf[ 'connectivity' ] = \
                { 'type' : "tcp", 'ip_address' : ip, 'port' : port }
        else: 
            raise ConfError( kwargs[ 'type' ], "Expecting 'local', 'udp', 'tcp' ")


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

    def __init__(self, conf=default_conf, secureTLS_connection=False ):
        self.init_conf( conf )
        self.conf = LurkConf( conf )
        self.conf.set_role( 'server' )
        self.message = LurkMessage( conf=self.conf.conf )

        # specify that we need to use TCP TLS
        self.secureTLS_connection = secureTLS_connection

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

    def get_context(self):
        '''
        This method sets the ssl context for a secure connection with the client.
        To do: enhance this method to load the certificates from the configuration.

        :return: ssl context object
        '''

        data_dir = pkg_resources.resource_filename(__name__, '../data/')

        #path to server certificate
        server_cert = join( data_dir,'cert_tls12_rsa_server.crt')

        #path to server key
        server_key = join( data_dir,'key_tls12_rsa_server.key')

        #path to client certificates
        client_certs = join( data_dir,'cert_tls12_rsa_client.crt')

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

class LurkClient:

    def __init__( self, conf=default_conf, secureTLS_connection=False):
        self.init_conf( conf )
        self.conf = LurkConf( conf )
        self.waiting_queries = {}
        self.server = self.get_server()
        self.message = LurkMessage( conf = self.conf.conf )

        #specify that we need to use TCP TLS
        self.secureTLS_connection = secureTLS_connection

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

    def is_response(self, response):
        try:
            query = self.waiting_queries[ response [ 'id' ] ]
            del self.waiting_queries[ response [ 'id' ] ]
            return True
        except KeyError:
            return False

    def get_context(self):
        '''
        This method sets the ssl context for a secure connection with the server.
        To do: enhance this method to load the certificates from the configuration.

        :return: ssl context object
        '''

        data_dir = pkg_resources.resource_filename(__name__, '../data/')

        # path to server key
        client_key = join(data_dir, 'key_tls12_rsa_client.key')

        # path to client certificates
        client_certs = join(data_dir, 'cert_tls12_rsa_client.crt')

        # context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=join( data_dir, 'server.crt' )) #used for default context selected by ssl

        #set the context to use TLS12
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)

        #load the client key and certificate
        context.load_cert_chain(certfile= client_certs, keyfile=client_key)

        return context


class LurkUDPClient(LurkClient):

    def __init__(self, conf=default_conf ):
        self.init_conf( conf )
        self.conf = LurkConf( conf )
        self.waiting_queries = {}
        self.server = self.get_server()
        self.message = LurkMessage( conf = self.conf.conf )

    def get_server( self):
         sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
         sock.settimeout(1.0)
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

class LurkUDPServer:

    def __init__(self,conf=default_conf):
        self.lurk = LurkServer( conf )

    def serve_client(self):
        """
        This method is used to serve a single client without invoking any threading functionaliy
        """
        #create and bind socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip = self.lurk.conf.server.ip_address
        port = self.lurk.conf.server.port
        sock.bind((ip, port))

        #recieve client request and reply
        while True:
          data, address = sock.recvfrom(4096)
          sock.sendto( self.lurk.byte_serve(data), address)

        #close socket
        sock.close()

    def get_thread_udpserver(self, max_workers=40):

       """
       This method is used whenever we want to use threding for UDPServer.
       :param max_workers: maximum number of threads (requests) to handle at a time
       :return: an instance of the ThreadedUDPServer from which we can have access to the server socket and client data
       """
       ip = self.lurk.conf.server.ip_address
       port = self.lurk.conf.server.port

       #create a UDP server (socket) bind the host (ip) to the port (port)
       server = ThreadedUDPServer((ip, port), UDPHandler, self.lurk, max_workers)
       return server

class PoolMixIn(ThreadingMixIn):

    def process_request(self, request, client_address):
        '''
        Override the process_request () in ThreadingMixIn
        This method is called by handle_request() pre-defined in BaseServer(in out case; ThreadedUDPServer, ThreadedTCPServer) class which is the superclass of UDPServer and TCPServer
        :param request:
        :param client_address:
        '''

        #call the process_request_thread () defined in ThreadingMixIn for each request in the pool
        self.pool.submit(self.process_request_thread, request, client_address)


class ThreadedUDPServer(PoolMixIn, UDPServer):
    '''
     This class represents a UDPServer which launches a new thread (for each request) when a client gets connected
     This default behavior is modified by extending the PoolMixIn class instead of ThreadingMixIn to handle a specific number of requests(max_workers) in parallel
    '''
    def __init__(self, server_info, udp_handler, lurkserver, max_workers=40):
        """
        Override the method to pass the lurk serversince it is needed to be able to call the byte_serve in UDPHandler.handle()
        :param server_info:(ip, port) on which the UDP server is listening
        :param UDPHandler: object of the UDPHandler class
        :param lurkserver: object of the LurkServer
        :param max_workers: maximum number of threads (requests) to handle at a time
        """
        #super(UDPServer, self).__init__(server_info, udp_handler)
        super(PoolMixIn, self).__init__(server_info, udp_handler)
        self.lurkServer = lurkserver
        self.pool = ThreadPoolExecutor(max_workers)


class UDPHandler(BaseRequestHandler):
    """
     This class works similar to the TCP handler class, except that
    self.request consists of a pair of data and client socket, and since
    there is no connection, the client address must be given explicitly
    when sending data back via sendto().
    An object of this class is instantiated whenever there is a new client request
    """

    def handle(self):
        """
             This method handles the processing for each request
        """
        #get data sent by the client to the server up to 8192 bytes
        data = self.request[0]

        #get the server socket
        socket = self.request[1]

        #manipulate the data and send it to the client
        #self.server is a ThreadedUDPServer
        socket.sendto(self.server.lurkServer.byte_serve(data), self.client_address)

        #socket.close()
        print("{} data:".format(threading.current_thread().name))
        print(data)

class LurkTCPClient(LurkClient):

    def __init__(self, conf=default_conf, secureTLS_connection=False):
        conf['connectivity']['type'] = 'tcp'

        #could not call super constructor as it was throwing an init_conf error
        self.init_conf(conf)
        self.conf = LurkConf(conf)
        self.waiting_queries = {}

        # specify that we need to use TCP TLS
        self.secureTLS_connection = secureTLS_connection

        self.server = self.get_server()
        self.message = LurkMessage(conf=self.conf.conf)



    def get_server( self):
         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

         if (self.secureTLS_connection):
             context = self.get_context()
             sock = context.wrap_socket(sock, server_side=False,server_hostname= self.conf.server.ip_address) #server_hostname='example.com' (this is the common name when generating the certificate)

         sock.settimeout(1.0)

         return sock

    def send(self, bytes_pkt):
         '''
         This method will connect the client to the server and send the bytes_pkt and recieve the response
         Important notes:
             1- We prevent the client to reconnect each time it tries to send a request.
             For that, we start by trying to send the bytes, if connection is lost of no connection is established a socket exception will be thrown and hence, the client will try to connect to server and re-send the bytes
             2- Use a buffer of 4096
             It is important to keep the buffer = 4096 and not less (i.e. 1024) to prevent a timeout error and a failure to reconnect when trying to send an 'rsa_extended_master' and capabilities

         :param bytes_pkt: bytes to send t server
         :return: recieved bytes (parsed)
         '''

         while True:
            try:
                #try to send first to check if there is a connection established
                self.server.sendall(bytes_pkt)
                response_bytes = self.server.recv(4096)
                waiting = True
                while waiting == True:
                    response_bytes = self.server.recv(4096)
                    response = self.message.parse(response_bytes)
                    if self.is_response(response) == True:
                       waiting = False
                return response
            #catch any error mainly if no connection exists
            except socket.error:
                try:
                    return response_bytes
                except:
                    ImplementationError('', "Unable resolve")

                # set connection status and recconnect
                connected = False

                while not connected:
                    #attempt to reconnect
                    try:
                        ip = self.conf.server.ip_address
                        port = self.conf.server.port
                        self.server.connect( ( ip, port ) )
                        connected = True
                    except socket.timeout:
                        print("timeout")

         self.server.close()



class LurkTCPServer(LurkServer):

    def __init__(self,conf=default_conf, secureTLS_connection=False):
        conf['connectivity']['type'] = 'tcp'
        LurkServer.__init__(self, conf, secureTLS_connection)

    def serve_client(self):
        """
        This method is used to serve a single client without invoking any threading functionality
        It only allows the connection of one client to the server.
        Unlike UDP where multiple clients can be handled sequentially, with TCP, for the server to handle multiple clients threading is needed.
        https://stackoverflow.com/questions/10810249/python-socket-multiple-clients/46980073
        """
        #create and bind socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ip = self.conf.server.ip_address
        port = self.conf.server.port

        #allow address reuse to prevent OS error that the address is already in use when binding
       # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        sock.bind((ip, port))
        sock.listen(1)


        #conn: a new socket object used to send and recv data; addr address of the client
        conn, addr = sock.accept()

        if (self.secureTLS_connection):
            context = self.get_context()
            conn =context.wrap_socket(conn, server_side=True)

        #recieve client request and reply
        while True:
          data = conn.recv(4096)
          conn.sendall( self.byte_serve(data))

        #close socket
        conn.close()

        sock.close()
