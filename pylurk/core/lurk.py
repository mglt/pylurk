import socket
from secrets import randbits
from Cryptodome.Hash import HMAC, SHA256
from pylurk.core.conf import default_conf
from pylurk.core.lurk_struct import *

HEADER_LEN = 16 

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
        if connectivity[ 'type' ] not in [ "local", "udp" ]:
            raise ConfError( connectivity, "Expected type as 'local' "+\
                                            "or 'udp'" )
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
        else: 
            raise ConfError( kwargs[ 'type' ], "Expecting 'local', 'udp' ")


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
        self.conf = conf
        self.struct = None

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

    def show(self, pkt_bytes ):
        """ shows the pkt_bytes. Similar to parse but without any
            control of the configuration and uses the structure
            visualization facilities. """
        print("%s"%self.struct.__class__.__name__)
        print("%s"%self.struct.parse(pkt_bytes))




class LurkMessage( Payload ):

    def __init__( self, conf=default_conf ):
        self.conf = LurkConf( conf )
        self.struct = LURKHeader
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

    def show_ext_payload( self, header, payload_bytes ):
        status = header[ 'status' ]
        mtype = header[ 'type' ]
        if status not in [ 'request', 'success' ]:
            raise ImplementationError( status, "Expected 'request' or 'success'")
        return  self.get_ext( header ).show( status, mtype, payload_bytes )


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
            
            
    def show(self, pkt_bytes ):
        print("%s"%self.struct.__class__.__name__)
        if type ( pkt_bytes ) == dict:
            self.check( pkt_bytes )
            pkt_bytes = self.build( **pkt_bytes )
        if len( pkt_bytes) < HEADER_LEN :
            print("Not enough bytes, cannot parse LURK Header" )
            print("Expecting %s, got %s"%( HEADER_LEN, len( pkt_bytes) ) )
            print("pkt_bytes: %s"%pkt_bytes )
        else: 
            print("%s"%self.struct.parse(pkt_bytes[ : HEADER_LEN] ))
            header = self.struct.parse(pkt_bytes[ : HEADER_LEN ] )
            if len( pkt_bytes ) >= header[ 'length' ]:
                payload_bytes = pkt_bytes[ HEADER_LEN : header[ 'length'] ]
            else:
                raise InvalidFormat( ( header, pkt_bytes ), \
                          "pkt_bytes too short %s bytes"%len (pkt_bytes ) )
            if header[ 'status' ] in [ "success", "request" ]:
                self.show_ext_payload( header, payload_bytes ) 
            else: ## the payload is an error payload
                LURKErrorPayload.parse( payload_bytes )

class LurkServer():

    def __init__(self, conf=default_conf ):
        self.conf = LurkConf( conf )
        self.conf.set_role( 'server' )
        self.message = LurkMessage( conf=self.conf.conf ) 

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


class LurkClient:

    def __init__( self, conf=default_conf): 
        self.conf = LurkConf( conf )
        self.conf.set_role( 'client' )
        self.waiting_queries = {}
        self.server = self.get_server(  ) 
        self.message = LurkMessage( conf = self.conf.conf )

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
        

class LurkUDPClient(LurkClient):

    def __init__(self, conf=default_conf ):
        self.conf = LurkConf( conf )
        self.conf.set_role( 'client' )
        self.waiting_queries = {}
        self.server = self.get_server( self.conf )
        self.message = LurkMessage( conf = self.conf.conf )

    def get_server( self, server_conf):
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

    def __init__(self, conf=default_conf ):

        self.conf = LurkConf( conf )
        self.conf.set_role( 'server' )
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip = self.conf.server.ip_address
        port = self.conf.server.port
        self.sock.bind( ( ip, port) )
        self.lurk = LurkServer( self.conf.conf )

        while True:
            data, address = self.sock.recvfrom(4096)
            self.sock.sendto( self.lurk.byte_serve( data ) , address)

        self.sock.close()

