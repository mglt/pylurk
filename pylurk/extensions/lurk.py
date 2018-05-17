from construct import *
from construct.lib import *
from pylurk.core.lurk_struct import LURKCapabilitiesResponsePayload
from pylurk.core.lurk import InvalidFormat, ImplementationError,\
                      ConfError, LurkConf, Payload
from pylurk.core.conf import default_conf
   
class LurkCapabilitiesResponsePayload( Payload ):

    def __init__( self, conf=default_conf):
        self.conf = LurkConf( conf )
        self.struct = LURKCapabilitiesResponsePayload

    def build_payload( self, **kwargs ):
        if 'supported_extensions' in kwargs.keys():
            supported_extensions = kwargs[ 'supported_extensions' ]
        else :
            supported_extensions = []
            for ext in self.conf.supported_extensions:
                supported_extensions.append( { 'designation' : ext[0], 'version' : ext[ 1 ] } ) 
        if 'lurk_state' in kwargs.keys():
            lurk_state = kwargs[ 'lurk_state' ]
        else:
            lurk_state = self.conf.get_state( ("lurk", "v1") )
        return { 'supported_extensions' : supported_extensions, \
                 'lurk_state' : lurk_state } 

    def check( self, payload ):
        for ext in payload[ 'supported_extensions' ]:
            ext = ( ext[ 'designation' ], ext[ 'version' ] ) 
            if ext not in self.conf.supported_extensions :
                raise InvalidExtension( ext, "Expected:%s"% \
                          self.conf.supported_extensions )

    def serve( self, request ):
        if len( request ) != 0:
            raise InvalidFormat( kwargs, "Expected {}")
        return self.build_payload( **request )


class LurkVoidPayload:

    def build_payload( self, **kwargs ):
        if len( kwargs.keys() ) != 0:
            raise InvalidFormat( kwargs, "Expected {}")
        return {}

    def build(self, **kwargs ):
        if len( kwargs.keys() ) != 0:
            raise InvalidFormat( kwargs, "Expected {}")
        return b''

    def serve( self, request ) :
        return {}

    def parse( self, pkt_bytes ) :
        if pkt_bytes != b'':
            raise InvalidFormat( request, "Expected b'' ")
        return {}

    def check( self, payload ):
        if payload != {}:
            raise InvalidFormat( payload, "Expected {}") 
    
    def show( self, pkt_bytes ):
        print("Void Payload") 

class LurkExt:

    def __init__(self, conf=default_conf ) :
        self.conf = LurkConf( conf )
        self.ext_class = self.get_ext_class() 

    
    def get_ext_class( self):
        ext_class = {}
        if 'ping' in self.conf.get_mtypes()[ 'lurk', 'v1' ]: 
            ext_class[ ( 'request', 'ping' ) ] = LurkVoidPayload( )
            ext_class[ ( 'success', 'ping' ) ] = LurkVoidPayload( ) 
        if 'capabilities' in self.conf.get_mtypes()[ 'lurk', 'v1' ] : 
            ext_class[ ( 'request', 'capabilities' ) ] = LurkVoidPayload( ) 
            ext_class[ ( 'success', 'capabilities' ) ] = \
                LurkCapabilitiesResponsePayload( conf=self.conf.conf ) 
        return ext_class


    def check_conf( self, conf ):
        for k in conf.keys():
            if k is 'role' :
                if conf[ k ] not in [ 'client', 'server' ]:
                    raise ConfError( conf, "Expecting role in  'client'" +\
                                           "'server'")
            elif k in [ 'ping', 'capabilities' ]:
                if type( conf[ k ] ) != list:
                    raise ConfError( conf[ k ], "Expected list")
                if len( conf[ k ] ) > 1: 
                    raise ConfError( conf[ k ], "Only len = 1 is currently " +\
                                                "supported")
                else:
                    raise ConfError( conf, "unexpected key %s"%k )


    def parse( self, status, mtype, pkt_bytes ):
        """ parse the byte array into containers. The same status code
            is used are used and response is indicated by "success" """
        return self.ext_class[ ( status, mtype ) ].parse( pkt_bytes )

    def build( self, status, mtype, **kwargs):
        return self.ext_class[ ( status, mtype ) ].build( **kwargs )

    def serve( self, mtype, request  ):
        return self.ext_class[ ( 'success' , mtype ) ].serve( request )

    def check( self, status, mtype, payload ):
        return self.ext_class[ ( status, mtype ) ].check( payload )

    def show( self, status, mtype, payload ):
        return self.ext_class[ ( status, mtype ) ].show( payload )


