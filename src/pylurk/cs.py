import logging
from pylurk.struct_lurk import LURKMessage, LURKHeader 
from pylurk.lurk.lurk_lurk   import LURKError, ImplementationError, ConfigurationError, LurkExt 
import sys
sys.path.insert(0, '/home/emigdan/gitlab/pylurk.git/src/')
import pylurk.tls13.lurk_tls13 
import pylurk.debug
#from pylurk.tls13.lurk_tls13  import Tls13Ext, TicketDB, SessionDB 

MINIMUM_PACKET_SIZE = 16
HEADER_SIZE = 12

def logger( conf, __name__ ):
  try:
    log_file = conf[ 'log' ]
  except KeyError :
    log_file = './crypto_service.log'
  logger = logging.getLogger(__name__)
  FORMAT = "[%(asctime)s : %(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
  logger.setLevel( logging.DEBUG )
  logging.basicConfig(filename=log_file, format=FORMAT )
  return logger

class BaseCryptoService:
  def __init__( self, conf ):
    self.con_type = 'lib_cs'
    self.conf = conf
    
    for ext in self.conf[ 'enabled_extensions' ]:
      if ext == ( 'lurk', 'v1' ):
        self.lurk = LurkExt( self.conf  )
      elif ext == ( 'tls13', 'v1' ):
        self.ticket_db = pylurk.tls13.lurk_tls13.TicketDB()
        self.session_db = pylurk.tls13.lurk_tls13.SessionDB()

        self.debug = None
        debug_conf = self.conf[ ext ][ 'debug' ]
        debug = pylurk.debug.Tls13Debug( debug_conf )
        if debug.trace is True or debug.test_vector is True: 
          self.debug = debug

#          if ( debug_conf[ 'test_vector' ][ 'file' ] and debug_conf[ 'test_vector' ][ 'mode' ] is True or\
#             debug_conf[ 'trace' ] is True :
#          self.debug = pylurk.debug.Tls13Debug( debug_conf ) 

        self.tls13 = pylurk.tls13.lurk_tls13.Tls13Ext( self.conf[ ext ],\
                       ticket_db=self.ticket_db,\
                       session_db=self.session_db,\
                       debug=self.debug )

#        raise ValueError( )
    try: 
      self.lurk_state = self.lurk.lurk_state 
    except NameError:
      raise Implementation( 'configuration', f"( 'lurk', 'v1' ) MUST be enabled" )
    self.logger = logger( self.conf, __name__ ) 

  def serve( self, req_bytes ) -> bytes :
    """ returns a binary response """
    if len( req_bytes ) < MINIMUM_PACKET_SIZE :
      return b''
    
    try : 
      header = LURKHeader.parse( req_bytes[ : HEADER_SIZE ] )  
      resp = { 'designation' : header[ 'designation' ], 
               'version' : header[ 'version' ], 
               'type' : header[ 'type' ],
               'status' : None,
               'id' : header[ 'id' ],
               'payload' : {} }
      ext = ( header[ 'designation' ], header[ 'version' ] )
      if ext  not in self.conf[ 'enabled_extensions' ] :
        raise LURKError( 'invalid_extension' , f"{ext}" )
      if header[ 'type' ] not in self.conf[ ext ] [ 'type_authorized' ] :
        raise LURKError( 'invalid_type' , f"{header[ 'type' ]}" )
      if header[ 'status' ] != 'request' :
        raise LURKError( 'invalid_status' , f"{header[ 'status' ]}" )
      req = LURKMessage.parse( req_bytes )
      if self.debug is not None:
        self.debug.handle_lurk_msg( req )
      if ext == ( 'lurk', 'v1' ):
        payload = self.lurk.payload_resp( req ) 
      elif ext == ( 'tls13', 'v1' ):
        payload = self.tls13.payload_resp( req )
      else:
        raise LURKError( 'invalid_extension' , f"{ext}" )
#      resp[ 'payload' ] = { 'lurk_state' : self.lurk_state }
      resp[ 'payload' ] = payload
      resp[ 'status' ] = 'success'
      if self.debug is not None:
#        self.test_vector.handle_lurk_msg( req )
        self.debug.handle_lurk_msg( resp)
#      print( f"--- resp: {resp}" )
#
      return LURKMessage.build( resp )
    except Exception as e :
      if isinstance( e, LURKError ):
        resp[ 'status' ] = e.status
        self.logger.info( f"{str( e )} - {e.message}" )  
      else:
        if isinstance( e, ImplementationError ) or isinstance( e, ConfigurationError ):
          self.logger.error( f"{e.status} : {e.message}" )
        else: 
          self.logger.exception( str( e ) )  
        resp[ 'status' ] = 'undefined_error' 
      resp[ 'payload' ] = { 'lurk_state' : self.lurk_state }
      print( f"--- CS: Returned Response by the CS:" )
      print( f"  - {LURKMessage.parse( LURKMessage.build( resp ) )}")
      print( f"--- crypto service: resp : {resp}")
      return LURKMessage.build( resp )

import socketserver

class StatelessTCPHandler( socketserver.BaseRequestHandler):
  """ the StatelessTCPHandler assumes that the packet it handles 
      contains only one LURK request. 
      TCP ensures all bytes are transported but a TCP session is 
      established for every LURK request.
  """
  def handle( self ):
    req_bytes = self.request.recv(4096)
    resp = self.server.cs.serve( req_bytes ) 
    self.request.sendall( resp )

class StatelessTCPCryptoService( socketserver.TCPServer):

  def __init__( self, conf  ):
    """ 
    
    The stateless TCP Crypto Service handles one TCP session per
    packet.  
    The StatelessTCP server extends the TCP calls to instantiate 
    a crypto service as self.cs. 
    """
    
    self.con_type = 'stateless_tcp'
    self.conf = conf
    self.cs = BaseCryptoService( self.conf )
    server_address = self.get_server_address_from_conf( )  
    super().__init__( server_address, StatelessTCPHandler,\
                       bind_and_activate=True )

  def get_server_address_from_conf( self ):
    """ return host and port from the configuration file """
    key_list = self.conf[ 'connectivity' ].keys()
    if 'type' in key_list: 
      cs_type = self.conf[ 'connectivity' ][ 'type' ]
      if cs_type != self.con_type:
        raise ConfigurationError( f"unexpected type {cs_type} for "\
          f"{self.__class__.__name__}. Expecting '{self.con_type}'." )
    else:
      raise ConfigurationError( f"Cannot find type in configuration "\
        f"{self.__class__.__name__}. Expecting 'stateless_tcp'." ) 
    host = None 
    if 'fqdn' in key_list:
      fqdn = self.conf[ 'connectivity' ][ 'fqdn' ]
      if fqdn not in [ None, '' ]:
        host = fqdn
    if host is None and 'ip' in key_list: 
      host = self.conf[ 'connectivity' ][ 'ip' ]
    if 'port' in key_list: 
      port = self.conf[ 'connectivity' ][ 'port' ] 
    else:
      raise ConfigurationError( f"Cannot find port in configuration "\
        f"{self.__class__.__name__}." )
    return ( host, port )
#    with socketserver.TCPServer((host, port), MyTCPHandler) as server:
#        # Activate the server; this will keep running until you
#        # interrupt the program with Ctrl-C
#        server.serve_forever()  

def get_cs_instance( conf ):
  """ returns appropriated Cryptographic Service instance from conf 

  """
  con_type = conf[ 'connectivity' ][ 'type' ] 
  if con_type == 'lib_cs':
    cs = BaseCryptoService( conf )
  elif con_type == 'stateless_tcp':
    cs = StatelessTCPCryptoService( conf )
  else:
    raise ConfigurationError( f"unknown connection_type {con_type}" )
  return cs

##class CryptoService:
##
##  def __init__( self, conf ):
##    self.conf = conf
##    self.con_type = self.conf[ 'connectivity' ][ 'type' ] 
##    if self.con_type == 'lib_cs':
##      self.cs = BaseCryptoService( self.conf )
##      BaseCryptoService.__init__( self,  self.conf )
##    elif self.con_type == 'stateless_tcp':
##      self.cs = StatelessTCPCryptoService( self.conf )
###      StatelessTCPCryptoService.__init__( self, self.conf )
##    else:
##      raise ConfigurationError( f"unknown connection_type {con_type}" )
##
##  def serve( self, req_bytes ) -> bytes :
##    if self.con_type == 'lib_cs':
##      return self.cs.serve( req_bytes )
##    else: 
####      self.serve_forever()
##      ImplementationError( f"'serve' can only be used for con_type {self.con_type}."\
##                            "Current con_type is set to {self.con_type}")
## 
##  def serve_forever( self ):
##    self.cs.serve_forver()
