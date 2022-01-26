import logging
from struct_lurk import LURKMessage, LURKHeader 
from lurk_lurk   import LURKError, ImplementationError, ConfigurationError, LurkExt 
from lurk_tls13  import Tls13Ext 

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

class CryptoService:
  def __init__( self, conf, ):
    self.conf = conf
    
    for ext in self.conf[ 'enabled_extensions' ]:
      if ext == ( 'lurk', 'v1' ):
        self.lurk = LurkExt( self.conf  )
      elif ext == ( 'tls13', 'v1' ):
        self.tls13 = Tls13Ext( self.conf[ ext ]  )
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
      if ext == ( 'lurk', 'v1' ):
        payload = self.lurk.payload_resp( req ) 
      elif ext == ( 'tls13', 'v1' ):
        payload = self.tls13.payload_resp( req )
      else:
        raise LURKError( 'invalid_extension' , f"{ext}" )
#      resp[ 'payload' ] = { 'lurk_state' : self.lurk_state }
      resp[ 'payload' ] = payload
      resp[ 'status' ] = 'success'
      return LURKMessage.build( resp )
    except Exception as e :
      if isinstance( e, LURKError ):
        resp[ 'status' ] = e.status
      else:
        if isinstance( e, ImplementationError ) or isinstance( e, ConfigurationError ):
          self.logger.error( f"{e.status} : {e.message}" )
        else: 
          self.logger.exception( str( e ) )  
        resp[ 'status' ] = 'undefined_error' 
      resp[ 'payload' ] = { 'lurk_state' : self.lurk_state }
      return LURKMessage.build( resp )

