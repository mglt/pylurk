## lurk_message handling
import pickle
#import cloudpickle
#import joblib
from cryptography.hazmat.primitives.hashes import Hash, SHA256
#from copy import deepcopy


class LURKError(Exception):
  def __init__(self, status:str,  message:str="" ):
    """ Generic Error class

    Args:
      expression : provides the python structures that generated the error
      message (str) : is a human readable message
      status (int) : the error number, that is the number returned in the LURK Header
      payload (dict) : a potential payload carried by the LURK Error Message
    """
    self.status = status
    self.message = message

class ImplementationError( LURKError ):
  def __init__(self, message:str ):
    """ Error that are related to the implementation """
    self.status = 'implementation_error'
    self.message = message

class ConfigurationError( LURKError ):
  def __init__(self, message:str ):
    """ Error that are related to the implementation """
    self.status = 'configuration_error'
    self.message = message


class LurkExt:

  def __init__( self, conf ):
    """ handles LURK messages """
    self.conf = conf
    self.lurk_state = self.get_lurk_state()

  def payload_resp( self, req: dict ) -> dict :
    if req[ 'type' ] == 'ping':
      payload = {}
    elif req[ 'type' ] == 'capabilities':
      supported_ext = []
      for ext in self.conf[ 'enabled_extensions' ]:
        supported_ext.append( { 'designation' : ext[ 0 ],
                                'version' : ext[ 1 ] } )
      payload = { 'supported_extensions' : supported_ext,
                  'lurk_state' : self.lurk_state }
    else:
      raise ImplementationError( 'invalid_type' )
    return payload

  ## NEEDS to be implemented. We are currently unable to copy,
  ## dump the self.conf object. It seems we are not able to copy
  ## the '_XXX' keys - as if we coudl not access the memory. One
  ## way may be to implement a function in the Configuration that
  ## is able to dump the self.conf...
  def get_lurk_state( self ):
    """ issue states from the configuration  """
    h = Hash( SHA256( ) )
#    conf = deepcopy( self.conf )
#    print( f" con: {conf}" )
    h.update( pickle.dumps( self.conf[ ( 'lurk', 'v1' ) ] ) )
#    h.update( cloudpickle.dumps( self.conf ) )
#    h.update( bytes( self.conf, 'utf-8' ) )
    digest = h.finalize( )
#    digest = joblib.hash( self.conf, hash_name='sha1', coerce_mmap=False)
    return digest[ : 4 ]


