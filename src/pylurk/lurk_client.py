import secrets
import pylurk.tls13.struct_lurk_tls13
from pylurk.struct_lurk import LURKMessage

class LurkTls13Client :

  def __init__( self, cs ):
    self.lurk_client_session_id = secrets.token_bytes( 4 )
    self.cs_session_id  = None
    self.freshness = 'sha256'
    self.cs = cs

  def secret_req( self, **kwargs ):
    secret_req = { 'b' : False, 'e_s' : False, 'e_x' : False, \
                   'h_c' : False, 'h_s' : False, 'a_c' : False, \
                   'a_s' : False, 'x' : False, 'r' : False }
    if 'secret_request' in kwargs.keys():
      for k in secret_req.keys():
        if k in kwargs[ 'secret_request' ]:
          secret_req[ k ] = True
    return secret_req

  def session_id( self, req_type, **kwargs ):
    """ handles the session id field between cs_session_id and engine_session_id """
    if 'session_id' in kwargs.keys():
      session_id = kwargs[ 'session_id' ]
    elif req_type == 'c_init_client_finished' :
      tag = self.tag( **kwargs )
      if tag[ 'last_exchange' ] is True:
        session_id = b''
      else:
        session_id =  self.lurk_client_session_id
    elif '_init_' in req_type :
      session_id =  self.lurk_client_session_id
    else:
      session_id = self.cs_session_id
    return session_id

  def fresh( self, **kwargs ):
    if 'freshness' in kwargs.keys():
      freshness = kwargs[ 'freshness' ]
      self.freshness = freshness
    else:
      freshness = self.freshness
    return freshness

  def tag( self, **kwargs ):
    """ set the tag structure ccording to the last_exchange value """
    if 'tag' in kwargs.keys() :
      tag = kwargs[ 'tag' ]
    elif 'last_exchange' in kwargs.keys():
      tag = { 'last_exchange' : kwargs[ 'last_exchange' ] }
    else :
      tag = { 'last_exchange' : True }
    return tag

  def req( self, req_type, **kwargs ):
    payload = {}
    if req_type == 'c_init_client_hello':
      try:
        psk_metadata_list = kwargs[ 'psk_metadata_list' ]
      except KeyError:
        psk_metadata_list = [] ## no psk
      try:
        secret_request = kwargs[ 'secret_request' ]
      except KeyError:
          secret_request = [ 'b', 'e_s', 'e_x' ]
     
      payload = { \
        'session_id' : self.session_id( req_type, **kwargs ),
        'handshake' : kwargs[ 'handshake' ],
        'freshness' : self.fresh( **kwargs ) ,
        'psk_metadata_list' : psk_metadata_list, 
        'secret_request' : self.secret_req( **kwargs )
      }       
    elif req_type == 'c_server_hello':
      payload = { \
        'session_id' : self.session_id( req_type, **kwargs ),
        'handshake' : kwargs[ 'handshake' ],
        'ephemeral' : kwargs[ 'ephemeral' ] 
      }
    elif req_type == 'c_client_finished':
      payload = { \
        'tag' : self.tag( **kwargs ), 
        'session_id' : self.session_id( req_type, **kwargs ),
        'handshake' : kwargs[ 'handshake' ],
        'server_certificate' : kwargs[ 'server_certificate' ], 
        'client_certificate' : kwargs[ 'client_certificate' ], 
        'secret_request' : self.secret_req( **kwargs )
      }
    elif req_type == 'c_register_tickets':
      payload = { \
        'tag' : self.tag( **kwargs ), 
        'session_id' : self.session_id( req_type, **kwargs ),
        'ticket_list' : kwargs[ 'ticket_list' ]
      }
    elif req_type == 'c_init_client_finished' :
      payload = { \
        'tag' : self.tag( **kwargs ), 
        'session_id' : self.session_id( req_type, **kwargs ),
        'handshake' : kwargs[ 'handshake' ],
        'server_certificate' : kwargs[ 'server_certificate' ], 
        'client_certificate' : kwargs[ 'client_certificate' ], 
        'freshness' : self.fresh( **kwargs ) ,
        'ephemeral' : kwargs[ 'ephemeral' ],
        'psk' : kwargs[ 'psk' ]
      }
    
    else:
      raise ValueError( f"Unknown request type {req_type}" )
    lurk_req = \
      { 'designation' : 'tls13',
        'version' : 'v1', 
        'type' : req_type,
        'status' : 'request',
        'id' : secrets.randbelow( 2  ** 64 ), ## MUST be int 
        'payload' : payload }
    return lurk_req

  def resp( self, req_type, **kwargs ):
    lurk_req = self.req( req_type, **kwargs )
#    print( f"____ {lurk_req}" )
    print( f"--- E -> CS: Sending {req_type} Request:" )
#    print( f"--- E -> CS: {lurk_req }" )
#    if lurk_req[ 'type' ] == 'c_server_hello' :
#      print( f"--- E -> CS: ephemral { pylurk.tls13.struct_lurk_tls13.Ephemeral.build( lurk_req[ 'payload' ][ 'ephemeral' ], _status='request', )}" )  
#      print( f"  - build: {LURKMessage.build( lurk_req )}" )
#    print( f"  - {LURKMessage.parse( LURKMessage.build( lurk_req ) )}" )
    lurk_resp = LURKMessage.parse( self.cs.serve( LURKMessage.build( lurk_req ) ) )
    if lurk_resp[ 'status' ] != 'success':
      raise ValueError( f"Lurk exchange error: {lurk_resp}" )
    print( "--- E <- CS: Receiving {req_type} Response:" )
#    print( f"  - {LURKMessage.parse( LURKMessage.build( lurk_resp ) )}" )
    ## updating the session_id (sending)
    if '_init_' in req_type :
      try:
        self.cs_session_id = lurk_resp[ 'payload' ][ 'session_id' ]
      except:
        pass
    return lurk_resp

class LurkTls13TCPClient :
  pass

