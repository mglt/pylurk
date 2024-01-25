import secrets
import select
import socket
import selectors
import pylurk.tls13.struct_lurk_tls13
from pylurk.struct_lurk import LURKMessage, LURKHeader
from pylurk.lurk.lurk_lurk import ConfigurationError, LURKError
import pylurk.cs

class BaseTls13LurkClient :

  """ The base class for the TLS 1.3 LURK client.

  This class defines an API to format LURK requests and handle
  the LURK responses.
  In addition, this class enables the LURK Client to interacts
  with a CS that is implemented via a library.
  When used in that context, the CS MUST be provided as an object.
  The CS can be set to None when no interaction is being
  requires with the CS.
  This is mostly used in the case where classes inherite from the
  class to format the LURK requests and handle the LURK response
  but handle the communication between the LURK client and teh CS
  on their own.

  Attributes:
    conf: a dictionnary that carries all configuration parameters
    lurk_client_session_id: the session ID of the session between
      the LURK client and the LURK server (or CS). Note that the
      intent is that the client is having a single session with
      the server, and all queries are carried via this session.
      The session id consists of 4 byte randomly generated at
      the instantiation of the LURK client
    freshness: the freshness algorithm used between the LURK
      client and teh CS. BY default it is set to 'sha256'.
    cs: the instance of the CS to which the LURK client is connected.
      This parameter is only provided when the LURK client and
      the CS are having a connection type of type 'lib_cs',
      otherwise it is set to None.
  """

  def __init__( self, conf:dict={ 'connection_type' : 'lib_cs',
                                  'freshness' : 'sha256' },
                       cs=None ):

    self.conf = conf
#    self.con_type = 'lib_cs'
    self.lurk_client_session_id = secrets.token_bytes( 4 )
    self.cs_session_id  = None
    self.freshness = 'sha256'
    if 'freshness' in self.conf.keys():
      self.freshness = self.conf[ 'freshness' ]
    self.cs = cs

  def secret_req( self, **kwargs ):
    """Format secret_request field of the LURK Request

    The LURK Client expresses its request for secrets as:
    secret_request = [ 'b', 'e_s', ... ]
    In other words, only the requested secrets are mentioned.
    The LURKRequest structure required all secrets type to be
    explicitly mentioned. This is performed by this function.

    Args:
      kwargs: the key word arguments or th efunction req

    Returns:
      secret_req: the structure of the secret_request field.
    """

    secret_req = { 'b' : False, 'e_s' : False, 'e_x' : False, \
                   'h_c' : False, 'h_s' : False, 'a_c' : False, \
                   'a_s' : False, 'x' : False, 'r' : False }
#    if 'secret_request' in kwargs.keys():
    if 'secret_request' in kwargs:
#      for k in secret_req.keys():
      for k in secret_req:
        if k in kwargs[ 'secret_request' ]:
          secret_req[ k ] = True
    return secret_req

  def session_id( self, req_type, **kwargs ):
    """ handles the session id field between cs_session_id and engine_session_id
    Args:
      kwargs: the key word arguments or the function req

    Returns:
      session_id: the session_id field of the request
    """

#    if 'session_id' in kwargs.keys():
    if 'session_id' in kwargs:
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
    """handles the freshness field of the LURK request (req)

    Args:
      kwargs: the key word arguments or the function req

    Returns:
      freshness: the session_id field of the request
    """

#    if 'freshness' in kwargs.keys():
    if 'freshness' in kwargs:
      freshness = kwargs[ 'freshness' ]
      self.freshness = freshness
    else:
      freshness = self.freshness
    return freshness

  def tag( self, **kwargs ):
    """ set the tag structure ccording to the last_exchange value """
#    if 'tag' in kwargs.keys() :
    if 'tag' in kwargs :
      tag = kwargs[ 'tag' ]
#    elif 'last_exchange' in kwargs.keys():
    elif 'last_exchange' in kwargs:
      tag = { 'last_exchange' : kwargs[ 'last_exchange' ] }
    else :
      tag = { 'last_exchange' : True }
    return tag

  def req( self, req_type, **kwargs ):
    """ a common way to express a LURK Request from the LURK client

    Args:
      kwargs: the key word arguments or the function req

    Returns:
      lurk_req: a dictionnary that represenst the LURK Request
        structure
    """
    payload = {}
    if req_type == 'c_init_client_hello':
      try:
        psk_metadata_list = kwargs[ 'psk_metadata_list' ]
      except KeyError:
        psk_metadata_list = [] ## no psk
      try:
        secret_request = kwargs[ 'secret_request' ]
      except KeyError:
        kwargs[ 'secret_request' ] = [ 'b', 'e_s', 'e_x' ]

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
    elif req_type in [ 'ping', 'capabilities' ]:
      payload = {}
    else:
      raise ValueError( f"Unknown request type {req_type}" )
    lurk_req = \
      { 'designation' : 'tls13',
        'version' : 'v1',
        'type' : req_type,
        'status' : 'request',
        'id' : secrets.randbelow( 2  ** 64 ), ## MUST be int
        'payload' : payload }
    if req_type in [ 'ping', 'capabilities' ]:
      lurk_req [ 'designation' ] = 'lurk'
    return lurk_req

  def bytes_resp( self, bytes_req:bytes ):
    """ return the byte response with the appropriated transport

    Args:
      - bytes_req: the lurk response expressed in bytes.
    """
    return self.cs.serve( bytes_req )


  def resp( self, req_type, **kwargs ):
    lurk_req = self.req( req_type, **kwargs )
#    print( f"____ {lurk_req}" )
    print( f"--- E -> CS: Sending {req_type} Request:" )
#    print( f"--- E -> CS: {lurk_req }" )
#    if lurk_req[ 'type' ] == 'c_server_hello' :
#      print( f"--- E -> CS: ephemral { pylurk.tls13.struct_lurk_tls13.Ephemeral.build( lurk_req[ 'payload' ][ 'ephemeral' ], _status='request', )}" )
#      print( f"  - build: {LURKMessage.build( lurk_req )}" )
#    print( f"  - {LURKMessage.parse( LURKMessage.build( lurk_req ) )}" )
#    print( f" lurk_req: {lurk_req}" )
#    print( f" build: {LURKMessage.build( lurk_req )}" )
#    print( f" bytes_resp : {self.bytes_resp( LURKMessage.build( lurk_req ) )}" )
    lurk_resp = LURKMessage.parse( self.bytes_resp( LURKMessage.build( lurk_req ) ) )
#    print( f"resp: {lurk_resp}" )
    if lurk_resp[ 'status' ] != 'success':
      raise LURKError( lurk_resp[ 'status' ],  f"Lurk exchange error: {lurk_resp}" )
    print( f"--- E <- CS: Receiving {req_type} Response:" )
#    print( f"  - {LURKMessage.parse( LURKMessage.build( lurk_resp ) )}" )
    ## updating the session_id (sending)
    if '_init_' in req_type :
      try:
        self.cs_session_id = lurk_resp[ 'payload' ][ 'session_id' ]
      except:
        pass
    return lurk_resp

#    if lurk_resp[ 'status' ] != 'success':
#      raise ValueError( f"Lurk exchange error: {lurk_resp}" )
#    print( "--- E <- CS: Receiving {req_type} Response:" )
#    print( f"  - {LURKMessage.parse( LURKMessage.build( lurk_resp ) )}" )
#    ## updating the session_id (sending)
#    if '_init_' in req_type :
#      try:
#        self.cs_session_id = lurk_resp[ 'payload' ][ 'session_id' ]
#      except:
#        pass
#    return lurk_resp

class TCPTls13LurkClient( BaseTls13LurkClient ) :

  def __init__( self, conf:dict ):
    """ configures the LURK client in a stateless TCP mode

    Stateless TCP means that every message is sent via a
    specific newly established TCP session

    - conf designates the configuration parameters for the CS.
      The complete configuration of the CS can be used, but only
      a subset of the parameters are being used.
      Mostly fqdn - ip_address and port.

    """
    super().__init__( conf=conf, cs=None )
#    self.conf = conf
#    self.conf_type = 'stateless_tcp'
    self.server_address = self.get_server_address_from_conf( )

  def get_server_address_from_conf( self ):
    """ return host and port from the configuration file """
#    print( self.conf.keys() )
#    key_list = self.conf[ 'connectivity' ].keys()
#    if 'type' in key_list:
#      cs_type = self.conf[ 'connectivity' ][ 'type' ]
#      if cs_type != 'stateless_tcp':
#        raise ConfigurationError( f"unexpected type {cs_type} for "\
#          f"{self.__class__.__name__}. Expecting 'stateless_tcp'." )
#
#else:
#      raise ConfigurationError( f"Cannot find type in configuration "\
#        f"{self.__class__.__name__}. Expecting 'stateless_tcp'." )
    host = None
    con_conf = self.conf[ 'connectivity' ]
    if 'fqdn' in con_conf.keys():
      fqdn = con_conf[ 'fqdn' ]
      if fqdn not in [ None, '' ]:
        ## maybe we coudl perform a DNS lookup
        host = fqdn
    if host is None and 'ip' in con_conf.keys():
      host = con_conf[ 'ip' ]
    else:
      raise ConfigurationError( f"Cannot find 'ip' or 'fqdn' in "\
        f"configuration: {self.conf} for {self.__class__.__name__}." )
    if 'port' in con_conf.keys():
      port = con_conf[ 'port' ]
    else:
      raise ConfigurationError( f"Cannot find 'port' in "\
        "configuration: {self.conf} for {self.__class__.__name__}." )
    return ( host, port )

#  def resp( self, req_type, **kwargs ):
#
#    lurk_req = self.req( req_type, **kwargs )
#    print( f"--- E -> CS: Sending {req_type} Request:" )
#    lurk_req_bytes = LURKMessage.build( lurk_req )
#    lurk_resp = LURKMessage.parse( self.cs.serve( LURKMessage.build( lurk_req ) ) )
  def bytes_resp( self, bytes_req:bytes ):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
      # Connect to server and send data
      sock.connect( self.server_address )
      sock.sendall( bytes_req )
      return sock.recv(1024)


class PersistentTCPTls13LurkClient( TCPTls13LurkClient ) :

  def __init__( self, conf:dict ):
    """ configures the LURK client in a persitent TCP mode

    While the TCP session remains persistent and thus can
    be re-used for multiple exchanges, this TCP client
    does not implement ways to pipeline query and responses.
    To do so would require a sort of Lurk resolver / proxy
    that binds response received to queries.
    """
    super().__init__( conf=conf )
    self.sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
    self.sock.connect( self.server_address )
    self.selector = selectors.DefaultSelector()
    ## registering the "accept" socket
    self.selector.register(fileobj=self.sock, \
                           events=selectors.EVENT_READ )

#    self.serve_forever( )

  def bytes_resp( self, bytes_req:bytes ):
    ## this should work
    self.sock.sendall( bytes_req )
    return self.sock.recv(1024)


    ## alternatively we may parse the exact response.
    ## introducing some listening
    ## we need thus to define two threads: one listening
    ## to the cs the other to stub clients.
  def server_forever( self ):
    bytes_recv = b''
    while len(bytes_recv) < pylurk.cs.HEADER_SIZE + 4 :
      rlist, wlist, xlist = select.select([self.sock], [], [])
      if len(rlist) > 0:
        bytes_recv = self.sock.recv( pylurk.cs.HEADER_SIZE + 4 )
    header = LURKHeader.parse( bytes_recv )
    bytes_nbr = header['length']
    print( f"DEBUG: CS: bytes_nbr: {bytes_nbr}" )
    bytes_recv += self.sock.recv(min(bytes_nbr - len(bytes_recv), 4096))
    return bytes_recv


def get_lurk_client_instance( conf:dict=None, cs=None ):
  """ returns a LURK Client instance as defined by the configuration """

  if conf is None:
    conf = { 'connectivity' : { 'type' : 'lib_cs' } }
  con_type = conf[ 'connectivity' ] [ 'type' ]
  if con_type == 'lib_cs' :
    if cs is None:
      raise ValueError( "cs MUST be provided " )
    lurk_client =  BaseTls13LurkClient( conf, cs=cs )
  elif con_type == 'tcp':
    lurk_client = TCPTls13LurkClient( conf )
  elif con_type == 'persistent_tcp':
    lurk_client = PersistentTCPTls13LurkClient( conf )
  else:
    raise ConfigurationError( f"unknown connection_type {con_type}" )
  return lurk_client
