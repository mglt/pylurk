import logging
import socketserver
import selectors
import time
#import ssl
#import ssl.SSLError

from pylurk.struct_lurk import LURKMessage, LURKHeader
from pylurk.lurk.lurk_lurk   import LURKError, ImplementationError, ConfigurationError, LurkExt
####import sys
###sys.path.insert(0, '/home/emigdan/gitlab/pylurk.git/src/')
import pylurk.tls13.lurk_tls13
import pylurk.debug
#from pylurk.tls13.lurk_tls13  import Tls13Ext, TicketDB, SessionDB

MINIMUM_PACKET_SIZE = 16
HEADER_SIZE = 12

def logger( conf, __name__ ):
  """ returns a looger object """
  try:
    log_file = conf[ 'log' ]
  except KeyError :
    log_file = './crypto_service.log'
  logger = logging.getLogger( __name__ )
  FORMAT = "[%(asctime)s : %(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
  logger.setLevel( logging.DEBUG )
  logging.basicConfig( filename=log_file, format=FORMAT )
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

        self.tls13 = pylurk.tls13.lurk_tls13.Tls13Ext( self.conf[ ext ],\
                       ticket_db=self.ticket_db,\
                       session_db=self.session_db,\
                       debug=self.debug )

#        raise ValueError( )
    try:
      self.lurk_state = self.lurk.lurk_state
    except NameError:
      raise ConfigurationError( "( 'lurk', 'v1' ) MUST be enabled" )
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
      resp[ 'payload' ] = payload
      resp[ 'status' ] = 'success'
      if self.debug is not None:
        self.debug.handle_lurk_msg( resp)
      return LURKMessage.build( resp )
    except Exception as e :
      if isinstance( e, LURKError ):
        resp[ 'status' ] = e.status
        self.logger.info( f"{str( e )} - {e.message}" )
      else:
        if isinstance( e, ( ImplementationError, ConfigurationError ) ):
          self.logger.error( f"{e.status} : {e.message}" )
        else:
          self.logger.exception( str( e ) )
        resp[ 'status' ] = 'undefined_error'
      resp[ 'payload' ] = { 'lurk_state' : self.lurk_state }
      return LURKMessage.build( resp )


class NonPersistentTCPHandler( socketserver.BaseRequestHandler):
  """ the NonPersistentTCPHandler assumes that the packet it handles
      contains only one LURK request.
      TCP ensures all bytes are transported but a TCP session is
      established for every LURK request.
  """
  def handle( self ):
    req_bytes = self.request.recv(4096)
    resp = self.server.cs.serve( req_bytes )
    self.request.sendall( resp )

class NonPersistentTCPCryptoService( socketserver.TCPServer):

  def __init__( self, conf  ):
    """ Non Persistent TCP service

    The non persistent TCP Crypto Service handles one TCP session per
    packet.
    The NonPersistentTCP server extends the TCP calls to instantiate
    a crypto service as self.cs.
    """

    self.con_type = 'tcp'
    self.conf = conf
    self.cs = BaseCryptoService( self.conf )
    server_address = self.get_server_address_from_conf( )
    super().__init__( server_address, NonPersistentTCPHandler,\
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
        f"{self.__class__.__name__}. Expecting 'tcp'." )
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



#class BaseTCPServer(TCPServer):
class PersistentTCPServer( socketserver.TCPServer ):

  def __init__(self, server_address, RequestHandlerClass,\
             bind_and_activate=True):
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

    self.allow_reuse_address = True
    super().__init__( server_address, RequestHandlerClass,\
                      bind_and_activate )
#    if self.connection_type == 'tcp+tls':
#        context = self.conf.get_tls_context()
#        self.socket = context.wrap_socket(self.socket, server_side=True)
    ## selector listen to sockets available to the server.
    ## there are 2 kind of sockets.
    ## 1. The server socket ( self.socket ) that is contacted
    ##   by lurk client to establish a communication socket.
    ##   This socket is designated as "accept" (see data value).
    ## 2. sockets establsihed between each lurk client and the
    ##   server. These sockets are used to transmit the LURK
    ##   exchanges and are designated as "established".
    ##
    ## All these sockets are listen for the READ event.
    self.selector = selectors.DefaultSelector()
    ## registering the "accept" socket
    self.selector.register(fileobj=self.socket, \
                           events=selectors.EVENT_READ, \
                           data="accept")\
    ## the time after wich a socket is closed in case
    ## of non activity
    self.fd_timeout = 30
    ## inactivity time associated to each socket (file descriptor)
    ## socket are identied by their file descriptor number
    self.fd_time = {}
    ## list of fd (sockets) being treated
    self.fd_busy = {}

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

    Handles requests until shutdown

    The main difference with the original BaseServer function
    is that the BaseServer function is using non persitent TCP
    sessions which means that only the server socket is
    being monitored.
    In the Base server every incoming TCP session waits for:

    1. the creation of a new socket (sock = self.sock.accept()).
    2. the response to be sent on this newly established socket
    3. that newly established socket being closed.

    In our case we need to monitore all persistent session that
    is:

    1. TCP session that are in an establishment
    2. Established TCP sessions

    An incoming TCP session message take sthe following path:

    1. Identify which socket is associated to the message
    2. If a new socket needs to be created creates it and
      monitor further actions.
    3. For every socket on whic a message has been sent
      Treat that message.

    The main difference is that for any action, the socket
    needs to be specified.
    """

    print("staring serve_forever")
    self._BaseServer__is_shut_down.clear()
    previous_time = 0
    try:
      while not self._BaseServer__shutdown_request:
        ## listen to ready files and returns ( key, event )
        ## with poll_intervall it block until a file is ready.
        ## selector.select returns the following list:
        ## [(SelectorKey(fileobj=<socket.socket fd=3,
        ##   family=AddressFamily.AF_INET,
        ##   type=SocketKind.SOCK_STREAM, proto=0,
        ##   laddr=('127.0.0.1', 9402)>, fd=3, events=1,
        ##   data='accept'), 1)]
        events = self.selector.select( poll_interval )
        for selector_key, event in events:
          ## ensure the server can be shutdown
          if self._BaseServer__shutdown_request:
            break
          ## check fd (socket) is already being treated
          try:
            self.fd_busy[ selector_key.fileobj.fileno() ]
          except KeyError:
            self._handle_request_noblock(selector_key, event)
            self.service_actions() ## pass
        ## closing sockets that have been opened for
        ## more than timeout
        current_time = time.time()
        if current_time - previous_time > 1:
          previous_time = current_time
          ##
          for fd in self.selector.get_map():
            key = self.selector._fd_to_key[ fd ]
            try:
              delta_time = current_time - self.fd_time[ fd ]
              if delta_time > self.fd_timeout and\
                 key.data == 'establish':
                self.close_request( key.fileobj )
            except KeyError as e:
              ## time of self.socket is not monitored
              ## while it triggers events
              continue
    finally:
      self._BaseServer__shutdown_request = False
      self._BaseServer__is_shut_down.set()

  def _handle_request_noblock(self, selector_key, event):
    """ Handle one request

    The only change from the original TCP is that we indicate
    the ( socket, event ) to be passes to get_request.

    In the BaseServer, such information is inferred from the
    server_socket. In our case, server_socket is only one
    possibility and established socket MUST be considered.

    """
    try:
      request, client_address = self.get_request(selector_key, event)
#      print( f"DEBUG: request {request}" )
    except ( TypeError, OSError ):
      return
    else:
      if self.verify_request(request, client_address):
        try:
#          print( f"DEBUG: processing_request" )
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
      ## the establishement does not indicate there is some data
      ## to be received. As aresult, one needs to put the socket
      ## in a non blocking state to prevent the socket to block
      ## waiting to receive any data.
      request.setblocking(False)
#      if self.connection_type == 'tcp+tls':
#          context = self.conf.get_tls_context()
#          request = context.wrap_socket(request, server_side=True,\
#                                        do_handshake_on_connect=False)
      self.selector.register(fileobj=request, \
                             events=selectors.EVENT_READ,\
                             data="establish")
#      ## registering the last tim eactivity o fthe socket
#      self.fd_time[request.fileno] = time.time()
    elif selector_key.data == "establish":
      request = selector_key.fileobj
      client_address = request.getpeername()
    ## registering the last time activity o fthe socket
    self.fd_time[request.fileno] = time.time()
    return request, client_address

  def close_request(self, request):
    self.selector.unregister(request)
    request.close()

MAX_ATTEMPTS = 3
class PersistentTCPHandler( socketserver.BaseRequestHandler):
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
    ## check the sicket is not being treated
    fileno = self.request.fileno()
    if fileno in self.server.fd_busy.keys():
      return
    self.server.fd_busy[ fileno ] = time.time()

#    try:
#      self.server.fd_busy[ self.request.fileno() ]
##      return
#    except KeyError:
#
##      self.server.fd_busy[ self.request.fileno() ] = time.time()
    try:
#      print( f"DEBUG: receiving bytes" )
      ## we need to consider the additional len
      ## of the payload (4 bytes)
      req_bytes = self.request.recv( HEADER_SIZE + 4 )
#      print( f"DEBUG: handle : bytes_recv : {req_bytes}" )
    ## BlockingIOError error 11 happens when a socket
    ## in a non blocking mode does not have any data.
    ## The reason we considered non blocking mode is when
    ## a client just connect, without sending requests.
    ## We do not want the server be blocked until data
    ## is being sent.
    ## Maybe we could set a timer to recv.
    except BlockingIOError as e :
#      print( f"DEBUG: Excpetion {type(e)} {e}" )
      del self.server.fd_busy[ self.request.fileno() ]
      return
    else:
      if req_bytes == b'':
        return
      ## the payload len defines teh remaining bytes to be receievd.
      payload_len = int.from_bytes( req_bytes[ -4 : ], byteorder='big' )
#      header = LURKHeader.parse( req_bytes )
      #bytes_nbr = header[ 'length' ]
      attempt_nbr = 0
      while len( req_bytes ) < payload_len + HEADER_SIZE + 4:
        try:
          remaining_bytes = payload_len + HEADER_SIZE + 4 - len( req_bytes )
          req_bytes += self.request.recv( min( remaining_bytes, 4096) )
#        except ssl.SSLError as err:
#          if err.args[0] == ssl.SSL_ERROR_WANT_READ:
#            select([self.request], [], [])
#          elif err.args[0] == ssl.SSL_ERROR_WANT_WRITE:
#            select([self.request], [], [])
#          else:
#            raise
        except BlockingIOError:
          attempt_nbr += 1
          if attempt_nbr == MAX_ATTEMPTS:
            return
          ## currently we just sleep for 1 sec, but we may
          ## also wait for the socket to raise a read event.
          time.sleep( 1 )
         #   self.server.selector.select([ self.request ], [], [], 5)
      attempt_nbr = 0
#      print( f"DEBUG: CS: request bytes: {req_bytes}" )
      while attempt_nbr <= MAX_ATTEMPTS:
        try:
          resp = self.server.cs.serve( req_bytes )
##         self.request.sendall(self.server.byte_serve(bytes_recv))
          self.request.sendall( resp )
#          print( f"DEBUG: CS: resp: {resp}" )
          break
#        except ssl.SSLError as err:
#          if err.args[0] == ssl.SSL_ERROR_WANT_WRITE:
#            select([], [ self.request ], [])
#          else:
#            raise
        except BlockingIOError:
          select([], [ self.request ], [])
        if attempt_nbr == MAX_ATTEMPTS:
          return
          raise ImplementationError(attempt_nbr, "Reading Header" +\
                  "attempts exceeds MAX_ATTEMPTS " +\
                  "= %s"%MAX_ATTEMPTS +\
                  "Lurk Header not read")
      del self.server.fd_busy[self.request.fileno()]
      return

class PersistentTCPCryptoService( PersistentTCPServer ):

  def __init__( self, conf  ):
    """

    The Persitent TCP Crypto Service handles persistent TCP sessions
    The TCP server extends the TCP calls to instantiate
    a crypto service as self.cs.
    """

    self.con_type = 'persistent_tcp'
    self.conf = conf
    self.cs = BaseCryptoService( self.conf )
    server_address = NonPersistentTCPCryptoService.get_server_address_from_conf( self )
#    super().__init__( server_address, PersistentTCPHandler,\
#                       bind_and_activate=True )
    PersistentTCPServer.__init__( self, server_address, \
                                  PersistentTCPHandler, \
                                  bind_and_activate=True )


def get_cs_instance( conf ):
  """ returns appropriated Cryptographic Service instance from conf

  """
  con_type = conf[ 'connectivity' ][ 'type' ]
  if con_type == 'lib_cs':
    cs = BaseCryptoService( conf )
  elif con_type == 'tcp':
    cs = NonPersistentTCPCryptoService( conf )
  elif con_type == 'persistent_tcp':
    cs = PersistentTCPCryptoService( conf )
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
##    elif self.con_type == 'tcp':
##      self.cs = NonPersistentTCPCryptoService( self.conf )
###      NonPersistentTCPCryptoService.__init__( self, self.conf )
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
