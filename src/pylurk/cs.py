import logging
import socketserver
import selectors
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
      raise ConfigurationError( f"( 'lurk', 'v1' ) MUST be enabled" )
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
        if isinstance( e, ImplementationError ) or isinstance( e, ConfigurationError ):
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
    """ 
    
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
##        self.conf = LurkConf(deepcopy(lurk_conf))
##        self.lurk = LurkServer(self.conf.get_conf())
##        self.server_address = self.conf.get_server_address()
##        self.connection_type = self.conf.get_connection_type()
        self.allow_reuse_address = True
        super().__init__( server_address, RequestHandlerClass,\
                          bind_and_activate )
#        if self.connection_type == 'tcp+tls':
#            context = self.conf.get_tls_context()
#            self.socket = context.wrap_socket(self.socket, server_side=True)
        self.selector = selectors.DefaultSelector()
        self.selector.register(fileobj=self.socket, \
                               events=selectors.EVENT_READ, \
                               data="accept")
        self.fd_timeout = 3600
        self.fd_time = {}

        self.fd_busy = {}

#    def byte_serve(self, data):
#        return self.lurk.byte_serve(data)

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

        This function listen to events on the listening socket
        (self.socket) as well as other sockets associated to accepted
        communications (sock = self.sock.accept()).

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
        print("staring serve_forever")
        self._BaseServer__is_shut_down.clear()
        previous_time = 0
        try:
            while not self._BaseServer__shutdown_request:
                events = self.selector.select(poll_interval)
                for selector_key, event in events:
                    if self._BaseServer__shutdown_request:
                        break
                    try:
                        self.fd_busy[selector_key.fileobj.fileno()]
                    except KeyError:
                        self._handle_request_noblock(selector_key, event)
                        self.service_actions()
                current_time = time()
                if current_time - previous_time > 1:
                    previous_time = current_time
                    for fd in self.selector.get_map():
                        key = self.selector._fd_to_key[fd]
                        try:
                            delta_time = current_time - self.fd_time[fd]
                            if delta_time > self.fd_timeout and key.data == 'establish':
                                self.close_request(key.fileobj)
                        except KeyError as e:
                            ## time of self.socket is not monitored
                            ## while it triggers events
                            continue
        finally:
            self._BaseServer__shutdown_request = False
            self._BaseServer__is_shut_down.set()

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
        if selector_key.data == "accept":
            request, client_address = self.socket.accept()
            request.setblocking(False)
            if self.connection_type == 'tcp+tls':
                context = self.conf.get_tls_context()
                request = context.wrap_socket(request, server_side=True,\
                                              do_handshake_on_connect=False)
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
        try:
            self.server.fd_busy[self.request.fileno()]
            return
        except KeyError:
            self.server.fd_busy[self.request.fileno()] = time()

        try:
            bytes_recv = self.request.recv(HEADER_LEN)
        except:
            del self.server.fd_busy[self.request.fileno()]
            return
        if req_bytes == b'':
            return
        header = LURKHeader.parse( req_bytes )
        bytes_nbr = header[ 'length' ]

        while len( req_bytes ) < bytes_nbr:
            try:
                req_bytes += self.request.recv( min( bytes_nbr - len( req_bytes ), 4096) )
            except ssl.SSLError as err:
                if err.args[0] == ssl.SSL_ERROR_WANT_READ:
                    select([self.request], [], [])
                elif err.args[0] == ssl.SSL_ERROR_WANT_WRITE:
                    select([self.request], [], [])
                else:
                    raise
            except BlockingIOError:
                select([ self.request ], [], [], 5)
        attempt_nbr = 0
        while attempt_nbr <= MAX_ATTEMPTS:
            try:
                resp = self.server.cs.serve( req_bytes ) 
#                self.request.sendall(self.server.byte_serve(bytes_recv))
                self.request.sendall( resp )
                break
            except ssl.SSLError as err:
                if err.args[0] == ssl.SSL_ERROR_WANT_WRITE:
                    select([], [ self.request ], [])
                else:
                    raise
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
