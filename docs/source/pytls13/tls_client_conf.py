import copy
import dns.resolver 
import argparse
import ipaddress
#import sys 
#sys.path.insert(0, '/home/emigdan/gitlab/pylurk.git/src')
import pylurk.conf 



class Configuration( pylurk.conf.Configuration ) :
  
  def __init__( self ):
    """ generates the client configuration 
 
    Note that we define the configuration inside the calls to 
    ensure the scope of the tempate only remains within the class.
    As python does not enable to protect the variable, it was very 
    difficult to make sure the template was not modified externally.
    """
     
    self.conf = {
      'role' : 'client',
      'description' : "TLS 1.3 Client configuration template",
      # destination can be added bu is not part of the default template
      # as it is expected to vary for every tls session. 
      #  'destination' : {
      #    'ip' : '127.0.0.1',
      #    'port' : 12000
      #  },
      'debug' : {
        'trace' : True, 
        # test_vectors are used to establish a very specific session 
        # that has been previously recorded. 
        # It is mostly intended to be used for testing purposes, 
        # where a specific session can be replayed. 
        # 
        #   file : defines where information can be read / recorded
        #   mode : defines if the session is being recorded or checked. 
        #     possible values for mode are 'check', 'record' or None
        # 
        # Both file and mode MUST be specified, when test_vector is used.
        # 'test_vector' : {
        #   'file' : '/home/emigdan/gitlab/pytls13/src/pytls13/illustrated_tls13.json',
        #   'mode' : 'check' # check / record / None
        # },
      },
      'lurk_client' : {
        'freshness' : 'sha256',
        'connectivity' : {
          'type' : 'lib_cs', #'stateless_tcp', # 'lib_cs', # 'stateless_tcp'
          # These connectivity paremeters are specific to a session 
          # between a lurk_client and a cs.
          # They do not apply to the type 'lib_cs' 
          # 'fqdn' : None,
          # 'ip' : "127.0.0.1",
          # 'port' : 9999,
        }
      },
      'tls13' : { ## maybe that shoudl be called the engine
    #    'ecdhe_authentication' : True, ## ecdhe indicates certificate based authentication
        'ke_modes' : [ 'psk_dhe_ke'], ## psk_ke
        'session_resumption' : True,
        'post_handshake_authentication' : False,  ## True/False
        ## sig scheme understood by the TLS Engine to authenticate the Server
        ## These values are considered by the TLS server to ensure the TLS
        ## client will be able to validate the server certificate
        ## these are NOT reflecting the sig_scheme supported by the CS,
        ## which indicates the signature scheme used by the CS.
        'signature_algorithms' : [ 'rsa_pkcs1_sha256', 'rsa_pkcs1_sha384', 'rsa_pkcs1_sha512', 'ecdsa_secp256r1_sha256', 'ecdsa_secp384r1_sha384', 'ecdsa_secp521r1_sha512', 'rsa_pss_rsae_sha256', 'rsa_pss_rsae_sha384', 'rsa_pss_pss_sha256', 'rsa_pss_pss_sha384', 'rsa_pss_pss_sha256', 'ed25519', 'ed448', 'rsa_pkcs1_sha1' ],
        ## configuration of ecdhe requires some synchronization with the cs
        ## configuration.
        ## maybe this may be generated from the CS configuration (or the reverse)
        'ephemeral_method' : 'cs_generated', ## cs_generated / e_generated when ECDHE is needed. otherwise can be set to 'no_secret'
        ## these values are used for the supported_group (non mandatory) and key_share extension
        'supported_ecdhe_groups' : [ 'x25519' ], #[ 'secp256r1', 'x25519', 'x448' ],
        ### These MUST be provided in the cs configuration part
      },
      ## parameters associated to the cryptographic material being used by
      ## the TLS client.
      ## When the CS is external, only the certificat enetry list is needed.
      ## When the CS is instantiated by the TLS client, it is likely that
      'cs' :{
        ( 'tls13', 'v1' ) : {
#          'public_key': ['/home/emigdan/gitlab/pytls13/src/pytls13/clt_cs/_Ed25519PublicKey-ed25519-X509.der'],
#          'private_key': '/home/emigdan/gitlab/pytls13/src/pytls13/clt_cs/_Ed25519PrivateKey-ed25519-pkcs8.der',
          'sig_scheme': ['ed25519'],
        }
      }
    }
    self.cs_conf = pylurk.conf.Configuration( )
    
  def update_cs_conf( self ):
    """ derives the cs configuration from the tls client's configuration

    Note that the tls client configuration is taken as the base to 
    configure the CS. 
    This means that necessary parameters MUST be defined in the tls 
    client configuration.
    The connectivity parameters MUST be defined for the lurk_client 
    (as part of the tls client configuration). 
    This connectivity parameter is used to determine if a complete CS 
    needs to be instantiated by the TLS client (with a connectivity 
    type set to 'lib_cs') or if the CS is instead configured as a 
    separated entity (with a connectivity type set to any other value).
    When connectivity type is set to 'lib_cs', connectivity and debug 
    parameters of the CS are aligned to those defined for the tls client. 
    For cryptographic parameters, the CS MUST be configured with a 
    private key and a public key.  
    When connectivity type is set to another value, such configuration 
    parameters are left out of scope of the TLS client.
    For cryptographic parameters, the CS MUST be configured only with a 
    public key. 
    These are the only parameters that is needed and it will be used to
    generate some internal values necessry to build the Certificate 
    message as well as optimize the communication between the lurk_client 
    and the CS. 
    """
    init_cs_conf = {}
    if 'cs' in self.conf.keys():
      init_cs_conf = self.conf[ 'cs' ]
##    print( f" --- init_cs_conf: {init_cs_conf}" )
    ## merging init_cs 
    self.cs_conf.merge( init_cs_conf )
    lurk_client_connectivity = self.conf[ 'lurk_client' ][ 'connectivity' ]
##    print( f" --- lurk_client_connectivity: {lurk_client_connectivity}" )
    if lurk_client_connectivity[ 'type' ] == 'lib_cs' :
      ## in that modul this is the only possibility
      self.cs_conf.set_role( 'client' )
      ## setting / cleaning  connectivity configuration
##      self.cs_conf.set_connectivity( **self.conf[ 'lurk_client' ][ 'connectivity' ] ) 
      self.cs_conf.conf[ 'connectivity' ] = lurk_client_connectivity
      self.cs_conf.conf[ ( 'tls13', 'v1' )  ][ 'debug' ] = self.conf[ 'debug' ]
#      self.cs_conf.set_tls13_debug( **self.conf[ 'debug' ] ) 
      self.cs_conf.set_tls13_authorization_type( )
      self.cs_conf.set_tls13_cs_signing_key( )
      self.conf[ 'cs' ] = self.cs_conf.conf
    else:
      ## cleaning unnecessary parameters
      self.cs_conf.set_tls13_cs_public_signing_key( )
      tmp_cs_conf = { ( 'tls13', 'v1' )  : { } }
      for k in [ 'public_key', 'sig_scheme', '_public_key',  '_cert_type', \
                 '_cert_entry_list', '_finger_print_entry_list', \
                 '_finger_print_dict' ] :
        tmp_cs_conf[ ( 'tls13', 'v1' ) ][ k ] = self.cs_conf.conf[ ( 'tls13', 'v1' ) ][ k ]
      self.conf[ 'cs' ] = tmp_cs_conf



class CLI( pylurk.conf.CLI ):
  def __init__( self, url:str="https://127.0.0.1:443", 
                      session_resumption:bool=False,
                      reconnect:bool=True,
                      auto_start_cs:bool=False,
                      freshness:str='sha256',
                      ephemeral_method='cs_generated', 
                      ### argument provided / shared with the cs
                      ### shared means Engine reuse them from the CS
                      debug:bool=False,        # shared
                      test_vector_mode=None,   # shared
                      test_vector_file=None,   # shared 
                      connectivity:str='lib_cs', # shared (lurk_client)
                      host:str='127.0.0.1',       # shared (lurk_client)
                      port:int=9400,             # shared (lurk_client)
##                      ## gramine* parameters are only needed if 
##                      ## one has the ability to start the cs, 
##                      ## that is if auto_start_cs is set.
##                      ## when connectivity is set to 'lib_cs'
##                      ## these parameters are ignored.
##                      ## gramine could be used for the TLS client.
##                      ## If so, these parameters would be provided to 
##                      ## the script setting the environment 
##                      ## and instantiating this object.
##                      ## As a result these parameters only apply 
##                      ## to the cs.
##                      gramine_sgx:bool=False,    ## not needed here 
##                      gramine_direct:bool=False  ## as not in template 
##                      gramine_build:bool=False 
                      ## sig_scheme is not used by the Engine 
                      ## as [to check].
                      ## It is used by the CS to eventually 
                      ## generate the keys. However, this argument
                      ## could be optional and only being specified 
                      ## for the generation of the keys
                      sig_scheme:str='ed25519', 
                      supported_ecdhe_groups:str=['x25519'],
                      ## key is only known to the CS 
                      key:str=None, # shared (sometimes)
                      ## cert is both used by the CS and the Engine.
                      cert:str=None, # shared
          ):
    """ generates a conf file from argument provided by en user

    This is an alternative to provide a configuration file.
    The intent is to make a TLS client accessible using command 
    line aand to remain compatible with what openssl is providing.

    Compatibility with the s_client command line is not a goal, 
    but when we can we try to reuse it. 

    Note that the configuration template DOES NOT consider
    variables that are related to the environement or the 
    behavior of the tls client. 
    Such parameters ARE NOT part of the configuration parameters 
    necessary to instantiate the tls client. 

    This Class however, defines a parser that takes such behavioral
    and behavioral parameter. 
    This is a convenience to more generic cli that will implement 
    the behavior and the environement parameter provided by the 
    end user.  
    """
    self.url = url
    self.session_resumption = session_resumption
#    self.reconnect = reconnect 
#    self.cs_auto_start = cs_auto_start,
    self.freshness = freshness,
    self.ephemeral_method = ephemeral_method
    self.supported_ecdhe_groups = supported_ecdhe_groups
    if cert == './_Ed25519PublicKey-ed25519-X509.der' :
    ### argument provided / shared with the cs
      super().__init__( connectivity, debug, test_vector_mode,\
                      test_vector_file, host, port, sig_scheme,\
                      key, cert )
#    self.gramine_sgx = gramine_direct
#    self.gramine_direct = gramine_direct
#    self.gramine_build = gramine_build


  def get_template( self ):
    destination, sent_data = self.get_destination_and_sent_data( )
    return { 
      'destination' : destination,
      'sent_data' : sent_data,
      'debug' : self.get_debug( ),
      'lurk_client' : self.get_lurk_client( ),
      'tls13' : self.get_tls13_client( ), 
      'cs' : self.get_cs( ),
            }
#    self.init_connect( self.connect )
#    self.init_debug( debug, test_vector_mode, test_vector_file )
#    self.template[ 'tls13' ][ 'session_resumption' ] = session_resumption

  def parse_url( self, url ):
    """ initializes various parameters provided in url

    url can take the various forms:
      * host:port
      * https://host:port

    with host being an ip address or a hostname.

    We manually parse this as urlparse does not parse properly 
    in th eabscence of a scheme.
    """

    if '://' in url:
      if 'https://' in url:
        scheme = 'https'
        netloc_path = url[ 8 : ].split( '/' ) 
      else:
        raise ValueError( f"Unknown scheme in {url}" )  
    else:
      scheme = ''
      netloc_path = url.split( '/' ) 

    ## only net_loc 
    if len( netloc_path ) == 1:
      netloc = netloc_path[ 0 ]
#      path = '/index.html'
      path = '/'
    else:
      netloc = netloc_path[ 0 ]
      path = netloc_path[ len( netloc ) - 1 : ]

    if ':' in netloc:
      host, port = netloc.split( ':' )
    else:
      host = netloc
      port = 443

    try:
      if isinstance( ipaddress.ip_address( host ),  ( ipaddress.IPv4Address, ipaddress.IPv6Address ) ) :
        ip = host
    except ValueError:
      answers = dns.resolver.resolve( host, 'A')
      if len( answers ) == 0:
        result = dns.resolver.resolve( host, 'AAAA')
        if len( answers ) == 0:
          raise ValueError( f"Unable to resolve {host}" )
      ip = answers[ 0 ].to_text()
    ## validating format of port and IP address  
    if isinstance( ipaddress.ip_address( ip ),  ( ipaddress.IPv4Address, ipaddress.IPv6Address ) ) is False :
      raise ValueError( f"{ip} Unable to find corresponding IP "\
                        f"address in {url}" )
    port = int( port )
    return ( scheme, host, ip, port, path )

  def get_destination_and_sent_data( self ):
    scheme, host, ip, port, path = self.parse_url( self.url )  
    destination_template = {}
    destination_template[ 'ip' ] = ip
    destination_template[ 'port' ] = port
    if scheme == 'https' :
      sent_data = f"GET {path} HTTP/1.1\r\n" +\
                  f"Host: {host}\r\n" +\
                  f"user-agent: pytls13/0.1\r\n" +\
                  f"accept: */*\r\n\r\n"
      sent_data = sent_data.encode( encoding = 'utf-8' )            
    else: 
      sent_data = b''
    return destination_template, sent_data
 
  def get_lurk_client( self ): 
    lurk_client_template = { 'connectivity' : self.get_connectivity( ) }
    lurk_client_template[ 'freshness' ] = self.freshness 
    return lurk_client_template

  def get_tls13_client( self ):
    tls13_template = {}
    tls13_template[ 'ephemeral_method' ] = self.ephemeral_method
    tls13_template[ 'supported_ecdhe_groups' ] = self.supported_ecdhe_groups
    tls13_template[ 'session_resumption' ] = self.session_resumption
    return tls13_template 

  def get_cs( self ):
    ## self.key is known to the Engine when 
    ## the cs is embeded in the engine mode 'lib_cs'
    cs_template = super().get_template( ) 
    if self.connectivity != 'lib_cs' :
      del cs_template[ ( 'tls13', 'v1' ) ][ 'private_key' ] 
    return cs_template
 
  def get_parser( self, env:bool=False, conf_dir:str='./', 
                parser=None ):
    description = \
    """
    Implements a TLS 1.3 Client. 
    """
    parser = argparse.ArgumentParser( description=description )
    parser = super().get_parser( env, conf_dir, parser )
    parser.add_argument( 'url',  type=ascii, nargs='?', \
      default='127.0.0.1:443', \
      help="The URL a TCP/TLS handlshake is performed" )
    parser.add_argument( '-no_resump', '--no_session_resumption', \
      default=False, action='store_const', const=True, \
      help='Indicates session resumption is disables')
    parser.add_argument( '-fresh', '--freshness', type=ascii, \
      nargs='?', default='sha256', help='Freshness')
    parser.add_argument( '-eph_method', '--ephemeral_method', \
      type=ascii, nargs='?', default='cs_generated', \
      help='Ephemeral Method')
    parser.add_argument( '-ecdhe', '--supported_ecdhe_groups', \
      type=ascii, nargs='?', default='x25519', \
      help='Ephemeral Method')
#    self.session_resumption = session_resumption
#    self.freshness = freshness,
#    self.ephemeral_method = ephemeral_method
# supported_ecdhe_groups
    ## behavioral parameters are not part of the configuration 
    ## but can influence the bahvior of the tls client.
    parser.add_argument( '-recon', '--reconnect', default=False,  \
      action='store_const', const=True, \
      help='Reconnect with Session Resumption')

##    ## env parameters
##    ## gramine for e
##    parser.add_argument( '-sgx', '--gramine_sgx', default=False,  \
##      action='store_const', const=True, \
##      help='Crypto Service is run into SGX (gramine)')
##    parser.add_argument( '-g', '--gramine_direct', default=False,  \
##      action='store_const', const=True, \
##      help='Crypto Service is run into SGX (gramine)')
##    parser.add_argument( '-b', '--gramine_build', default=False,  \
##      action='store_const', const=True, \
##      help='Build the Crypto Service into the enclave')
    parser.add_argument( '-cs', '--cs_auto_start', default=False,  \
      action='store_const', const=True, \
      help='Auto start the CS')

    ## gramine for cs
    ## Note that env=setto True defines --gramine* parameters.
    ## these parameters are considered to be for the Engine (e).
    ## This remains consistent with how we defined the parameters 
    ## for CS. 
    ## There is a remaining question whether we have use cases for 
    ## the engine to be protected by SGX as the purpose of the CS is
    ## to have the CS protected while the Engine remains unprotected.
    ##   * One possible scenario consists in having the  the full 
    ##   TLS client run into the SGX enclave in which case 
    ##   --gramine_sgx is combined with --connectivity lib_cs.
    ##  * One possible scenario consists in spliting in splitting 
    ##  the TLS client while benefiting from teh SGX protection. 
    ##  This combines --gramin_sgc and --connectivity tcp for example.
    parser.add_argument( '-cs_sgx', '--cs_gramine_sgx', default=False,  \
      action='store_const', const=True, \
      help='Crypto Service is run into SGX (gramine)')
    parser.add_argument( '-cs_g', '--cs_gramine_direct', default=False,  \
      action='store_const', const=True, \
      help='Crypto Service is run into SGX (gramine)')
    parser.add_argument( '-cs_b', '--cs_gramine_build', default=False,  \
      action='store_const', const=True, \
      help='Build the Crypto Service into the enclave')
    return parser

  def init_from_args( self, args ):
    """ takes from arguments the non env and non behavioral param 
    """
    super().init_from_args( args )  
    self.session_resumption = not args.no_session_resumption
    self.freshness = args.freshness[1:-1]
    self.ephemeral_method = args.ephemeral_method[1:-1]
    self.supported_ecdhe_groups = [ args.supported_ecdhe_groups[1:-1] ]
    self.url = args.url[1:-1]
