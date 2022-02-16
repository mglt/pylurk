from  os.path import join
import pkg_resources
from copy import deepcopy
from construct.core import MappingError
import hashlib ## mostly for compatibility with key_schedule

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, SECP384R1, SECP521R1, ECDSA, EllipticCurvePublicNumbers, ECDH, EllipticCurvePrivateKey, EllipticCurvePublicKey

from cryptography.hazmat.primitives.hashes import Hash, SHA256, SHA384, SHA512
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_pem_private_key, NoEncryption, Encoding, PrivateFormat, PublicFormat
#from cryptography.hazmat.primitives.serialization.PrivateFormat import PKCS8, Raw
#from cryptography.hazmat.primitives.serialization.PublicFormat import PublicKeyInfo, Raw
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
import datetime

from lurk_lurk import LURKError, ImplementationError, ConfigurationError
from struct_tls13 import SignatureScheme, Handshake

data_dir = pkg_resources.resource_filename(__name__, '../data/')

web_profile = { 
    'tls13' : {
    'role' : [ 'client', 'server' ],
    'enable_session_resumption' : True, 
    'trusted_ecdhe' : True,
    'public_key' : [join(data_dir, 'cert-rsa-enc.der')], ## certificate chain
    'private_key' : join(data_dir, 'key-rsa-enc.pkcs8'), ## der, pkcs8
    }
}

conf_template = {
  'profile' : 'explicit configuration',
  'enabled_extensions' : [ ( 'lurk', 'v1' ) , ( 'tls13', 'v1' ) ],
  ( 'lurk', 'v1' ) : {
     'type_authorized' : [ 'ping',  'capabilities' ]
  },
  ( 'tls13', 'v1' ) : {
     'role' : [ 'client', 'server' ],
     'type_authorized' : [ 's_init_cert_verify',     ## server ECDHE
                           's_init_early_secret',    ## server PSK
                           's_hand_and_app_secret',  ## server PSK
                           's_new_ticket' ],           ## session resumption
     ## echde authentication parameter
       ## certificate chain, the public key of the TLS client or server
       ## is expected to be the last one
     'public_key' : [join( data_dir, 'cert-rsa-enc.der' )], 
     'private_key' : join( data_dir, 'key-rsa-enc.pkcs8' ), ## der, pkcs8
     'ephemeral_method_list' : ['no_secret', 'cs_generated', 'e_generated'],
     'authorized_ecdhe_group' : ['secp256r1', 'secp384r1', 
                                 'secp521r1', 'x25519', 'x448'], 
     ## only one signature scheme must be selected
     'sig_scheme' : ['rsa_pkcs1_sha256', \
                   'rsa_pkcs1_sha384', \
                   'rsa_pkcs1_sha512',\
                   'ecdsa_secp256r1_sha256', \
                   'ecdsa_secp384r1_sha384',\
                   'ecdsa_secp521r1_sha512', \
                   'rsa_pss_rsae_sha256', \
                   'rsa_pss_rsae_sha384', \
                   'rsa_pss_rsae_sha512', \
                   'ed25519', \
                   'ed448', \
                   'rsa_pss_pss_sha256', \
                   'rsa_pss_pss_sha384', \
                   'rsa_pss_pss_sha512' ], 
     ## secrets
     'client_early_secret_authorized' : True,    ## only for PSK
     'early_exporter_secret_authorized' : True,  
     'exporter_secret_authorized' : True,  
     'app_secret_authorized' : True,             ## anytime application is protected by TLS
     'resumption_secret_authorized' : True,     ## PSK / non protected ECDHE

     ## machinery logic
     's_init_early_secret_session_id' : True,
     'last_exchange' : { 's_init_cert_verify' : False, 
                         's_hand_and_app_secret' : False,
                         'c_init_client_finished' : False,
                         'c_init_post_auth' : False, 
                         'c_client_finished' : False}, 
     ## ticket related configuration
     'max_tickets' : 6, 
     'ticket_life_time' : 172800, # 2d = 2*24*3600 < 2**32-1
     'ticket_nonce_len' : 20,  ## bytes < 255
     'ticket_generation_method': 'ticket', ## versus index 
     'ticket_public_key': join(data_dir, 'ticket-cert-rsa-enc.der'), ## one key
     'ticket_private_key' : join(data_dir, 'key-rsa-enc.pkcs8'), ## der, pkcs8
     'ticket_len' : 4,  ## bytes < 255
     ## client parameters
     'post_handshake_authentication' : True,
     'max_post_handshake_authentication' : 1, ## 'c_post_hand_auth' ?
        },
}

### we may need to change this to SigScheme
# class SigAlgo
class SigScheme:
  def __init__( self, name:str) :
    """ used to pars ethe signature scheme

    The function also extract the hash for cipher suites
    """
    self.name = name
    self.algo = self.get_algo()
    self.hash = self.get_hash()
    self.pad = self.get_pad()
    self.curve = self.get_curve()


  def get_algo( self ):
    return self.name.split('_')[0]

  def get_hash( self ):
    ## returns None in case of ed25519 or ed448 sig scheme
    ## TLS cipher suite are expected to pass.
    ## we use hashlib to remain compatible with key_schedule
    if self.algo in [ 'ed25519', 'ed448' ]:
      return None
    hash_algo = self.name.split( '_' )[-1].lower()
    if hash_algo == 'sha256':
      h = SHA256()
#      h = hashlib.sha256
    elif hash_algo == 'sha384':
      h = SHA384()
#      h = hashlib.sha384
    elif hash_algo == 'sha512':
      h = SHA512()
#      h = hashlib.sha512
    else:
      raise LURKError( 'invalid_signature_scheme', f"{hash_algo} is not implemented" )
    return h

  def get_curve( self ): # -> Union[ SECP256R1, SECP384R1, SECP521R1 ] :
    if self.algo != 'ecdsa':
      return None
    curve_name = self.name.split( '_' )[1]
    if  curve_name == 'secp256r1':
      curve = SECP256R1()
    elif curve_name == 'secp384r1':
      curve = SECP384R1()
    elif curve_name == 'secp521r1':
      curve = SECP521R1()
    else:
      raise LURKError( 'invalid_signature_scheme', f"{curve_name} is not implemented" )
    return curve

  def get_pad( self ):
    if self.algo != 'rsa':
      return None
    pad_name = self.name.split( '_' )[1]
    if pad_name == 'pkcs1':
      pad = padding.PKCS1v15()
    elif pad_name == 'pss':
      pad = padding.PSS(
        mgf=padding.MGF1(self.hash),
       salt_length=padding.PSS.MAX_LENGTH)
    else:
      raise LURKError( 'invalid_signature_scheme', f"{pad_name} is not implemented" )
    return pad

  def matches( self, key):
    if ( self.algo == 'ed25519' and not \
         isinstance( key, Ed25519PrivateKey ) ) or\
       ( self.algo == 'ed448' and not \
         isinstance( key, Ed448PrivateKey ) ) or\
       ( self.algo == 'ecdsa' and not \
          isinstance( key, EllipticCurvePrivateKey ) ) or\
       ( self.algo == 'rsa' and not \
          isinstance( key, RSAPrivateKey ) ):
      raise LURKError( 'invalid_signature_scheme', \
              f"{self.name}, {type( private_key)} ,"\
              f"incompatible private key and signature algorithm" )
    if isinstance( key, EllipticCurvePrivateKey ):
      if isinstance( key.curve, type( self.curve ) ) == False:
        raise LURKError( 'invalid_signature_scheme', \
              f"{self.name}, {self.curve}, {key.curve} ,"\
              f"incompatible curve and signature algorithm" )

class CipherSuite:
  def __init__( self, name:str) :
    """ Handle the cipher suite string  
    """
    self.name = name
    self.hash = self.get_hash()

  def get_hash( self ):
    return SigScheme( self.name ).get_hash( )

class Configuration:

  def __init__( self, conf=deepcopy( conf_template ) ):
    """ manipuationof teh configuration file
    
    configuration class has two distinct goals:
      1 - eases the use interactions with the configuration dictionary ( fill, remove items ). As to avoid misconfiguration, the initial configuration file expect to carry the minimal amount of information. For example, public key information is filled at one place, and any arguments are them derived from it - even tough this might require extra processing.
      2 - generates informations that can be used by the software: This typically includes some information that can be derive. In this case, we would like to avoid information to be reprocessed muliutple times. For example, we do not want the certificate to read from the file each time a CERT message is sent. 
     We that purpose we are adding some extra variables that are noted _key to distinguish from those expected from the user. 
    """
    self.conf = conf 

  def set_role( self, role:str ):
    """ set the role """

    if isinstance( role, str ):
      if role not in [ 'client', 'server' ]:
        raise ConfigurationError( f"unknown role {role}." )
      role = [ role ]
    elif isinstance( role, list ):
      for r in role:
        if r not in [ 'client', 'server' ]:
          raise ConfigurationError( f"unknown role {role}." )
    else: 
      raise ConfigurationError( f"unknown role {role}. Must be string or list." )
    self.conf[ ( 'tls13', 'v1' ) ] [ 'role' ] = role

  def set_ecdhe_authentication( self, tls_sig_scheme:str, key_format='X509', conf_dir='./' ) :
    """generates, stores and configures self.conf

    Args:
      - sig_algo (str) : the Signature Scheme as defined fro TLS 1.3
    """
    private_key, public_key = self.generate_keys( tls_sig_scheme )
    private_file, public_file = self.store_keys( private_key, key_format, conf_dir )
    self.conf[ ( 'tls13', 'v1' ) ][ 'private_key' ] =  private_file
    self.conf[ ( 'tls13', 'v1' ) ][ 'public_key' ] = [ public_file ] 
    self.conf[ ( 'tls13', 'v1' ) ][ 'sig_scheme' ] = [ tls_sig_scheme ] 
    
  def generate_keys( self, tls_sig_scheme:str ):
    """ updates conf to serve the mentioned signature 

    according to the algorithm and format 
    """
    try:  
      SignatureScheme.build( tls_sig_scheme )
    except MappingError: 
      raise ConfigurationError( f"Invalid sig_scheme - only TLS1.3 sig_scheme" \
              "are expected: {conf[ ( 'tls13', 'v1' ) ][ 'sig_scheme' ]}." )

    sig_scheme = SigScheme( tls_sig_scheme )
    sig_algo = sig_scheme.algo
    if sig_algo == 'ed25519' :
      private_key = Ed25519PrivateKey.generate()
    elif sig_algo == 'ed448' :
      private_key = Ed448PrivateKey.generate()
    elif sig_algo == 'ecdsa' :
      private_key = ec.generate_private_key(
        sig_scheme.curve, default_backend())
    elif 'rsa' in sig_algo :
      private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048,
        backend=default_backend())
    else:
      raise ConfigurationError( f"unable to generate keys for {sig_algo.algo}" )
    public_key = private_key.public_key( )
    return private_key, public_key 

  def store_keys( self, key, key_format, conf_dir ) -> list: # type 'X509', 'Raw'
    """ store key(s) and return file names

    Args:
      - key the key object. When a private key is provided private and public keys are stored. ( RSAPrivateKey, RSAPublicKey, Ed25519PrivateKey, d25519PublicKey, Ed448PrivateKey, Ed448PublicKey, EllipticCurvePrivateKey, EllipticCurvePublicKey).  
      - key_format: the format of the storage ( Raw or 'X509' )

    Returns:
      - file_name list 
    """
    if isinstance( key, RSAPrivateKey ) or \
       isinstance( key, Ed25519PrivateKey ) or \
       isinstance( key, Ed448PrivateKey ) or \
       isinstance( key, EllipticCurvePrivateKey ) :
      private = True
    elif isinstance( key, RSAPublicKey ) or\
         isinstance( key, Ed25519PublicKey ) or \
         isinstance( key, Ed448PublicKey ) or \
         isinstance( key, EllipticCurvePublicKey ) :
      private = False
    else:
      raise ConfigurationError( f"unable to generate keys for {sig_algo.algo}" )
    algo = self.key_algo( key )

    private_file = None
    public_file = None
    if private is True:
      class_name = key.__class__.__name__
      private_file = join( conf_dir, f"{class_name}-{algo}-pkcs8.der" )
      ## storing private key
      with open( private_file, 'wb' ) as f:
        f.write( key.private_bytes( encoding=Encoding.DER, \
          format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption() ) )
      ## retrieving the public key
      private_key = key
      public_key = private_key.public_key( )
    
    ## storing public key
    class_name = public_key.__class__.__name__
    public_file = join( conf_dir, f"{class_name}-{algo}-{key_format}.der" )
    if key_format == 'Raw':
      with open( key, 'wb' ) as f:
        f.write( public_key.public_bytes( encoding=Encoding.DER,  \
                 format=PublicFormat.SubjectPublicKeyInfo))
    elif key_format == 'X509':
      one_day = datetime.timedelta(1, 0, 0)
      today = datetime.datetime.today()
      builder = x509.CertificateBuilder()
      builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),\
        ]))
      builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),\
        ]))
      builder = builder.not_valid_before( today - one_day )
      builder = builder.not_valid_after( today + ( one_day * 30 ) )
      builder = builder.serial_number(x509.random_serial_number())
      builder = builder.public_key( public_key )
      builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u'cryptography.io')] ),\
          critical=False )
      ### CA
      ## Currently set to self-signed
      if private is True:
        if isinstance( private_key, Ed25519PrivateKey ) or\
             isinstance( private_key, Ed448PrivateKey ):
          ca_algo = None
        else:
          ca_algo = SHA256()
        builder = builder.add_extension(
          x509.BasicConstraints(ca=False, path_length=None), critical=True, )
        certificate = builder.sign (private_key=private_key, algorithm=ca_algo,\
          backend=default_backend() )
        with open( public_file, 'wb' ) as f:
          f.write( certificate.public_bytes( Encoding.DER ) )
      else:
        raise ConfigurationError( f"Cannot store public key. self signed "\
                f"certificate requires the private key to be provided" )
    else:
      ConfigurationError( f"invalid key format {key_format}")
    return private_file, public_file
    
  def load_public_key( self, public_file) :
    """ load the public key and define the key format"""

    with open( public_file, 'rb' )  as f:
      public_bytes = f.read()
    ## trying to load the certificate
    try:
      cert = x509.load_der_x509_certificate( public_bytes, default_backend())
      public_key = cert.public_key()
      cert_type = 'X509'
    except:
      try:
        cert = x509.load_pem_x509_certificate( public_bytes, default_backend())
        public_key = cert.public_key()
        cert_type = 'X509'
      except:
        ## trying to load the raw public key
        try:
          public_key = Ed25519PublicKey.from_public_bytes( public_bytes )
          cert_type = 'Raw'
        except:
          try:
            public_key = Ed448PublicKey.from_public_bytes( public_bytes ) 
          except:
            ## RSAPublicKey, EllipticCurvePublicKey,
            try:
              public_key = load_pem_public_key( public_bytes, backend=default_backend() )
              cert_type = 'Raw'
            except:
              try:
                public_key = load_der_public_key( public_bytes, backend=default_backend() )
                cert_type = 'Raw'
              except:
                raise LURKImplementation( 'configuration_error', \
                  f"Unable to load public key public_file {public_file}" )
    return public_key, cert_type

  def load_private_key( self, private_file ):
    """ returns the private key """

    with open( private_file, 'rb' )  as f:
      private_bytes = f.read()
      ## ed25519
      try:
        private_key = Ed25519PrivateKey.from_private_bytes( private_bytes )
      except:
      ## ed448
        try:
          private_key  = Ed448PrivateKey.from_private_bytes( private_bytes )
        except:
        ## RSA / ECDSA
          try:
            private_key = load_der_private_key(private_bytes, password=None, backend=default_backend() )
          except:
            raise LURKImplementation( 'configuration_error', \
              f"Unable to load the private key from {private_file}" )
    return private_key

  def key_algo( self, key ) -> str :
    """ returns the key signature algorithm 
    """
    if isinstance( key, Ed25519PrivateKey ) or\
       isinstance( key, Ed25519PublicKey ) :  
      algo = 'ed25519'
    elif isinstance( key, Ed448PrivateKey ) or\
        isinstance( key, Ed448PublicKey ) :  
      algo  = 'ed448'
    elif isinstance( key, EllipticCurvePrivateKey) or\
        isinstance( key, EllipticCurvePublicKey ) :  
      algo = 'ecdsa_' + key.curve.name 
    elif isinstance( key, RSAPrivateKey ) or\
        isinstance( key, RSAPublicKey ) :  
      algo = 'rsa'
    else:
      raise ConfigurationError( f"unable to determine key algo." )
    return algo


  ### TLS or LURK engine related functions
  
  def load_cert_entry_list( self ):
    """ returns the certificate list """
    cert_file_list = self.conf[ ( 'tls13', 'v1' )  ] ['public_key']
    cert_entry_list = [] 
    for cert_file in cert_file_list:
      with open( cert_file, 'rb' ) as f:
        public_bytes = f.read() 
      cert_entry_list.append( { 'cert' : public_bytes, 'extensions': [] } ) ## certificateEntry
    return cert_entry_list 

  def set_extention( self, ext=None ) : 
#  def export_conf( self ):
    if ext == ( 'tls13', 'v1' ):
      ## taking the last file mentioned in the public_key list
      public_key_file = self.conf[ ( 'tls13', 'v1' )  ] ['public_key'][ -1 ]
      public_key, cert_type = self.load_public_key( public_key_file )
      private_file = self.conf[ ( 'tls13', 'v1' ) ][ 'private_key' ]
      private_key = self.load_private_key( private_file )
      if self.key_algo( public_key ) !=  self.key_algo( private_key ) :
        raise ConfigurationError( f"public ({self.key_algo( public_key )}) and "\
                f"private keys ({self.key_algo( private_key )}) do not match" )
      self.conf[ ( 'tls13', 'v1' ) ] [ '_private_key' ] = private_key 
      self.conf[ ( 'tls13', 'v1' ) ] [ '_public_key' ] = public_key 
      self.conf[ ( 'tls13', 'v1' ) ] [ '_cert_type' ] = cert_type
      cert_entry_list = self.load_cert_entry_list() 
      self.conf[ ( 'tls13', 'v1' ) ][ '_cert_entry_list' ] = cert_entry_list
#      hs_certificate =\
#        { 'msg_type' : 'certificate',
#          'data' :  { 'certificate_request_context': b'',
#                      'certificate_list' : cert_list } }
##     digest = Hash( SHA256(), backend=default_backend())
      finger_print_dict = {}
      finger_print_entry_list = []
      for cert_entry in cert_entry_list:
        public_bytes = cert_entry[ 'cert' ]
        digest = Hash( SHA256() )
        digest.update( public_bytes )
        finger_print = digest.finalize()[ :4 ]
        finger_print_dict[ finger_print ] = public_bytes
        finger_print_entry_list.append( { 'finger_print' : finger_print, 'extensions': [] } )
      self.conf[ ( 'tls13', 'v1' ) ] [ '_finger_print_entry_list' ] = finger_print_entry_list
      self.conf[ ( 'tls13', 'v1' ) ] [ '_finger_print_dict' ] = finger_print_dict
    else: 
      raise ConfigurationError( f"unknown extention {ext} " )
    return self.conf[ ext ]


   
     
#   def load_cert( self, cert_req_ctx=b'' ):
#    if self.hs_cert_msg == None:
#      cert_files = self.msg('keys')['public_key']
#      cert_list = [] 
#      for cert_file in cert_files:
#        with open( cert_file, 'rb' ) as f:
#          public_bytes = f.read() 
#        cert_list.append( { 'cert' : public_bytes, 'extensions': [] } ) ## certificateEntry
#        
#      self.hs_cert_msg = { 'msg_type' : 'certificate',
#                           'data' :  { 'certificate_request_context': cert_req_ctx,
#                                       'certificate_list' : cert_list } }
#    else:
#      self.hs_cert_msg[ 'data' ][ 'certificate_request_context' ] = cert_req_ctx
#
#    digest = Hash( SHA256(), backend=default_backend())
#    digest.update( Handshake.build( self.hs_cert_msg, \
#                                   _certificate_type=self.cert_type ))
#    self.cert_finger_print = digest.finalize()[:4]

  

"""
Structure that provides the various configuration parameters:

Args:
    cert (list): the list of certificates. The list contains a list of
        files name that contains the certificates or the raw keys. By
        convention, a file that contains the string "key" indicates
        that it contains a raw key. A file that contains the string
        "cert" indicates that it contains a x509 certificate. Unless
        one of these string is found in the file name, the file is
        assumed to contain a x509 certificate. Type of the certificate
        is required as the capability provides tehtype.


"""


default_conf = {
    'role' : 'server', # "client", "server"
    'connectivity' : {
        'type' : "udp",  # "local", "tcp", "tcp+tls", http, https
        'ip_address' : "127.0.0.1",
        'port' : 6789,
        'key' : join(data_dir, 'key_tls12_rsa_server.key'),
        'cert' : join(data_dir, 'cert_tls12_rsa_server.crt'),
        'key_peer' : join(data_dir, 'key_tls12_rsa_client.key'),
        'cert_peer' : join(data_dir, 'cert_tls12_rsa_client.crt')
#        'keys': {#TLS keys
#              'client': join(data_dir, 'key_tls12_rsa_client.key'),
#              'server': join(data_dir, 'key_tls12_rsa_server.key'),
#          },
#        'certs': {#TLS certifications
#              'client': join(data_dir, 'cert_tls12_rsa_client.crt'),
#              'server': join(data_dir, 'cert_tls12_rsa_server.crt'),
#        },
        },
    'extensions' : [
        {'designation' : "lurk",
         'version' : "v1",
         'type' : 'ping',
        },
        {'designation' : "lurk",
         'version' : "v1",
         'type' : 'capabilities',
        },
        {'designation' : "tls12",
         'version' : "v1",
         'type' : 'ping',
        },
        {'designation' : "tls12",
         'version' : "v1",
         'type' : 'capabilities',
        },

        {'designation' : "tls12",
         'version' : "v1",
         'type' : "rsa_master",
         'key_id_type' : ["sha256_32"],
         'freshness_funct' : ["null", "sha256"],
         'prf_hash' : ["sha256", "sha384", "sha512"],
         'random_time_window' : 5,
         'check_server_random' : True,
         'check_client_random' : False,
         'cert' : [join(data_dir, 'cert-rsa-enc.der')],
         'key' : [join(data_dir, 'key-rsa-enc-pkcs8.der')],
         'cipher_suites' : ["TLS_RSA_WITH_AES_128_GCM_SHA256", \
                            "TLS_RSA_WITH_AES_256_GCM_SHA384"]
        },
        {'designation' : "tls12",
         'version' : "v1",
         'type' : "rsa_master_with_poh",
         'key_id_type' : ["sha256_32"],
         'freshness_funct' : ["null", "sha256"],
         'prf_hash' : ["sha256", "sha384", "sha512"],
         'random_time_window' : 5,
         'check_server_random' : True,
         'check_client_random' : False,
         'cert' : [join(data_dir, 'cert-rsa-enc.der')],
         'key' : [join(data_dir, 'key-rsa-enc-pkcs8.der')],
         'cipher_suites' : ["TLS_RSA_WITH_AES_128_GCM_SHA256", \
                            "TLS_RSA_WITH_AES_256_GCM_SHA384"]
        },
        {'designation' : "tls12",
         'version' : "v1",
         'type' : "rsa_extended_master",
         'key_id_type' : ["sha256_32"],
         'freshness_funct' : ["null", "sha256"],
         'prf_hash' : ["sha256", "sha384", "sha512"],
         'random_time_window' : 5,
         'check_server_random' : True,
         'check_client_random' : False,
         'cert' : [join(data_dir, 'cert-rsa-enc.der')],
         'key' : [join(data_dir, 'key-rsa-enc-pkcs8.der')],
         'cipher_suites' : ["TLS_RSA_WITH_AES_128_GCM_SHA256", \
                            "TLS_RSA_WITH_AES_256_GCM_SHA384"]
        },
        {'designation' : "tls12",
         'version' : "v1",
         'type' : "rsa_extended_master_with_poh",
         'key_id_type' : ["sha256_32"],
         'freshness_funct' : ["null", "sha256"],
         'prf_hash' : ["sha256", "sha384", "sha512"],
         'random_time_window' : 5,
         'check_server_random' : True,
         'check_client_random' : False,
         'cert' : [join(data_dir, 'cert-rsa-enc.der')],
         'key' : [join(data_dir, 'key-rsa-enc-pkcs8.der')],
         'cipher_suites' : ["TLS_RSA_WITH_AES_128_GCM_SHA256", \
                            "TLS_RSA_WITH_AES_256_GCM_SHA384"]
        },
        {'designation' : "tls12",
         'version' : "v1",
         'type' : "ecdhe",
         'key_id_type' : ["sha256_32"],
         'freshness_funct' : ["null", "sha256"],
         'random_time_window' : 5,
         'check_server_random' : True,
         'check_client_random' : False,
         'cert' : [join(data_dir, "cert-ecc-sig.der")],
         'key' : [join(data_dir, "key-ecc-sig-pkcs8.der")],
         'sig_and_hash' : [('sha256', 'rsa'), ('sha512', 'rsa'),\
                            ('sha256', 'ecdsa'), ('sha512', 'ecdsa')],
         ## acceptable ecdsa curves when 'ecdsa' is chosen in
         ## 'sig_andhahs'. This parameter must not be specified
         ## when 'rsa' is the only acceptable signature.
         'ecdsa_curves' : ['secp256r1', 'secp384r1', 'secp521r1'],
         ## acceptable curves for ecdhe. This is used to check
         ## the provided ecdhe_params before signing those. It is
         ## only required for the server. Client only needs then
         ## when they generate the parameters and SHOULD be omitted
         ## in the configuration.
         'ecdhe_curves' : ['secp256r1', 'secp384r1', 'secp521r1'],
         ## defines how proo-of ownership is generated.
         'poo_prf' : ["null", "sha256_128", "sha256_256"],
         'cipher_suites' : ['TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', \
                             'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',\
                             'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', \
                             'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384']
        },
        {'designation' : 'tls13',
         'version' : 'v1',
         'type' : 'keys', 
         'public_key' : [join(data_dir, 'cert-rsa-enc.der')], ## certificate chain
         'private_key' : join(data_dir, 'key-rsa-enc.pkcs8'), ## der, pkcs8
         'sig_algo' : ['rsa_pkcs1_sha256', \
                       'rsa_pkcs1_sha384', \
                       'rsa_pkcs1_sha512',\
                       'ecdsa_secp256r1_sha256', \
                       'ecdsa_secp384r1_sha384',\
                       'ecdsa_secp521r1_sha512', \
                       'rsa_pss_rsae_sha256', \
                       'rsa_pss_rsae_sha384', \
                       'rsa_pss_rsae_sha512', \
                       'ed25519', \
                       'ed448', \
                       'rsa_pss_pss_sha256', \
                       'rsa_pss_pss_sha384', \
                       'rsa_pss_pss_sha512' ]
        },
        {'designation' : 'tls13',
         'version' : 'v1',
         'type' : 's_init_early_secret',
         'session_id' : True, ## session_is are not expected. 
         'client_early_secret_authorized' : True,
         'early_exporter_secret_authorized' : True,
        }, 
        {'designation' : 'tls13',
         'version' : 'v1',
         'type' : 's_init_cert_verify',
         'last_exchange' : False,  
         'app_secret_authorized' : True, 
         'exporter_secret_authorized' : True, 
         'ephemeral_methods' : ['no_secret', 'cs_generated', 'e_generated'],
         'authorized_ecdhe_group' : ['secp256r1', 'secp384r1', 
                                     'secp521r1', 'x25519', 'x448'], 
##         'public_key' : [join(data_dir, 'cert-rsa-enc.der')], ## certificate chain
##         'private_key' : join(data_dir, 'key-rsa-enc.pkcs8'), ## der, pkcs8
##         'sig_algo' : ['rsa_pkcs1_sha256', \
##                       'rsa_pkcs1_sha384', \
##                       'rsa_pkcs1_sha512',\
##                      'ecdsa_secp256r1_sha256', \
##                       'ecdsa_secp384r1_sha384',\
##                       'ecdsa_secp521r1_sha512', \
##                       'rsa_pss_rsae_sha256', \
##                       'rsa_pss_rsae_sha384', \
##                       'rsa_pss_rsae_sha512', \
##                       'ed25519', \
##                       'ed448', \
##                       'rsa_pss_pss_sha256', \
##                       'rsa_pss_pss_sha384', \
##                       'rsa_pss_pss_sha512' ]
        }, 
        {'designation' : 'tls13',
         'version' : 'v1',
         'type' : 's_hand_and_app_secret',
         'last_exchange' : False,  
         'app_secret_authorized' : True, 
         'exporter_secret_authorized' : True, 
         'ephemeral_methods' : ['no_secret', 'cs_generated', 'e_generated'],
         'authorized_ecdhe_group' : ['secp256r1', 'secp384r1', 
                                     'secp521r1', 'x25519', 'x448'], 
        }, 
        {'designation' : 'tls13',
         'version' : 'v1',
         'type' : 's_new_ticket',
         'resumption_secret_authorized' : True,
         'max_tickets' : 6, 
##         'max_new_ticket_exchange' : 1, 
         'ticket_life_time' : 172800, # 2d = 2*24*3600 < 2**32-1
         'ticket_nonce_len' : 20,  ## bytes < 255
         'ticket_generation_method': 'ticket', ## versus index 
         'public_key': join(data_dir, 'ticket-cert-rsa-enc.der'), ## one key
         'private_key' : join(data_dir, 'key-rsa-enc.pkcs8'), ## der, pkcs8
         'ticket_len' : 4,  ## bytes < 255
        },
        
        {'designation' : 'tls13',
         'version' : 'v1',
         'type' : 'c_init_cert_verify',
         'ephemeral_methods' : ['e_generated'],
         'authorized_ecdhe_group' : ['secp256r1', 'secp384r1', 
                                     'secp521r1', 'x25519', 'x448'],
         'last_exchange' : False,  
##         'public_key' : [join(data_dir, 'cert-rsa-enc.der')], ## certificate chain
##         'private_key' : join(data_dir, 'key-rsa-enc.pkcs8'), ## der, pkcs8
##         'sig_algo' : ['rsa_pkcs1_sha256', \
##                       'rsa_pkcs1_sha384', \
##                       'rsa_pkcs1_sha512',\
##                       'ecdsa_secp256r1_sha256', \
##                       'ecdsa_secp384r1_sha384',\
##                       'ecdsa_secp521r1_sha512', \
##                       'rsa_pss_rsae_sha256', \
##                       'rsa_pss_rsae_sha384', \
##                       'rsa_pss_rsae_sha512', \
##                       'ed25519', \
##                       'ed448', \
##                       'rsa_pss_pss_sha256', \
##                       'rsa_pss_pss_sha384', \
##                       'rsa_pss_pss_sha512' ]
        }, 
        {'designation' : 'tls13',
         'version' : 'v1',
         'type' : 'c_init_post_auth',
         'last_exchange' : False,  
         'ephemeral_methods' : ['e_generated'], ## MANDATORY
         'authorized_ecdhe_group' : ['secp256r1', 'secp384r1', 
                                     'secp521r1', 'x25519', 'x448'], 
         'last_exchange' : False
##         'public_key' : [join(data_dir, 'cert-rsa-enc.der')], ## certificate chain
##         'private_key' : join(data_dir, 'key-rsa-enc.pkcs8'), ## der, pkcs8
##         'sig_algo' : ['rsa_pkcs1_sha256', \
##                       'rsa_pkcs1_sha384', \
##                       'rsa_pkcs1_sha512',\
##                       'ecdsa_secp256r1_sha256', \
##                       'ecdsa_secp384r1_sha384',\
##                       'ecdsa_secp521r1_sha512', \
##                       'rsa_pss_rsae_sha256', \
##                       'rsa_pss_rsae_sha384', \
##                       'rsa_pss_rsae_sha512', \
##                       'ed25519', \
##                       'ed448', \
##                       'rsa_pss_pss_sha256', \
##                       'rsa_pss_pss_sha384', \
##                       'rsa_pss_pss_sha512' ]
        }, 
        {'designation' : 'tls13',
         'version' : 'v1',
         'type' : 'c_post_auth',
         'max_post_handshake_authentication' : True
        }, 
        {'designation' : 'tls13',
         'version' : 'v1',
         'type' : 'c_init_ephemeral',
         'ephemeral_methods' : [ 'cs_generated' ], ## MANDATORY
         'authorized_ecdhe_group' : ['secp256r1', 'secp384r1', 
                                     'secp521r1', 'x25519', 'x448'], 
        }, 
        {'designation' : 'tls13',
         'version' : 'v1',
         'type' : 'c_init_early_secret',
         'client_early_secret_authorized' : True,
         'early_exporter_secret_authorized' : True,
         'ephemeral_methods' : [ 'no_secret', 'cs_generated' ], ## MANDATORY
         'authorized_ecdhe_group' : ['secp256r1', 'secp384r1', 
                                     'secp521r1', 'x25519', 'x448'], 
        }, 
        {'designation' : 'tls13',
         'version' : 'v1',
         'type' : 'c_hand_and_app_secret',
         'last_exchange' : False,
         'app_secret_authorized' : True, 
         'exporter_secret_authorized' : True, 
         'resumption_secret_authorized' : True,
        }, 
        {'designation' : 'tls13',
         'version' : 'v1',
         'type' : 'c_register_ticket',
        }, 
        {'designation' : 'tls13',
         'version' : 'v1',
         'type' : 'c_post_hand',
        }, 

        ]
}
