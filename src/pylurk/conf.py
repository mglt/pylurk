
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
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM, AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
import datetime

import sys
sys.path.insert(0, '/home/emigdan/gitlab/pytls13/src/')
import pytls13.struct_tls13 as tls
#import pytls13.test_vector

sys.path.insert(0, '/home/emigdan/gitlab/pylurk.git/src')
#import pylurk.tls13.struct_tls13 as lurk
from pylurk.lurk.lurk_lurk import LURKError, ImplementationError, ConfigurationError
#import pylurk.tls13.lurk_tls13


import pylurk.tls13.struct_tls13 as lurk
import pylurk.utils
import pylurk.tls13.crypto_suites
import binascii

data_dir = pkg_resources.resource_filename(__name__, '../data/')


conf_template = {
  'profile' : 'explicit configuration',
  'description' : "LURK Cryptographic Service configuration template",
#  'mode' : 'debug',
  'connectivity' : {
      'type' : "udp",  # "local", "stateless_tcp", "tcp", "tcp+tls", http, https
      'fqdn' : None,
      'ip_address' : "127.0.0.1",
      'port' : 9999,
      'key' : join(data_dir, 'key_tls12_rsa_server.key'),
      'cert' : join(data_dir, 'cert_tls12_rsa_server.crt'),
      'key_peer' : join(data_dir, 'key_tls12_rsa_client.key'),
      'cert_peer' : join(data_dir, 'cert_tls12_rsa_client.crt')
      },
  'enabled_extensions' : [ ( 'lurk', 'v1' ) , ( 'tls13', 'v1' ) ],
  ( 'lurk', 'v1' ) : {
     'type_authorized' : [ 'ping',  'capabilities' ]
  },
  ( 'tls13', 'v1' ) : {
    'debug' : {
      'test_vector' : True,
      'trace' : True,  # prints multiple useful information
      'test_vector_file' : './illustrated_tls13.json',
      'test_vector_mode' : 'check', # check / record
      'test_vector_tls_traffic' : True, #'local' # / remote 
      },
     'role' : 'server', #[ 'client', 'server' ],
     'type_authorized' : [ 's_init_cert_verify',     ## server ECDHE
                           's_init_early_secret',    ## server PSK
                           's_hand_and_app_secret',  ## server PSK
                           's_new_ticket',           ## session resumption
                           'c_init_client_finished', ## only signature 
                           'c_post_hand_auth',       ## post hand
                           'c_init_client_hello',    ## client hello
                           'c_server_hello',
                           'c_client_finished',
                           'c_register_tickets' ],
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
      role = role
    elif isinstance( role, list ):
      for r in role:
        if r not in [ 'client', 'server' ]:
          raise ConfigurationError( f"unknown role {role}." )
    else: 
      raise ConfigurationError( f"unknown role {role}. Must be string or list." )
    self.conf[ ( 'tls13', 'v1' ) ] [ 'role' ] = role

  def merge( self, branch:dict, master:dict=None ):
    """ merge th ebranch conf to the master conf

    The branch configuration is expected to provide a subset of the parameters
    Those not provided are taken from the template.
    """
    if master is None :
      master = self.conf
    for key in branch.keys():
      if isinstance( branch[ key ], dict ) is False :
        master[ key ] = branch[ key ]
      else:
        master[ key ] = self.merge( branch[ key ], master[ key] )
    return master

  def generate_keys( self, tls_sig_scheme:str ):
    """ updates conf to serve the mentioned signature 

    according to the algorithm and format 
    """
    try:  
      tls.SignatureScheme.build( tls_sig_scheme )
    except MappingError: 
      raise ConfigurationError( f"Invalid sig_scheme - only TLS1.3 sig_scheme" \
              "are expected: {conf[ ( 'tls13', 'v1' ) ][ 'sig_scheme' ]}." )

    sig_scheme = pylurk.tls13.crypto_suites.SigScheme( tls_sig_scheme )
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

  def set_tls13_keys( self, private_key_file=None, public_key_file=None, \
                      sig_scheme:str='ed25519', key_format='X509' ):
    """ configures the cryptographic material for the TLS 1.3 extension 

    This function generates the appropriated cryptographic material when
    needed. 
    This includes when the material is not specified or when not coherent.
       
    """
    ## Trying to derive directory from the files being provided.
    try:
       conf_dir = os.path.dirname( private_key_file )
    except:
      try:
        conf_dir = os.path.dirname( public_key_file )
      except:
        conf_dir = './'
    ## ensures that there is a private key
    try:  
      private_key = self.load_private_key( private_key_file )
    except :
      private_key, public_key = self.generate_keys( sig_scheme )
      private_file, public_file = self.store_keys( private_key, key_format, conf_dir )

    private_key = self.load_private_key( private_key_file )
    sig_scheme = self.key_algo( private_key )
    
    ## ensure there is a corresponding public key or certificate
    ## stored in the file and that public key matches the private key
    try :
      ## taking the last file mentioned in the public_key list
      public_key_file = self.conf[ ( 'tls13', 'v1' )  ] ['public_key'][ -1 ]
      public_key, cert_type = self.load_public_key( public_key_file )
      if self.key_algo( public_key ) !=  sig_scheme:
        raise ConfigurationError( f"public ({self.key_algo( public_key )}) and "\
                f"private keys ({self.key_algo( private_key )}) do not match" )
    except:
      private_key = self.load_private_key( private_key_file )
      public_key = private_key.public_key( )
      self.store_keys( public_key, key_format, conf_dir )
    return private_key_file, public_key_file


  def set_connectivity( self, **kwargs ):
    """configure the connectivity informations """
    self.conf[ 'connectivity' ] = kwargs 

  def set_tls13_debug( self, **kwargs ):
    """ updating the debug configuration
    
    There is a special check for the trace key
    """
    if 'trace' not in kwargs.keys() :
      kwargs[ 'trace' ] = False
    self.conf[ ( 'tls13', 'v1' ) ][ 'debug' ] = kwargs

  def set_tls13_authorization_type( self ):
    role = self.conf[ ( 'tls13', 'v1' ) ][ 'role' ]
    for k in self.conf[ ( 'tls13', 'v1' ) ][ 'type_authorized'] :
     
     if ( role == 'client' and k[0:2] == 's_' ) or\
        ( role == 'server' and k[0:2] == 'c_' ):
       self.conf[ ( 'tls13', 'v1' ) ][ 'type_authorized'].remove( k )

  def set_tls13_cs_signing_key( self ):
    """configure the CS signing keys and associated internal variables"""
   
    try: 
      private_file = self.conf[ ( 'tls13', 'v1' ) ][ 'private_key' ]
    except KeyError:
      private_file = None
    try:
      public_key_file = self.conf[ ( 'tls13', 'v1' )  ] ['public_key'][ -1 ]
    except KeyError:
      public_key_file = None
    try: 
      sig_scheme = self.conf[ ( 'tls13', 'v1' )  ] [ 'sig_scheme' ]
    except KeyError:
      sig_scheme = 'ed25519'
    private_key_file, public_key_file = self.set_tls13_keys( \
                                          private_key_file=private_file, \
                                          public_key_file=public_key_file, \
                                          sig_scheme=sig_scheme,\
                                          key_format='X509' )
    ## Once the files have been checked are correct we can load them
    public_key, cert_type = self.load_public_key( public_key_file )
    private_key = self.load_private_key( private_file )

    ## updating self.conf 
    self.conf[ ( 'tls13', 'v1' ) ][ 'private_key' ] = private_file
    ## handling the public key file is a bit more complex as the 
    ## file is a file list when key format X509 is used.
    public_key_conf_status = False
    if 'public_key' in self.conf[ ( 'tls13', 'v1' )  ].keys( ) :
      if isinstance( self.conf[ ( 'tls13', 'v1' )  ]['public_key'], list ):
        if self.conf[ ( 'tls13', 'v1' )  ] ['public_key'][ -1 ] == public_key_file :
          public_key_conf_status = True
    if public_key_conf_status is False:
      self.conf[ ( 'tls13', 'v1' )  ] ['public_key'] = [ public_key_file ]   
    self.conf[ ( 'tls13', 'v1' ) ] [ '_private_key' ] = private_key
    self.set_tls13_cs_public_signing_key( )

  def set_tls13_cs_public_signing_key( self ):
    """ set the configuration related to the public key 

    The reason we split the private and public key is to enable the 
    TLS Engine to configure the necessary (public) parameteres to build 
    its Certificate payload or identify the signature algorithm and keys.
    """
    public_key_file = self.conf[ ( 'tls13', 'v1' )  ] ['public_key'][ -1 ]
    public_key, cert_type = self.load_public_key( public_key_file )
    self.conf[ ( 'tls13', 'v1' ) ] [ '_public_key' ] = public_key 
    self.conf[ ( 'tls13', 'v1' ) ] [ '_cert_type' ] = cert_type
    cert_entry_list = self.load_cert_entry_list() 
    self.conf[ ( 'tls13', 'v1' ) ][ '_cert_entry_list' ] = cert_entry_list
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
