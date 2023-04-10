import os
import os.path
from  os.path import join
import pathlib
import shutil
import datetime
import argparse
#import pkg_resources
#import copy
#from copy import deepcopy
#import hashlib ## mostly for compatibility with key_schedule

from cryptography.hazmat.backends import default_backend
#from cryptography.hazmat.primitives.asymmetric.x25519 import \
#  X25519PrivateKey, X25519PublicKey
#from cryptography.hazmat.primitives.asymmetric.x448 import \
#  X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import \
  Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import \
  Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import \
  RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import \
  EllipticCurvePrivateKey, EllipticCurvePublicKey
#  SECP256R1, SECP384R1, SECP521R1, ECDSA, \
#  EllipticCurvePublicNumbers, ECDH,
from cryptography.hazmat.primitives.hashes import \
  Hash, SHA256
# SHA384, SHA512
from cryptography.hazmat.primitives.serialization import \
  load_der_private_key, load_der_public_key, load_der_public_key, \
  NoEncryption, Encoding, PrivateFormat, PublicFormat
# load_pem_private_key, \
from cryptography import x509
from cryptography.x509.oid import NameOID
#from cryptography.hazmat.primitives.asymmetric import padding
#from cryptography.hazmat.primitives.ciphers import \
#  Cipher, algorithms, modes
#from cryptography.hazmat.primitives.ciphers.aead import \
#  ChaCha20Poly1305, AESGCM, AESCCM
#from cryptography.hazmat.primitives.kdf.hkdf import \
#  HKDF, HKDFExpand

from construct.core import MappingError

import pytls13.struct_tls13 as tls

from pylurk.lurk.lurk_lurk import ConfigurationError
#  ImplementationError
# LURKError, \
#import pylurk.tls13.struct_tls13 as lurk
import pylurk.tls13.crypto_suites
#import binascii



class Configuration:
  """manipulates configuration file

    configuration class has two distinct goals:
      1. easing the use interactions with the configuration
        dictionary ( fill, remove items ). As to avoid
        misconfiguration, the initial configuration file expect
        to carry the minimal amount of information. For example,
        public key information is filled at one place, and any
        arguments are them derived from it - even tough this
        might require extra processing.

      2. generating informations that can be used by the
        software: This typically includes some information that
        can be derive. In this case, we would like to avoid
        information to be reprocessed muliutple times. For
        example, we do not want the certificate to read from the
        file each time a CERT message is sent.
        For that purpose we are adding some extra variables that
        are noted _key to distinguish from those expected from
        the user.

    Attributes:
      conf: a dictionary with all configuration parameters
  """

  def __init__( self ):
    """ initializes self.conf """

#    data_dir = pkg_resources.resource_filename(__name__, '../data/')
    self.conf = {
      'profile' : 'explicit configuration',
      'description' : "LURK Cryptographic Service configuration template",
      ## connectivity describes how to connect the CS
      ##  type: describe sthe type of connectivity.
      ##    Values include 'lib_cs', stateless_tcp, tcp, tcp+tls, http, https,..
      ##    The default type is lib_cs. other types are usually associated with
      ##    other parameters that needs to be provided explicitly
      'connectivity' : {
          'type' : "lib_cs"
           #'fqdn' : None,
           #'ip_address' : "127.0.0.1",
           #'port' : 9999,
           #'key' : join(data_dir, 'key_tls12_rsa_server.key'),
           #'cert' : join(data_dir, 'cert_tls12_rsa_server.crt'),
           #'key_peer' : join(data_dir, 'key_tls12_rsa_client.key'),
           #'cert_peer' : join(data_dir, 'cert_tls12_rsa_client.crt')
          },
      'enabled_extensions' : [ ( 'lurk', 'v1' ) , ( 'tls13', 'v1' ) ],
      ( 'lurk', 'v1' ) : {
         'type_authorized' : [ 'ping',  'capabilities' ]
      },
      ( 'tls13', 'v1' ) : {
        ## prints multiple useful information
        ## test_vector is not part of the default template and
        ## is expected to be explicitly provided.
        ##   trace (bool) : indicate to provide multiple information
        ##   file : is te path tho the file that is use to record the
        ##     parameters or to check the measured parameters against those
        ##     provided in the test vector
        'debug' : {
          'trace' : True,
          #'test_vector' : {
          #'file' : './illustrated_tls13.json',
          #'mode' : 'check', # possible value None /check / record
          #   }
        },
        ## role indicates if the CS is implemented for a
        ## TLS client or a TLS server
        'role' : 'server', #[ 'client', 'server' ],
        ## defines the type of LURK requests that are served by the
        ## CS.
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
        ## is the last one.
        ##
        ## Note that the file name follows a generic patent to specify
        ## the type of the key (in some case sig_scheme) as well as the
        ## type of encoding.
        ## This information are not necessary, and we shoudl be able to
        ## remove that constraint.
        ##
        ## Note that the chain of certificates is likely to be stored
        ## into a single file.
        #'public_key' : [join( data_dir, 'cert-rsa-enc.der' )],
        #'private_key' : join( data_dir, 'key-rsa-enc.pkcs8' ), ## der, pkcs8
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
         ## the key used to encrypt tickets
         ##
         #'ticket_public_key': join(data_dir, 'ticket-cert-rsa-enc.der'), ## one key
         #'ticket_private_key' : join( data_dir, 'key-rsa-enc.pkcs8'), ## der, pkcs8
         'ticket_len' : 4,  ## bytes < 255
         ## client parameters
         'post_handshake_authentication' : True,
         'max_post_handshake_authentication' : 1, ## 'c_post_hand_auth' ?
            },
    }

  def set_role( self, role:str ):
    """ set the role in the configuration

    Args:
      role: set the configuration to TLS client or TLS server. 
        rold must be either 'client' or 'server'
    """

    if isinstance( role, str ):
      if role not in [ 'client', 'server' ]:
        raise ConfigurationError( f"unknown role {role}." )
      # role = role
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

    Args:
      branch: the dictionary containing the configuration 
        parameters to be integrated
      master: the dictionary to which the branch is merged.
    """

    if master is None :
      master = self.conf
#    branch = copy.deepcopy( branch )
    for key in branch.keys():
      value_is_dict = isinstance( branch[ key ], dict )
      if value_is_dict is False or key not in master.keys() :
        master[ key ] = branch[ key ]
      else:
        master[ key ] = self.merge( branch[ key ], master[ key] )
    return master

  def generate_keys( self, tls_sig_scheme:str ):
    """ updates conf to serve the TLS signature scheme

    Args:
      tls_sig_scheme: the TLS signature scheme
    """

    try:
      tls.SignatureScheme.build( tls_sig_scheme )
    except MappingError as exc:
      raise ConfigurationError( f"Invalid sig_scheme - only TLS1.3 sig_scheme" \
            f"are expected: {self.conf[ ( 'tls13', 'v1' ) ][ 'sig_scheme' ]}." )

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
      key: the key object. When a private key is provided private
        and public keys are stored. ( RSAPrivateKey,
        RSAPublicKey, Ed25519PrivateKey, d25519PublicKey,
        Ed448PrivateKey, Ed448PublicKey, EllipticCurvePrivateKey,
        EllipticCurvePublicKey).
      key_format: the format of the storage ( Raw or 'X509' )

    Returns:
      file_name list
    """
# changed form pylint
#    if isinstance( key, RSAPrivateKey ) or \
#       isinstance( key, Ed25519PrivateKey ) or \
#       isinstance( key, Ed448PrivateKey ) or \
#       isinstance( key, EllipticCurvePrivateKey ) :
    if isinstance( key, ( RSAPrivateKey, Ed25519PrivateKey, \
                        Ed448PrivateKey, EllipticCurvePrivateKey ) ) :
      private = True
# changed form pylint
#    elif isinstance( key, RSAPublicKey ) or\
#         isinstance( key, Ed25519PublicKey ) or \
#         isinstance( key, Ed448PublicKey ) or \
#         isinstance( key, EllipticCurvePublicKey ) :
    elif isinstance( key, ( RSAPublicKey,  Ed25519PublicKey, \
                          Ed448PublicKey, EllipticCurvePublicKey ) ) :
      private = False
    else:
      raise ConfigurationError( f"unknown key class {key.__class__.__name__}" )
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
    else:
      public_key = key
    ## storing public key
    ## Note that storing self signed certificate requires the private key
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
      builder = builder.add_extension( x509.KeyUsage( \
                  digital_signature=True,
                  content_commitment=True,
                  key_encipherment=False,
                  data_encipherment=True,
                  key_agreement=False,
                  key_cert_sign=True,
                  crl_sign=False,
                  encipher_only=False,
                  decipher_only=False ), critical=False )
      ### CA
      ## Currently set to self-signed
      if private is True:
#        if isinstance( private_key, Ed25519PrivateKey ) or\
#             isinstance( private_key, Ed448PrivateKey ):
        if isinstance( private_key, ( Ed25519PrivateKey, Ed448PrivateKey ) ):
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
        raise ConfigurationError( "Cannot store public key. self signed " +\
                "certificate requires the private key to be provided" )
    else:
      raise ConfigurationError( f"invalid key format {key_format}")
    return private_file, public_file

  def load_public_key( self, public_file) :
    """ load the public key and define the key format"""

    pylurk.debug.check_file( public_file )
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
                raise ConfigurationError( \
                  f"Unable to load public key public_file {public_file}" )
    return public_key, cert_type

  def load_private_key( self, private_file ):
    """ returns the private key """

    pylurk.debug.check_file( private_file )
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
            private_key = load_der_private_key(private_bytes, \
                    password=None, backend=default_backend() )
          except:
            raise ConfigurationError( \
              f"Unable to load the private key from {private_file}" )
    return private_key

  def key_algo( self, key ) -> str :
    """ returns the key signature algorithm
    """
#    if isinstance( key, Ed25519PrivateKey ) or\
#       isinstance( key, Ed25519PublicKey ) :
    if isinstance( key, ( Ed25519PrivateKey, Ed25519PublicKey ) ) :
      algo = 'ed25519'
#    elif isinstance( key, Ed448PrivateKey ) or\
#        isinstance( key, Ed448PublicKey ) :
    elif isinstance( key, ( Ed448PrivateKey, Ed448PublicKey ) ) :
      algo  = 'ed448'
#    elif isinstance( key, EllipticCurvePrivateKey) or\
#        isinstance( key, EllipticCurvePublicKey ) :
    elif isinstance( key, ( EllipticCurvePrivateKey, EllipticCurvePublicKey ) ) :
      algo = 'ecdsa_' + key.curve.name
#    elif isinstance( key, RSAPrivateKey ) or\
#        isinstance( key, RSAPublicKey ) :
    elif isinstance( key, ( RSAPrivateKey, RSAPublicKey ) ) :
      algo = 'rsa'
    else:
      raise ConfigurationError( f"unknown algo for {key.__class__.__name__}" )
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

    Args:
      private_key_file (str): the file path for the private_key.
        It can be a directory, in which case, the private key
        will be generated into that directoiry. When not
        provided a file is generated in the local directory.
      public_key_file (str): the file path for the public_key
        (see private_key_file).

    """

    ## Derive directory from the provided files (when possible).
    try:
      if os.path.isfile( private_key_file ) :
        conf_dir = os.path.dirname( private_key_file )
      elif os.path.isdir( private_key_file ) :
        conf_dir = private_key_file
    except:
      try:
        if os.path.isfile( public_key_file ) :
          conf_dir = os.path.dirname( public_key_file )
        elif os.path.isdir( public_key_file ) :
          conf_dir = public_key_file
      except:
        conf_dir = './'
    ## ensures that there is a private key
    try :
      private_key = self.load_private_key( private_key_file )
    except ConfigurationError as e:
      print( e.message )
      print( "WARNING: Generating new keys")
      private_key, public_key = self.generate_keys( sig_scheme )
      private_key_file, public_key_file = self.store_keys( private_key, key_format, conf_dir )
      print( f"  - private_file: {private_key_file}" )
      print( f"  - public_file: {public_key_file}" )
      ## updating the configuration (only necessary when directory is provided)
      self.conf[ ( 'tls13', 'v1' )  ] ['private_key'] = private_key_file
      self.conf[ ( 'tls13', 'v1' )  ] ['public_key'] = [ public_key_file ]

#    finally:
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
##      self.store_keys( public_key, key_format, conf_dir )
      ##  we do store the private key as 1) storing the private key
      ## results in storing the public key. but also 2) storing the public
      ## key as a self-signed certificate requires the private key.
      self.store_keys( private_key, key_format, conf_dir )
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
    for k in list( self.conf[ ( 'tls13', 'v1' ) ][ 'type_authorized'] ) :

      if ( role == 'client' and k[0:2] == 's_' ) or\
         ( role == 'server' and k[0:2] == 'c_' ):
        self.conf[ ( 'tls13', 'v1' ) ][ 'type_authorized'].remove( k )

  def set_tls13_cs_signing_key( self ):
    """configure the CS signing keys and associated internal variables"""

    try:
      private_key_file = self.conf[ ( 'tls13', 'v1' ) ][ 'private_key' ]
    except KeyError:
      private_key_file = None
    try:
      public_key_file = self.conf[ ( 'tls13', 'v1' )  ] ['public_key'][ -1 ]
    except KeyError:
      public_key_file = None
    try:
      sig_scheme = self.conf[ ( 'tls13', 'v1' )  ] [ 'sig_scheme' ][ 0 ]
    except KeyError:
      sig_scheme = 'ed25519'
#    print( f"private_key_file: {private_key_file}" )
#    print( f"public_key_file: {public_key_file}" )
#    print( f"conf: {self.conf}" )
    private_key_file, public_key_file = self.set_tls13_keys( \
                                          private_key_file=private_key_file, \
                                          public_key_file=public_key_file, \
                                          sig_scheme=sig_scheme,\
                                          key_format='X509' )
    ## Once the files have been checked are correct we can load them
    ## we are just checking loading is performed correctly
    public_key, cert_type = self.load_public_key( public_key_file )
    private_key = self.load_private_key( private_key_file )

    ## updating self.conf
    self.conf[ ( 'tls13', 'v1' ) ][ 'private_key' ] = private_key_file
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


class CLI:
  """ Generates conf file from command line arguments.

  Template can be manually generated.
  The template is expected to provide a single port
  to each configuration.
  The template for a CS is expected to look this way:

  ..  code-block:: python

    cs_conf_template = {
    'connectivity' : {
       'type': 'tcp',
       'ip' : '127.0.0.1',
       'port' : 9402
      },
      ## logs are redirected to stdout especially when
      ## the cs is running in the enclave.
      'log' : None,
      ( 'tls13', 'v1' ) : {
        'public_key' : [ os.path.join( conf_dir, 
                         '_Ed25519PublicKey-ed25519-X509.der' ) ],
        'private_key': os.path.join( conf_dir, 
                         '_Ed25519PrivateKey-ed25519-pkcs8.der' ) ,
        'sig_scheme': ['ed25519']
      }
    }

  The reason we define a class is to be able to manage the
  various configuration of the CS with which also includes
  the implementation of illustrated_tls13 as well as the
  instantiation inside a sgx enclave.

  Attributes:
    connectivity: the type of connectivity for the CS. Possible values are
      'lib_cs' (default), 'tcp', 'persistent_tcp'
    debug: a boolean value that indicates if the debug mode is enabled
    test_vector_mode: indicates if values are expected to be taken from
      a test_vector file or recorded in a test_vector file or no 
      test_vector file is considered at all. The possible values are
      'check', 'record' or None (default).
    test_vector_file: when the test_vector_mode is not set to None, 
      the file the values are read from or written to. By default 
      it is set to None. 
    host: The IP address of the FQDN of the CS. This parameter is
      mostly useful for entities connecting to the CS as opposed to 
      the CS. The default is '127.0.0.1'.
    port: integer that defines the port of the CS set to 9400 by default.
    sig_scheme: the signature scheme the CS implements. This parameter
      may be redundant when the key is specified - but not necessarily.
      For example a RSA key may be used with different signature scheme.
      The scheme is also used to generate a key when the key is not 
      provided. By default, it is set to 'ed25519'.
    key: The file that contains the private key. By default it is set 
      to None and the key is generated at the instantiation of the CS.
    cert: The public key or certificate.
  """


  def __init__( self, connectivity:str='lib_cs',
                      debug:bool=False,
                      test_vector_mode=None,
                      test_vector_file=None,
                      host='127.0.0.1',
                      port=9400,
                      sig_scheme='ed25519',
                      key=None,
                      cert=None,
                      ):

    self.connectivity = connectivity
    self.debug = debug
    self.test_vector_mode = test_vector_mode
    self.test_vector_file = test_vector_file
    self.host = host
    self.port = port
    self.sig_scheme = sig_scheme
    self.key = key
    self.cert = cert


  def get_template( self ):
    """ generates the template

    Note that log is set to None and redirects the messages
    to the outputs.
    We define such value as to prevent writing an external file
    when teh server runs in an SGX enclave. We should define --log_level
    --log_file and force these values when SGX is enabled.
    """
    return { 'log' : None,
             'connectivity' : self.get_connectivity( ),
             ( 'tls13', 'v1' ) : self.get_tls13( ) }

  def get_debug( self ):
    debug_template = { 'trace' : self.debug }
    if self.test_vector_mode not in [ 'check', 'mode', None ]:
      raise ValueError( f"Invalid test_vector_mode value {self.test_vector_mode}")
    if self.test_vector_file is None:
      if self.test_vector_mode == 'check' :
        raise ValueError( f"non coherent values for test_vector_file"\
              f"{self.test_vector_file} and test_vector_mode {self.test_vector_mode}" )
      elif self.test_vector_mode == 'record' :
        self.test_vector_file = "./test_vector_file.json"
    else:
      if self.test_vector_mode is None:
        self.test_vector_mode == 'check'

    if self.test_vector_mode is not None:
      debug_template[ 'test_vector' ] = {}
      debug_template[ 'test_vector' ][ 'file' ][ self.test_vector_file ]
      debug_template[ 'test_vector' ][ 'mode' ][ self.test_vector_mode ]
    return debug_template


  def get_connectivity( self ):
    if self.connectivity not in [ 'lib_cs', 'tcp', 'persistent_tcp' ]:
      raise ValueError ( f"connectivity ({self.connectivity}) MUST be in "\
            f"'lib_cs', 'tcp', 'persistent_tcp'" )
    connectivity_template = { 'type' : self.connectivity }
    if connectivity_template [ 'type' ] != 'lib_cs' :
      connectivity_template [ 'ip' ] = self.host
      connectivity_template [ 'port' ] = self.port
    return connectivity_template

  def get_tls13( self ):
    tls13_template = { 'sig_scheme': [ self.sig_scheme ] }
    tls13_template[ 'public_key' ] = [ self.cert ]
    tls13_template[ 'private_key' ] = self.key
    tls13_template[ 'debug' ] = self.get_debug( )
    return tls13_template


  def get_parser( self, env:bool=True, conf_dir:str='./',
                  parser=None):
    """ This function returns a parser to start the CS

    The CS can be started as a regular library in which case
    only library related parameters are provided.
    On the other hand, the CS MAY also requires some speciifc
    OS configuration to start the service.
    These parameters are not handled by the CS library itself,
    but actually defines how the library is started.

    Args:
      env (bool) when set to False indicates that only the
        library parameters are provided.
        When set to True, this includes OS specific environement
        configuration parameters.
      conf_dir (str): The path to the CS directory. It is
        expected to contain the CS enclave as well as some
        parameters such as the keys, certificate.

    """


    if parser is None:
      if env is True:
        description = \
        """
        This scripts launches the Crypto Service in various modes.
        These modes includes:

        1) launching the Crypto Service in the rich environement
        - that is like a standard python library in the OS.
        This is the defaul mode.
        
        2) lauching the Crypto Service in an SGX enclave using
        Gramine. This is indicated by the -sgx or
        --gramine_sgx option.
        
        3) launching the Crypto Service with Gramine but NOT
        in a SGX enclave.
        This is indicated by the -g or --grammine_direct option

        To start the Crypto Service using SGX, the Crypto Service
        the enclave MUST have been previously built.
        Building the enclave is performed using the -b or
        --gramine_build option.

        This script can be seen as setting the expected environement
        to start the Crypto Service.
        However the Crypto Service (with its expected configuration)
        is actually started by the start_cs.py script.
        Most of the arguments are passed to that start_cs.py

        Example:
          ## Building the enclave (needs only to be performed once)
          ./crypto_service --gramine_build

          ## Starting the CS in an SGX enclave
          ./crypto_service --connectivity tcp --sig_scheme ed25519
            --gramine_sgx
        """

      else :
        description = \
        """
        This script configure the CS but not the OS environment
        parameters.
        """
      parser = argparse.ArgumentParser( description=description )

##    parser = argparse.ArgumentParser( description=description )
    parser.add_argument( '-con', '--connectivity', type=ascii, \
      default='tcp', nargs='?', \
      help='Crypto Service  connectivity [ tcp, persistent_tcp ]')
    parser.add_argument( '-host', '--host', type=ascii, \
      default='127.0.0.1', nargs='?', \
      help='Crypto Service  IP address or hostname')
    parser.add_argument( '-port', '--port', type=int, \
      default='9400', nargs='?', \
      help='Crypto Service  port')
    parser.add_argument( '-sig', '--sig_scheme', \
      type=ascii, default='ed25519', nargs='?', \
      help='Crypto Service  signature scheme  [ ed25519 ]')
    ## We mandate the CS to have a public / private key
    ## and currently do not consider the key not to be used.
    ## this may not represent the case of an unauthenticated
    ## TLS client.
    ##
    ## With SGX the file needs to be local - as it is configured
    ## in the  python template.
    ## There might need to take different path depending on
    ## whether crypto_service or strat_cs is used.
    ## currently We assume that one is in the local directory.
#    key_file = os.path.join( './sig_key_dir', \
#                 '_Ed25519PrivateKey-ed25519-pkcs8.der' )
#    key_file = os.path.join( conf_dir, 'sig_key_dir', \
#                 '_Ed25519PrivateKey-ed25519-pkcs8.der' )
    parser.add_argument( '-key', '--key', \
      type=pathlib.Path, default=None, nargs='?', \
      help='Crypto Service  private key')
#    cert_file = os.path.join( conf_dir, 'sig_key_dir', \
#                  '_Ed25519PublicKey-ed25519-X509.der' )
#    cert_file = os.path.join(  './sig_key_dir', \
#                  '_Ed25519PublicKey-ed25519-X509.der' )
    parser.add_argument( '-cert', '--cert', \
      type=pathlib.Path, default=None, nargs='?', \
      help='Crypto Service  public key')
    parser.add_argument( '-debug', '--debug', default=False,  \
      action='store_const', const=True, \
      help='Crypto Service debug_mode')
    parser.add_argument( '-tv_mode', '--test_vector_mode', \
      type=ascii, default=None, nargs='?', \
      help="Crypto Service  test vector mode [ 'check', 'record', None ]" )
    parser.add_argument( '-tv_file', '--test_vector_file', \
      type=pathlib.Path, default=None, nargs='?', \
      help='Crypto Service  test vector file')
#    print( f"env - 2: {env}" )
    if env is True:
      parser.add_argument( '-sgx', '--gramine_sgx', default=False,  \
        action='store_const', const=True, \
        help='Crypto Service is run into SGX (gramine)')
      parser.add_argument( '-g', '--gramine_direct', default=False,  \
        action='store_const', const=True, \
        help='Crypto Service is run into SGX (gramine)')
      parser.add_argument( '-b', '--gramine_build', default=False,  \
        action='store_const', const=True, \
        help='Build the Crypto Service into the enclave')
      parser.add_argument( '-sec_prov', '--secret_provisioning',\
        default=False,  action='store_const', const=True, \
        help='Enable Secret Provisioning')
      parser.add_argument( '-ra_type', '--ra_type', type=ascii, \
        default='None', nargs='?', help='type of remote attestation')
      parser.add_argument( '-ra_spid', '--ra_spid', type=ascii, \
        default='None', nargs='?', \
        help='Service Provider ID for remote attestation ')
      parser.add_argument( '-ra_linkable', '--ra_linkable', \
        type=ascii, default='None', nargs='?', \
        help='Specify whether EPID attestation is linkable or not.')
      parser.add_argument( '-gramine_dir', '--gramine_dir',\
        type=ascii, default='None', nargs='?', \
        help='Specify whether EPID attestation is linkable or not.')

    return parser

  def init_from_args( self, args ):
    """initializes the variables from the command lines arguments

    The command lines have been parsed with the parser obtained
    from get_parser.

    Args:
      args: the output returned by parser.parse_args( )
    """
    if args.test_vector_mode is None:
      test_vector_mode = None
    else:
      test_vector_mode = args.test_vector_mode[ 1:-1 ]
    if args.test_vector_file is None:
      test_vector_file = None
    else:
      test_vector_file = args.test_vector_file[ 1:-1 ]

    self.connectivity = args.connectivity[1:-1]
    self.debug = args.debug
    self.test_vector_mode=test_vector_mode
    self.test_vector_file=test_vector_file
    self.host=args.host[1:-1]
    self.port=args.port
    self.sig_scheme=args.sig_scheme[1:-1]
    self.key=args.key
    self.cert=args.cert

  def copy_and_update_file_path( self, origin_file_path, \
      GRAMINE_DIR, sub_dir='' ):
    """ copy and upadte the file paths so it can be used by gramine

    Gramine requires all elements it trusts to be below the
    script starting Gramine.

    When a key file is provided, the file is copy under the
    specific con_dir location and the new file path is returned.
    The new file path is relative to the gramine directory.
    """
    try:
      shutil.copy( origin_file_path, os.path.join( GRAMINE_DIR, sub_dir ) )
    except shutil.SameFileError :
      pass
    return os.path.join( './', sub_dir, \
             os.path.basename( origin_file_path) )


