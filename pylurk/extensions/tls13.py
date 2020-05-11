from secrets import randbits, token_bytes
from  os.path import join
from copy import deepcopy


from typing import Union, NoReturn, TypeVar, List  

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


from construct.core import *
from construct.lib import *
#from pylurk.extensions.tls12_struct import FreshnessFunct, KeyPairId
from pylurk.extensions.tls13_tls13_struct import PskIdentity, Certificate,\
                                                  SignatureScheme, Handshake
from pylurk.extensions.key_schedule import TlsHash
from pylurk.core.conf import default_conf

import pkg_resources
data_dir = pkg_resources.resource_filename(__name__, '../data/')

LINE_LEN = 75

class LURKError(Exception):
    """ Generic Error class
    """
    def __init__(self, expression, message, status):
        self.expression = expression
        self.message = message
        self.status = status

err_impl = 'implementation_error' 

def get_struct(l: list, key:str, value) -> dict :
  """ return the first element of the list that contains  key:value """
  for e in l:
    if e[ key ] == value:
      return e
  return None

def get_struct_index(l: list, key:str, value) -> dict :
  """ return the first element of the list that contains  key:value """
  for e in l:
    if e[ key ] == value:
      return l.index(e)
  return None


def get_structs(l: list, key: str, value) -> list :
  """ return the list of structures that contains  key:value """
  sub_list = []
  for e in l:
    if e['key'] == value:
      sub_list.append(e)
  return sub_list


def match_list(l: list, mandatory: list = None,\
                        optional: list = None, \
                        forbiden: list = None) -> None :
  if mandatory != None:
    for e in mandatory:
      if e not in l:
        raise LURKError( (l , e), "Missing mandatory elements [%s]"%e,  err_impl)

  if optional != None and mandatory != None:
    for e in l:
      if e not in mandatory and e not in optional:
        raise LURKError( (l, e), "Unexpected element  [%s]"%e,  err_impl )

  if forbiden != None:
    for e in forbiden:
      if e in l:
        raise LURKError( (l, e), "Forbidden element  [%s]"%e,  err_impl )
  return True       


class SigAlgo:
  def __init__( self, name:str)-> NoReturn :
    self.name = name
    self.algo = self.get_algo()
    self.hash = self.get_hash() 
    self.pad = self.get_pad()
    self.curve = self.get_curve()

  
  def get_algo( self ):
    return self.name.split('_')[0]

  def get_hash( self ):
    print("::: self.algo: %s"%self.algo )
    if self.algo not in [ 'rsa', 'ecdsa' ]:
      return None
    hash_algo = self.name.split( '_' )[-1]
    if hash_algo == 'sha256':
      h = SHA256()
    elif hash_algo == 'sha384':
      h = SHA384()
    elif hash_algo == 'sha512':
      h = SHA512()
    else:
      raise LURKError( hash_algo, 'not implemented', 'conf_error' )
    return h

  def get_curve( self ): # -> Union[ SECP256R1, SECP384R1, SECP521R1 ] :
    if self.algo != 'ecdsa':
      return None
    curve_name = self.name.split( '_' )[1] 
    print( "::: curve_name: %s"%curve_name )
    if  curve_name == 'secp256r1':
      curve = SECP256R1()
    elif curve_name == 'secp384r1':
      curve = SECP384R1()
    elif curve_name == 'secp521r1':
      curve = SECP521R1()
    else:
      raise LURKError( curve_name, 'not implemented', 'conf_error' )
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
      raise LURKError( pad_name, 'not implemented', 'conf_error' )
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
      raise LURKError( ( sig_algo, type( private_key ) ),\
      'incompatible private key and signature algorithm', \
      'invalid_signature_scheme' )
    if isinstance( key, EllipticCurvePrivateKey ):
      if isinstance( key.curve, type( self.curve ) ) == False:
        raise LURKError( ( self.curve, key.curve ),\
          'incompatible curve and signature algorithm',\
          'invalid_signature_scheme' )


class Conf:

  def __init__(self,  conf: dict = deepcopy(default_conf) ) -> NoReturn:
    self.conf = conf
    ## server_certificate parameters
    try:
      public_files = self.msg('s_init_cert_verify')[ 'public_key' ]
      self.public_key, self.cert_type =\
        self.load_public_key( public_files[ -1 ] ) 
      self.hs_cert_msg, self.cert_finger_print =\
        self.cert_msg( public_files )
    except:
      self.public_key = None
      self.cert_type = None
      self.hs_cert_msg = None
      self.cert_finger_print = None
    private_file = self.msg( 's_init_cert_verify' )[ 'private_key' ]
    self.private_key = self.load_private_key( private_file ) 
    self.key_type = self.get_type( self.public_key )  
    try:
      private_file = self.msg( 's_init_cert_verify' )[ 'private_key' ]
      self.private_key = self.load_private_key( private_file ) 
      self.key_type = self.get_type( self.public_key )  
    except:
      print("::: %s"%self.msg( 's_init_cert_verify' ))
      self.private_key =None
      self.key_type = None
    
    print("::: self.public_key : %s"%self.public_key)
    print("::: self.private_key : %s"%self.private_key)
    print("::: self.hs_cert_msg : %s"%self.hs_cert_msg)
    print("::: self.cert_finger_print : %s"%self.cert_finger_print )
    self.check_keys(self.private_key, self.public_key)
    self.check_key_sig_algo()

  def is_in_classes( self, obj, class_list):
    tests = [ isinstance( obj, c ) for c in class_list ]
    if True not in tests:
      raise LURKError( type(obj), 'unacceptable class. ' +\
      'Expected classes %s'%class_list, 'conf_error')
    return tests.index(True)

  def check_keys( self, private_key, public_key ) -> NoReturn :
    """checks compatibility between public/private keys """
    private_classes = [ Ed25519PrivateKey, Ed448PrivateKey,\
                        EllipticCurvePrivateKey, RSAPrivateKey ]
    public_classes = [ Ed25519PublicKey, Ed448PublicKey,\
                       EllipticCurvePublicKey, RSAPublicKey ]
    if private_key != None:
      private_i = self.is_in_classes( private_key, private_classes )
    if public_key != None:
      public_i = self.is_in_classes( public_key, public_classes )
    if private_key != None and public_key != None:
      if private_i != public_i:
        raise LURKError( ( type( private_key ), type( public_key ) ),\
        'incompatible public and private key', 'conf_error' )
    ## check public are private are associated TBD  

  def check_key_sig_algo( self ) -> NoReturn :
    """checks compatibility between signature algorithms and keys """
    if self.private_key == None:
      raise LURKError('', 'missing private key', 'conf_error' )
    sig_algo_list = self.msg( 's_init_cert_verify' )[ 'sig_algo' ]
    for sig_algo in sig_algo_list:
      sig = SigAlgo(sig_algo)
      sig.matches( self.private_key )

  def load_private_key( self, private_bytes_source:str):
##        -> Union[ Ed25519PrivateKey, Ed448PrivateKey, RSAPrivateKey, \
##                  EllipticCurvePrivateKey ] :
    """ returns the private key """
    print("::: private_bytes_source: %s"%private_bytes_source )
    with open( private_bytes_source, 'rb' )  as f:
      private_bytes = f.read()
      print( "::: %s"%private_bytes )
      ## ed25519
      try:
        key  = Ed25519PrivateKey.from_private_bytes(private_bytes)
      except:
      ## ed448
        try:
          key  = Ed448PrivateKey.from_private_bytes(private_bytes)
        except:
        ## RSA / ECDSA
          try:
            key = load_der_private_key(private_bytes, password=None, backend=default_backend())
          except:
            LURKError( private_key_source, 'unable to load private key',\
                      'conf_error')
      return key 

  def load_public_key( self, public_bytes_source:str):
##         -> Union[ RSAPublicKey, EllipticCurvePublicKey,\
##                   Ed25519PublicKey, Ed448PublicKey ] :
    """ load the public key and define the key format""" 
    with open(public_bytes_source, 'rb' )  as f:
      public_bytes = f.read()
    ## trying to load the certificate
    try:
      cert = x509.load_der_x509_certificate(public_bytes, default_backend())
      public_key = cert.public_key() 
      cert_type = 'X509'
      print("::: cert (DER) %s"%cert )
      print("::: cert public_key %s"%public_key )
    except:
      try:
        cert = x509.load_pem_x509_certificate(public_bytes, default_backend())
        public_key = cert.public_key() 
        cert_type = 'X509'
      except:
        ## trying to load the raw public key
        try:
          public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
          cert_type = 'Raw'
        except: 
          try:
            public_key = Ed448PublicKey.from_public_bytes(public_bytes)
          except:
            ## RSAPublicKey, EllipticCurvePublicKey,
            try: 
             public_key = load_pem_public_key(public_bytes, backend=default_backend())
             cert_type = 'Raw'
            except:
              try:
                public_key = load_der_public_key(public_bytes, backend=default_backend())
                cert_type = 'Raw'
              except:
                raise LURKError( public_source, \
                                 'unable to load public key', 'conf_error')
    return public_key, cert_type

  def get_type( self, key ):
    """ returns the type of key """
    if isinstance( key, Ed25519PrivateKey ) or\
       isinstance( key, Ed25519PublicKey ) : 
      key_type = 'ed25519'
    elif isinstance( key, Ed448PrivateKey ) or\
        isinstance( key, Ed448PublicKey ) : 
       key_type = 'ed448'
    elif isinstance( key, EllipticCurvePrivateKey) or\
        isinstance( key, EllipticCurvePublicKey ) : 
       key_type = 'ecdsa_' + key.curve.name 
    elif isinstance( key, RSAPrivateKey ) or\
        isinstance( key, RSAPublicKey ) : 
       key_type = 'rsa'
    else:
      raise LURKError(self.private_key, 'unkown key type', 'conf_error')
    return key_type 

  def msg( self, lurk_msg:str) -> dict:
    """ returns the conf structure associated to the lurk message """
    return get_struct( self.conf['extensions'], 'type', lurk_msg)

  def role(self):
    return self.conf['role']

  def cert_msg(self, public_key_bytes_sources:list ) -> ( dict, bytes ):
    cert_files = self.msg('s_init_cert_verify')['public_key']
    key, cert_type = self.load_public_key(cert_files[0])
    cert_list = []
    print("::: cert_type: %s"%cert_type )
    for cert_file in cert_files:
      key, current_cert_type = self.load_public_key( cert_file )
      if cert_type != current_cert_type:
        raise LURKError( self.conf['certificate'], 'unmatched cert types',
                         'conf_error')    
      print(":::current_cert_type: %s"%current_cert_type )
      print(":::cert_file: %s"%cert_file )
      with open( cert_file, 'rb' ) as f:
        public_bytes = f.read() 
      print(":::public_bytes: %s"%public_bytes )
      cert_list.append( { 'cert' : public_bytes, 'extensions': [] } ) ## certificateEntry
    print(":::cert_list: %s"%cert_list )
      
    hs_cert = { 'msg_type' : 'certificate', 
                 'data' :  { 'certificate_request_context': b'',
                             'certificate_list' : cert_list } }
    bytes_hs_cert = Handshake.build( hs_cert, _certificate_type=cert_type )
    digest = Hash( SHA256(), backend=default_backend())
    digest.update( Handshake.build( hs_cert, _certificate_type=cert_type ))
    finger_print = digest.finalize()
    return hs_cert, finger_print


class ConfBuilder( Conf ):

  def __init__( self, conf: dict = deepcopy( default_conf ) ) -> NoReturn:
    self.conf = conf
    self.private_key = None
    self.public_key = None
    self.private_key_file = None
    self.public_key_files = None
    self.key_format = None
    self.sig_algo = None

  def update_msg( self, msg_conf:dict) -> None:
    """updates configuration with msg_conf"""
    for ext_conf in self.conf['extensions']:
      if ext_conf[ 'designation' ] == msg_conf[ 'designation' ] and\
         ext_conf[ 'version' ] == msg_conf[ 'version' ] and\
         ext_conf[ 'type' ] == msg_conf[ 'type' ]:
        index = self.conf['extensions'].index(ext_conf)
        self.conf['extensions'][ index ] = msg_conf
         
  def generate_keys( self, sig_algo:str, key_format='X509' ):
    """generates keys according to the algorithm and format """
  
    SignatureScheme.build( sig_algo )
    self.sig_algo = SigAlgo( sig_algo )
    if key_format not in [ 'X509', 'Raw' ]:
      raise LURKError( key_format, 'unknown key format', 'conf_error' )

    if self.sig_algo.algo == 'ed25519':
      self.private_key = Ed25519PrivateKey.generate()
    elif self.sig_algo.algo == 'ed448':
      self.private_key = Ed448PrivateKey.generate()
    elif self.sig_algo.algo == 'ecdsa': 
      self.private_key = ec.generate_private_key(
          self.sig_algo.curve, default_backend())
    elif 'rsa' in sig_algo:
      self.private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048,
        backend=default_backend())
    else:
      raise LURKError( sig_algo, 'not implemented', 'conf_error' )
    self.public_key = self.private_key.public_key()
    self.store_keys( key_format )
    self.update_conf()

  def store_keys( self, key_format ): # type 'X509', 'Raw'
    """ stores self.public_key in files """
    print("::: public_key: %s"%self.public_key ) 
    self.key_format = key_format
    self.private_file = join( data_dir, \
                         self.private_key.__class__.__name__ + '-' +\
                         self.sig_algo.algo + '-pkcs8.der' )
   ## storing private key
    with open( self.private_file, 'wb' ) as f:
      f.write( self.private_key.private_bytes( encoding=Encoding.DER,\
                 format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption() ) )

    ## storing public key
    self.public_file = join( data_dir, \
                        self.public_key.__class__.__name__ + '-' +\
                        self.sig_algo.algo + '-' + key_format + '.der' )
    if self.key_format == 'Raw':
      with open( self.public_file, 'wb' ) as f:
        f.write( self.public_key.public_bytes(
          encoding=Encoding.DER,  format=PublicFormat.SubjectPublicKeyInfo))
    elif self.key_format == 'X509':
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
      builder = builder.public_key( self.public_key )
      builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u'cryptography.io')] ),\
          critical=False )
      ### CA
      ## Currently set to self-signed
      if isinstance( self.private_key, Ed25519PrivateKey ) or\
           isinstance( self.private_key, Ed448PrivateKey ):
        ca_algo = None
      else: 
        ca_algo = SHA256()
      builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True, )
      certificate = builder.sign(
        private_key=self.private_key, algorithm=ca_algo,
        backend=default_backend() )
      with open( self.public_file, 'wb' ) as f:
        f.write( certificate.public_bytes( Encoding.DER ) )
    else:
      LURKError( key_format, 'unknown format for key', 'conf_error')

  def update_conf( self ):
    """ updates the conf """
    if self.role() == 'server':
      conf_ext = self.msg('s_init_cert_verify')
      conf_ext['public_key'] = [ self.public_file ]
      conf_ext['private_key'] = self.private_file
      conf_ext['sig_algo'] = [ self.sig_algo.name ]
    elif self.role() == 'client':
      pass

    self.update_msg( conf_ext )

  def export( self ) -> dict:
    return deepcopy( self.conf )




class Ephemeral:

  def __init__(self, ephemeral:dict, conf, mtype, handshake_ctx:dict) -> None:
    """ initializes the object based on the structure """

    self.struct = ephemeral
    self.conf = conf
    self.mtype = mtype
    self.method = self.struct['ephemeral_method']

    if self.method not in conf.msg(mtype)['ephemeral_methods']:
      raise LURKError( self.method, "unsupported ephemeral mode " + \
                 "supported modes [%s]"%\
                 conf.msg('s_init_cert_verify')[ 'ephemeral_methods' ], \
                 'invalid_ephemeral')
    self.server_key_exchange = None
    self.ecdhe = None 
      
    if mtype == 's_init_cert_verify':
      handshake = TlsHandshake( conf )
      handshake.insert( handshake_ctx )
      self.compute_server_key_exchange( handshake ) 


  def compute_server_key_exchange(self, handshake ):
    """ treat ephemeral extension and initializes self.ecdhe, self.server_key_exchange """ 
    if self.method == 'shared_secret':
      ## makes more sense if only one secret is sent, not a list
      self.ecdhe = self.struct['key'][ 'shared_secret' ]
    elif self.method == 'secret_generated':
      ## key_shae is taken in the serverhello to make sure the extension
      ## is in the same place. Note that inserting the extension
      ## may require to update all length.
      server_hello_exts = handshake.msg( 'server_hello' )['extensions']
      server_key_share = get_struct(server_hello_exts, 'extension_type', 'key_share' )
      self.group = server_key_share[ 'extension_data' ][ 'server_share' ][ 'group' ]
      client_hello_exts = handshake.msg( 'client_hello' )[ 'extensions' ]
      client_key_share = get_struct(client_hello_exts, 'extension_type', 'key_share' )
      client_shares = client_key_share[ 'extension_data' ][ 'client_shares' ]
      client_key_exchange = get_struct(client_shares, 'group', self.group)
       
      if self.group not in self.conf.msg( self.mtype )[ 'authorized_ecdhe_group' ]:
        raise LURKError( self.group, "unsupported group " + \
               " [%s]"%forbiden_keys, 'invalid_key_request')

      client_public_key = client_key_exchange[ 'key_exchange' ]
      if self.group in [ 'secp256r1', 'secp384r1', 'secp521r1' ]:
        if self.group ==  'secp256r1':
          curve =  SECP256R1()
        elif self.group ==  'secp394r1':
          curve = SECP384R1()
        elif self.group ==  'secp521r1':
          curve = SECP521R1()
        server_private_key = ec.generate_private_key( curve, default_backend())
        server_public_key = private_key.public_key()
        server_public_numbers = server_public_key.public_numbers()
        self.server_key_exchange = {'x' : server_public_numbers.x, 
                                    'y' : server_public_numbers.y }    
        client_public_key = EllipticCurvePublicNumbers( client_public_key[ 'x' ], 
                              client_public_key[ 'y' ], curve) 
        self.ecdhe = server_private_key.exchange( ECDH(), client_public_key())
      elif self.group  in [ 'x25519', 'x448' ]:
        if self.group == 'x25519':
          server_private_key = X25519PrivateKey.generate()
          client_public_key = X25519PublicKey.from_public_bytes(client_public_key) 
        elif self.group == 'x448':
          server_private_key = X448PrivateKey.generate()
          print("::: client_key_exchange [%s bytes ]: %s"%\
            ( len(client_key_exchange), client_key_exchange ) )
          client_public_key = X448PublicKey.from_public_bytes(client_public_key) 
        server_public_key = server_private_key.public_key() 
        self.server_key_exchange = server_public_key.public_bytes(
          encoding=Encoding.Raw, format=PublicFormat.Raw)
        self.ecdhe = server_private_key.exchange(client_public_key)

  def serve( self):
    if self.method == 'secret_generated' and self.server_key_exchange != None :
      return { 'extension_type' : 'ephemeral',\
               'extension_data' : \
                 { 'ephemeral_method' : self.method, 
                   'key' : { 'group' : self.group, \
                             'key_exchange' : self.server_key_exchange } } }
    else:
      LURKError( self.method, "unexpected ephemeral", 'implementation_error') 

class SessionID:
  def __init__( self, session_id:bytes):
    self.outbound =  session_id
    self.inbound = token_bytes( 4  )

class Freshness:
  def __init__( self, freshness:int):
      self.freshness_funct = freshness
  
class PskID:
  def __init__( self, psk_id:dict ) -> NoReturn: 
    self.identity = psk_id[ 'identity' ]
    self.obfuscated_ticket_adge = psk_id[ 'obfuscated_ticket_age' ]


class Cert:
  def __init__( self, finger_print:bytes ):
    pass

class SigScheme:
  def __init__( self, finger_print:bytes ):
    pass
  


class KeyRequest:

  def __init__( self, key_request, mtype, conf ):
    self.authorized_secrets = []

    if mtype == 's_init_early_secret':
      mandatory = ['b']
      forbiden = [ 'h_c', 'h_s', 'a_c', 'a_s', 'x', 'r'] 
      optional = [ 'e_c', 'e_x' ]
    elif mtype in [ 's_init_cert_verify' or 's_hand_and_app_secret']:
      mandatory = [ 'h_c', 'h_s']
      forbiden = [ 'b', 'e_c', 'e_x', 'x', 'r']
      optional = [ 'a_c', 'a_s', 'x' ]
    elif mtype == 's_new_ticket':
      mandatory = []
      forbiden = [ 'b', 'e_c', 'e_x', 'h_c', 'h_s', 'a_c', 'a_s', 'x']
      optional = ['r'] 
    elif mtype == 'c_binder_key':
      mandatory = [ 'b' ]
      forbiden = [ 'e_c', 'e_x', 'h_c', 'h_s', 'a_c', 'a_s', 'x', 'r']
      optional = []
    elif mtype == 'c_init_early_secret':
      mandatory = []
      forbiden = [ 'b', 'e_c', 'e_x', 'h_c', 'h_s', 'a_c', 'a_s', 'x', 'r']
      optional = ['e_c', 'e_x']
    elif mtype in [ 'c_init_hand_secret', 'c_hand_secret' ]:
      mandatory = ['h_c', 'h_s']
      forbiden = [ 'b', 'e_c', 'e_x', 'a_c', 'a_s', 'x', 'r']
      optional = []
    elif mtype in [ 'c_app_secret', 'c_cert_verify' ]:
      mandatory = []
      forbiden = [ 'b', 'e_c', 'e_x', 'r']
      optional = ['a_c', 'a_s',  'x' ]
    elif mtype == 'c_register_ticket':  
      mandatory = []
      forbiden = [ 'b', 'e_c', 'e_x', 'h_c', 'h_s', 'a_c', 'a_s', 'x']
      optional = ['r'] 
    elif mtype == 'c_post_hand':
      mandatory = []
      forbiden = [ 'b', 'e_c', 'e_x', 'h_c', 'h_s', 'a_c', 'a_s', 'x', 'r']
      optional = [] 
    ## building the list of requested secrets, that is
    ## those set to True in key_request 
    for key in key_request.keys():
      if key_request[ key ] == True:
        self.authorized_secrets.append( key )
    try:
      match_list( self.authorized_secrets, mandatory=mandatory,\
                  forbiden=forbiden, optional=optional)
    except LURKError as e :
      raise LURKError( e.expression, e.message , 'invalid_key_request')

    if mtype == 's_init_cert_verify':
      if conf.msg( mtype )[ 'app_secret_authorized' ] == False: 
        self.authorized_secrets.remove( 'a_c' )
        self.authorized_secrets.remove( 'a_s' )
      if conf.msg( mtype )[ 'exporter_secret_authorized' ] == False: 
        self.authorized_secrets.remove( 'x' )
    if mtype == 's_new_ticket':
      if conf.msg( mtype )[ 'resumption_secret_authorized' ] == False: 
        self.authorized_secrets.remove( 'x' )
    if mtype == 's_init_early_secret':
      if conf.msg( mtype )[ 'client_early_secret_authorized' ] ==  False:
        self.authorized_secrets.remove( 'e_c' )
      if conf.msg( mtype )[ 'early_exporter_secret_authorized' ] ==  False:
        self.authorized_secrets.remove( 'e_x' )


class SecretReq:

  def __init__(self, secret_req, conf, mtype):
    ## self.secret_req = secret_req 
    self.conf = conf
    self.mtype = mtype
    self.hs_ctx = secret_req['handshake_context']
    self.key_request = KeyRequest(secret_req[ 'key_request' ], mtype, conf )
    self.ticket_nbr = None

    ## extensions
    self.ephemeral = None
    self.session_id = None
    self.freshness = None
    self.psk_id = None
    self.cert_fingher_print = None

    extensions = secret_req[ 'extension_list' ]
    print("::: extensions: %s"%extensions )
    ext_types = [ e[ 'extension_type' ] for e in extensions ]
    self.check_exts( ext_types, mtype )
    for ext in extensions:
      ext_type = ext[ 'extension_type' ]
      ext_data = ext[ 'extension_data' ]
      if ext_type == 'psk_id':
        pass 
      elif ext_type == 'ephemeral':
        self.ephemeral = Ephemeral( ext_data, conf, mtype, \
                                    secret_req['handshake_context'] ) 
      elif ext_type == 'freshness':
        print("::: ext_data %s"%ext_data )
        self.freshness = Freshness( ext_data ) 
      elif ext_type == 'session_id':
        if self.conf.msg( mtype )[ 'session_id_ignored' ] is False: 
          self.session_id = SessionID( ext_data )
      elif ext_type == 'cert_finger_print':
        pass
      elif ext_type == 'sig_algo':
        pass

    if mtype == 's_new_ticket':
      self.ticket_nbr = secret_req[ 'ticket_nbr' ]

       
  def check_exts( self, extension_type_list, mtype ):
    """ sanity checks for LURK extensions """
    if self.mtype == 's_init_early_secret':
      mandatory = ['psk_id', 'session_id' ]
      forbiden = ['ephemeral', 'freshness' ]
    elif self.mtype == 's_init_cert_verify':
      mandatory = ['ephemeral', 'freshness' ]
      optional = [ 'session_id' ] 
      forbiden = [ 'psk_id' ]
    elif self.mtype == 's_hand_and_app_secret':
      mandatory = [ 'freshness' ]
      if self.conf[ 'ephemeral' ] == True:
        mandatory.append( 'session_id' ) 
      forbiden = [ 'psk_id' ]
    elif self.mtype == 's_new_ticket':
      mandatory = []
      forbiden = ['ephemeral', 'psk_id', 'freshness']

    if len(set(extension_type_list)) != len(extension_type_list):
      raise LURKError( self.secret_req, "duplicated extensions " + \
              "Found [%s]"%extension_type_list, 'invalid_extension')
    try:
      match_list(extension_type_list, mandatory=mandatory, forbiden=forbiden)
    except LURKError as e :
      e.status = 'invalid_extension'
      raise e

  def serve( self, key_scheduler ):
   
    ## secret_response --> To be moved to key_request
    secret_list = []
    for secret_type in self.key_request.authorized_secrets:
      secret_list.append( \
        { 'secret_type' : secret_type, 
          'secret_data' : key_scheduler.secrets[ secret_type ] } ) 
    ### should the check be part of the extention ?
    ext_list = []
    if isinstance( self.ephemeral, Ephemeral ):
      if self.ephemeral.method == 'secret_generated':
        ext_list.append( self.ephemeral.serve( ) )
        
    if isinstance( self.session_id, SessionID) : 
      if self.mtype in [ 's_init_cert_verify', 's_init_early_secret' ]:  
      if self.conf.msg( mtype )[ 'session_id_ignored' ] == False: 
           ext_list.append( {  'extension_type' : 'session_id',
                               'extension_data' : self.session_id.inbound } )
    if self.mtype == 's_init_early_secret':
      resp = { 'secret_list' : secret_list,
               'extension_list' : ext_list }
    if self.mtype == 's_hand_and_app_secret':
      resp = { 'secret_list' : secret_list,
               'extension_list' : ext_list }
    if self.mtype == 's_init_cert_verify':
      resp = { 'secret_list' : secret_list,
               'extension_list' : ext_list }
    elif self.mtype == 's_new_ticket':
      resp = { 'secret_list' : secret_list, \
               'ticket_list' : key_scheduler.get_tickets( self.ticket_nbr ) }
  
  def secret_list( self, secret_candidates:list)-> list:
    """returns the sublist of secrets both authorized and requested.

     Usually useful to determine which secrets need to be computed """
    secret_list = []
    for secret in secret_candidates:
      if secret in self.key_request.authorized_secrets:
        secret_list.append( secret )
    return secret_list

class SigningReq(SigAlgo):

  def __init__(self, signing_req, conf, mtype):
    self.conf = conf
    print("::: name: %s"%signing_req[ 'sig_algo' ] )
    SigAlgo.__init__( self, signing_req[ 'sig_algo' ] )
#    self.sig_algo = SigAlgo( signing_req[ 'sig_algo' ]
    if self.name not in conf.msg( 's_init_cert_verify' )[ 'sig_algo' ]:
      raise LURKError( ( self.name, conf.msg( 's_init_cert_verify' )[ 'sig_algo' ] ),  'unsupported signature algorithm',\
              'invalid_signature_scheme' )

class TlsHandshake:

  def __init__( self, conf=None ) -> None:
    self.conf = conf
    ## list of structures representing the TLS handshake messages
    self.msg_list = []
    ## lists the index associated to each message type. One message type
    ## may have multiple indexes
    ## ex: { 'client_hello' : [0], ..., 'certificate' [4,7], ...}
    self.msg_index = {}
  
  ## ToDO: we should probably add a sanity check function that ensures
  ## self.struct has an appropriated sequence. 

  def update_msg_type_index( self ) -> None:
    """ build correspondence between msg_type and msg_list index """ 
    for index in range( len( self.msg_list ) ):
      ## print("::: msg_list: %s"%self.msg_list )
      ## print("::: msg_list[ index ]: %s"%self.msg_list[ index ] )
      msg_type = self.msg_list[ index ][ 'msg_type' ]
      ## print("::: msg_type: %s"%msg_type )
      try:
        self.msg_index[ msg_type ].append( index )
      except KeyError:
        self.msg_index[ msg_type ] = [ index ]

  def msg_i( self, msg_type:str) -> list:
    """ returns the indexes associated to msg_type"""
    try: 
      indexes = self.msg_index[ msg_type ]
    except KeyError:
      indexes = None
    return indexes

  def msg( self, msg_type:str, ith:int=0 ) -> dict:
    """ returns the data of the ith message of type msg_type """
    try:
      msg = self.msg_list[self.msg_i( msg_type)[ ith ] ][ 'data' ]
    except KeyError:
      msg = None
    return msg

  def later_of( self, msg_type_list:list, mode='server' ) -> (str, int):
     """returns the msg_type and position """
     ## check hard_stop is present
     print("::: later_of : msg_type_list: %s"%msg_type_list )
     try:
       if mode == 'server':
         ith = 0
       elif mode == 'client':
         ith = 1
       else:
         raise LURKError( mode, "unknown", 'implementation_error' )
       upper_i = server_finised_i = self.msg_index[ 'finished' ][ ith ]
     except ( IndexError, KeyError ):
       upper_i = len( self.msg_list ) ## assuming mode Finished message 
                                    ## is not present
     try:
       if mode == 'server':
         lower_i = self.msg_index[ 'encrypted_extensions' ][0]
       elif mode == 'client':
         lower_i = self.msg_index[ 'finished' ][0]
     except KeyError:
       raise LURKError( ( mode, self.msg_index), " 'encrypted_extensions' " +\
              "or server 'finished' not found ", 'implementation_error' )
     msg_type_list.reverse()
     print("::: later_of : msg_type_list: %s"%msg_type_list )
     for msg_type in msg_type_list:
       print("::: later_of : msg_type (reverse): %s"%msg_type )
       try:
         msg_type_i = self.msg_index[ msg_type ][ ith ]
       except KeyError:
         continue
       if lower_i <= msg_type_i <= upper_i:
         break
       else:
         continue
     msg_type = self.msg_list[ msg_type_i ][ 'msg_type' ]
     pos = self.msg_i( msg_type ).index( msg_type_i )
     print("::: later_of : msg_type: %s"%msg_type )
     print("::: later_of : pos: %s"%pos )
     return msg_type, pos



  def insert( self, msg_sub_list:list, after=None):
    """ add additional context to TlsHandshakeCtx """
    if after == None:
##      self.msg_list.append( msg_sub_list )
##      self.msg_list.insert( 0, msg_sub_list )
      index = 0
    else:
      msg_type = after[ 0 ]
      ith = after[ 1 ] 
      index = self.msg_index[ msg_type ][ ith ] + 1
    for i in range( len( msg_sub_list ) ):
      self.msg_list.insert( index + i , msg_sub_list[ i ] )
    self.update_msg_type_index()
 
  def bytes_messages( self, msg_type:str, ith: int=0 ) -> bytes:
    """ returns the concatenation of the handshale messages """
    ## messages = self.bytes_messages(msg_type='client_hello', ith=0)
    ## As an exception to this general rule, when the server responds to a
    ## ClientHello with a HelloRetryRequest, the value of ClientHello1 is
    ## replaced with a special synthetic handshake message of handshake type
    ## "message_hash" containing Hash(ClientHello1).  I.e.,

    ## Transcript-Hash(ClientHello1, HelloRetryRequest, ... Mn) =
    ## Hash(message_hash ||        /* Handshake type */
    ## 00 00 Hash.length  ||  /* Handshake message length (bytes) */
    ##  Hash(ClientHello1) ||  /* Hash of ClientHello1 */
    ##  HelloRetryRequest  || ... || Mn)
    print("::: msg_type: %s"%msg_type )
    print("::: ith: %s"%ith )
    print("::: self.msg_i( msg_type ): %s"%self.msg_i( msg_type ) )
    msgs = bytearray()
    ctx_struct = { '_certificate_type': self.conf.cert_type }
    for i in range( self.msg_i( msg_type )[ ith ] ):  
      print("::: msg_list[%i]: %s"%( i, self.msg_list[i] ) )
      msgs.extend( Handshake.build( self.msg_list[i], **ctx_struct ) ) 
    return msgs

  def update_server_key_share( self, ephemeral:Ephemeral ) -> NoReturn:
    """ update key_exchange value of the serverHello  """
    exts = self.msg( 'server_hello', ith=0 )[ 'extensions' ] 
    key_share = get_struct( exts, 'extension_type', 'key_share' )
    key_share_index = exts.index( key_share )
    self.msg_list[1][ 'data' ][ 'extensions' ][ key_share_index ]\
      [ 'extension_data' ][ 'server_share' ][ 'key_exchange' ] = ephemeral.server_key_exchange  



  def update_server_certificate( self ):
    """ build the various certificates payloads 

     Ensure the Certificate message is generated in the handshake
     context. If the server Certificate message is not provided, it
     needs to be built. 
     Building the certificate payload requires the following information:
       * cert_type that can be X.509 or RawPublicKey
       * format can be 'full' (default) or 'finger_print'
      when finger_print is used, the handshake contains all necessary information
      to build the certificate payload and check there is a common understanding 
      between the TLS server, the TLS Client and the CS. 
      When 'full' (the default) is used, the indication of the appropriated key 
      needs to be specified ( unless a single key is used ).  
    """
    ## checking the Certtificate message is present
    cert_idx = self.msg_i('certificate')
    if cert_idx != None:
      if cert_idx[0] <= 5:
        return None
    ## cert message needs to be built types/format are defined in
    ## extensions 
    server_hello_exts = self.msg( 'server_hello' )['extensions']
    
    ## type is X.509 unless specified otherwise in server_certificate_type
    cert_type = 'X.509'
    try:
       ext = get_struct(server_hello_exts, 'extension_type', 'server_certificate_type')
       cert_type = ext['extension_data']['server_certificate_type']  
    except ( KeyError, TypeError ):
      pass

    ### define Certificate format (finger print versus full Certificate )
    ## format is full format unless finger_print is specified 
    finger_print = False
    try: 
      ext = get_struct( server_hello_exts, 'extension_type', 'cached_info' )
      for cache_info in ext:
        if ext['type'] == 'cert':
          finger_print = True
          if ext[ 'hash_value' ] != self.conf.cert_finger_print:
            raise LURKError( (self.conf.cert_finger_print, ext['hash_value'] ), 
                    'certificate mismatch', 'invalid_key_id')
    except ( KeyError, TypeError ):
      pass 

    ## generates the certificate message according to 
    ## cert_type and finger_print
    if finger_print == False:
      cert = self.conf.hs_cert_msg
    else:
      cert = { 'msg_type' : 'certificate', 
               'data' : self.conf.cert_finger_print }
    msg_type, ith = self.later_of( ['encrypted_extensions', 'certificate_request' ],\
                            mode='server' )
    self.insert( [ cert ], after=( msg_type, ith ) ) 

  def update_server_certificate_verify( self, sig_algo ) :
    string_64 = bytearray()
    for i in range(64):
      string_64.extend(b'\20')
    if self.conf.role() == 'server':
      ctx = b'server: TLS 1.3, server CertificateVerify'
    else:
      ctx = b'client: TLS 1.3, client CertificateVerify'
    if self.conf.role() == 'server':
      ith = 0
    else:
      ith = 1
    content = bytes( string_64 + ctx + b'\x00' + \
              self.ctx( 'server_certificate_verify' ) )

#    if sig_algo.name not in self.conf.msg('s_init_cert_verify')['sig_algo']:
#      raise LURKError( sig_algo, 'disabled by conf', \
#                       'invalid_signature_scheme')
    ## ed25519, ed448
    #sig_algo = SigAlgo( sig_algo )
    if sig_algo.algo in [ 'ed25519', 'ed448' ]:
      signature = self.conf.private_key.sign( content )
    ## ecdsa
    elif sig_algo.algo == 'ecdsa':
      signature = self.conf.private_key.sign( content, \
                    ECDSA( sig_algo.hash ) )
    ## rsa
    elif 'rsa' in sig_algo.algo:
      signature = self.conf.private_key.sign( content, sig_algo.pad, sig_algo.hash )
    else:
      raise LURKError( sig_algo.algo, 'unknown', \
                       'invalid_signature_scheme')

    cert_verify = { 'msg_type' : 'certificate_verify', 
                    'data' : { 'algorithm' : sig_algo.name,
                               'signature' : signature } }
    msg_type, ith = self.later_of( ['encrypted_extensions', 'certificate_request',\
                               'certificate' ], mode='server' )
    self.insert( [ cert_verify ], after=( msg_type, ith ) ) 
    
  def update_server_finished( self , scheduler):
    msg = self.ctx( 'server_finished' )
    ## base key server_handshake_traffic_secret 
    secret = scheduler.secrets[ 'h_s' ]
##\
##    self.sheduler.server_handshake_traffic_secret()
    verify_data = scheduler.tls_hash.verify_data(secret, msg )
##   verify_data =
##     HMAC(finished_key,
##           Transcript-Hash(Handshake Context,
##                               Certificate*, CertificateVerify*))
    server_finished = { 'msg_type' : 'finished', 
                        'data' : verify_data }
    msg_type, ith = self.later_of( ['encrypted_extensions', 'certificate_request',\
                               'certificate', 'certificate_verify' ],\
                               mode='server' )
    self.insert( [ server_finished ], after=( msg_type, ith ) )
   
  def ctx( self, ctx:str) -> bytes:
    """returns the bytes messages of ctx """
    print( "::: 1 - ctx: %s"%ctx )
    if ctx == 'early_secrets': 
      ## ClientHello or ClientHello1, HelloRetryRequest, ClientHello2
      msg_type = 'client_hello'
      ith = len ( self.msg_index[ 'client_hello' ] - 1 ) 

    elif ctx == 'handshake_secrets': 
      ## ClientHello...ServerHello
      msg_type = 'server_hello'
      ith = 0
    elif ctx == 'application_secrets' or ctx == 'exporter_secret' :
      ## ClientHello...server Finished
      msg_type = 'finished'
      ith = 0
    elif ctx == 'resumption_secret': 
      ## ClientHello...client Finished 
      msg_type = 'finished'
      ith = 1
      print("::: finished (msg_type, ith): %s, %s"%(msg_type, ith)) 
    elif ctx == 'server_certificate_verify':
      ## ClientHello ... later of EncryptedExtensions 
      ## CertificateRequest, Certificate
      ## checking Finished has/have been generated
      print( "::: 2 - ctx: %s"%ctx )
      msg_type, ith = self.later_of( \
                        [ 'encrypted_extensions', 'certificate_request',\
                          'certificate' ], mode='server' )
      print( "::: server_certificate_verify (msg_type, ith): %s, %s"%\
               ( msg_type, ith ) ) 
    elif ctx == 'client_certificate_verify':
      ## ClientHello ... later of server Finished EndOfEarlyData
      msg_type, ith = self.later_of( \
                        [ 'finished', 'end_of_early_data' ], mode='client' )
    elif ctx == 'server_finished':
      msg_type, ith = self.later_of( \
                        [ 'encrypted_extensions', 'certificate_request',\
                          'certificate', 'certificate_verify' ], mode='server' )
    elif ctx == 'client_finished':
      pass
    elif ctx == 'post_handshake':
      pass
    elif ctx == 'psk_binder':
    ## Truncate(ClientHello1)
    ##  ClientHello1, HelloRetryRequest, Truncate(ClientHello2)
      pass
    else:
      raise LURKError( ctx, "unknown context", 'implementation_error' )
    return self.bytes_messages( msg_type=msg_type, ith=ith ) 

class NewSessionTicket

  def __init__( self, conf ):
   self.ticket_lifetime = conf.msg('s_new_ticket')[ 'ticket_life_time' ]
   self.ticket_age_add = randbits( 32 ) 
   self.ticket_nonce = token_byte( conf.msg('s_new_ticket')[ 'ticket_nonce_len' ] )
   self.ticket = token_byte( conf.msg('s_new_ticket')[ 'ticket_nonce' ] )
   self.extensions = []
   
  def export( self ):
    return { 'ticket_lifetime' : self.ticket_lifetime, \
             'ticket_age_add' : self.ticket_age_add, \
             'ticket_nonce' : self.ticket_nonce, \
             'ticket' : self.ticket }



class KeyScheduler:

  def __init__( self, seed, ecdhe:bytes=None, psk:bytes=None): ## seed is TlsHanshake or KeyScheduler
    self.secrets = { 'b' : None, 'e_c' : None, 'e_x' : None,\
                    'h_c' : None, 'h_s' : None, 'a_c' : None,\
                    'a_s' : None, 'x' : None, 'r' : None }
    self.tickets = []
    self.server_cipher = None
    self.ecdhe = ecdhe
    self.psk = psk

    if isinstance(seed, TlsHandshake ) == True:
      try:
        self.server_cipher = handshake.msg( 'server_hello' )[ 'cipher_suite' ]
      except:
        raise LURKError( server_cipher, "unable to determine hash function",\
                         'invalid_handshake')
      if 'SHA256' in  server_cipher:
        self.tls_hash = TlsHash()
      elif 'SHA384' in server_cipher:
        self.tls_hash = TlsHash(hashmod=hashlib.sha384)
      else:
        raise LURKError( server_cipher, "unable to determine hash function",\
          'invalid_handshake')
      print("::: ecdhe: %s"%ecdhe)
      self.init_scheduler( ecdhe, psk )
    elif isinstance( seed, KeyScheduler):
      self.tls_hash = TlsHash( hashmod=seed.tls_hash.hashmod )
      self.psk = seed.compute_psk( psk_id )
      self.psk_wrapper = PSKWrapper( self.psk, self.tls_hash, is_ext = False )
      self.server_cipher = seed.server_cipher


  def init_scheduler( ecdhe=None, psk=None):
    if self.ecdhe is None:
      self.ecdhe = ecdhe
    if self.psk is None:
      self.psk = psk
      self.scheduler = self.tls_hash.scheduler( self.ecdhe, self.psk )

  def process( self, secret_list:list, handshake:TlsHandshake ) -> None: 
  
    if 'b' in secret_list:
      self.secrets[ 'b' ] = self.psk_wrapper.binder_key()
    if 'e_c' in secret_list or  'e_x' in secret_list:
      messages = handshake.ctx( 'early_secrets' )
      if 'e_c' in secret_list:
        self.secrets[ 'e_c' ] = \
          self.psk_wrapper.client_early_traffic_secret( messages )
      if 'e_x' in secret_list:
        self.secrets[ 'e_c' ] = \
          self.psk_wrapper.early_exporter_master_secret( messages )

    if 'h_c' in secret_list or  'h_c' in secret_list:
#      try: 
      ## 'ClientHello...ServerHello'  
      messages = handshake.ctx( 'server_certificate_verify' )
#      except: 
#        raise LURKError( self.handshake.msg_list, 'unable to find server_hello', \
#                                           'implementation_error')
      if 'h_c' in secret_list:
        self.secrets[ 'h_c' ] = \
          self.scheduler.client_handshake_traffic_secret( messages )
        self.secrets[ 'h_s' ] = \
          self.scheduler.server_handshake_traffic_secret( messages )
    if 'a_c' in secret_list or  'a_c' in secret_list or\
       'x' in secret_list:
##      try: 
        ## ClientHello...server Finished
      messages = handshake.ctx( 'server_finished' )
##     except: 
##        raise LURKError()
      if 'a_c' in secret_list: 
        self.secrets[ 'a_c' ] =\
          self.scheduler.client_application_traffic_secret_0( messages )
      if 'a_s' in secret_list: 
        self.secrets[ 'a_s' ] =\
          self.scheduler.server_application_traffic_secret_0( messages )
      if 'x' in secret_list: 
        self.secrets[ 'x' ] = self.scheduler.exporter_master_secret( messages )
    if 'r' in secret_list:
      messages = handshake.ctx( 'resumption_secret' )
      self.secrets[ 'r' ] = self.scheduler.resumption_master_secret( messages )

  def get_tickets( self, ticket_number) -> list :
    tickets = []
    for i in range( ticket_number ) :
      if len( self.tickets ) < self.conf.msg( 's_new_ticket' )['max_new_ticket_exchange']:
        new_ticket = NewSessionTicket( self.conf )
        self.tickets.append( new_ticket )
        tickets.append( new_ticket.export( ) )
      else:
        break
    return tickets

  def compute_psk( self, psk_id:PskID ) -> bytes: ## or None
    for ticket in self.tickets:
      if ticket.ticket == psk_id.identity:
        break
    return self.tls_hash.hkdf_expand_label(
            secret, b"resumption", ticket_nonce, self.tls_hash.hash_len )


class Session:

  def __init__( self, conf ): # type Conf
    self.conf = conf 
    self.scheduler = None
    self.handshake = TlsHandshake( conf )
    self.next_mtype = None
    self.id = None

  def serve( self, payload, mtype, status, session_db=None ):
    if status != 'request':
      raise LURKError( status, "expecting 'request' status", \
                       'invalid_request')
    if self.next_mtype == None:
      self.next_mtype = mtype
    if mtype != self.next_mtype:
      raise LURKError( mtype, "expecting %s mtype "%self.next_mtype, \
                       'invalid_request')
    if mtype == 's_init_early_secret':
      pass
    elif mtype == 's_init_cert_verify':
      secret_req = SecretReq( payload[ 'secret_request' ], self.conf, mtype )
      signing_req = SigningReq( payload[ 'signing_request' ], self.conf, mtype )
      ## initializing objects 
      print("::: hs_ctx: %s"% secret_req.hs_ctx)
      self.handshake.insert( secret_req.hs_ctx )
      shared_secret  = secret_req.ephemeral.ecdhe
      if secret_req.ephemeral.method == 'secret_generated':
        self.handshake.update_server_key_share( secret_req.ephemeral )
      self.scheduler = KeyScheduler( self.handshake, shared_secret )
      self.scheduler.process( secret_req.secret_list([ 'h_c', 'h_s' ] ), self.handshake )
      self.handshake.update_server_certificate()
      self.handshake.update_server_certificate_verify( signing_req )
      self.scheduler.process( secret_req.secret_list( [ 'a_c', 'a_s' ] ), self.handshake )
      self.handshake.update_server_finished( self.scheduler )
      self.scheduler.process( secret_req.secret_list( [ 'x' ] ), self.handshake )
      print("::: certificate_verify: %s"%self.handshake.msg( 'certificate_verify' ) ) 
      sig = self.handshake.msg( 'certificate_verify' )[ 'signature' ] 
      print("::: scheduler: %s"%self.scheduler ) 
      resp = { 'secret_response' : secret_req.serve( self.scheduler ), 
               'signing_response' : { 'signature' : sig } }
      self.id = secret_req.session_id
      if isinstance( self.id, SessionID ):
        self.next_mtype = 's_new_ticket'
      else:
        self.next_mtype = None
    elif mtype == 's_new_ticket':
      secret_req  = SecretReq( payload, self.conf, mtype )
      self.handshake.insert( secret_req.hs_ctx )
      self.scheduler.process( secret_req.secret_list( [ 'r' ] ), self.handshake )
      resp = secret_req.serve( self.scheduler )
      resp[ 'session_id' ] = self.id.outbound
      if len( self.scheduler.tickets) < self.conf.msg( 's_new_ticket' )[ 'max_new_ticket_exchange' ]:
        self.next_mtype = 's_new_ticket'
      else:
        self.next_mtype = None
    elif mtype == 's_init_early_secret':
      secret_req = SecretReq( payload[ 'secret_request' ], self.conf, mtype )
      self.handshake.insert( secret_req.hs_ctx )
      parent_session = session_db.search( secret_req.psk_id )
      psk = parent_session.compute_psk( secret_req.psk_id )
      ## TBD: check same Hash and same cipher_suite. 
      self.handshake.insert( secret_req.hs_ctx )
      self.scheduler = KeyScheduler( parent_session.scheduler, psk=psk)
      self.scheduler.process( secret_req.secret_list([ 'b', 'e_c', 'e_x' ] ), self.handshake )
      resp = { 'secret_response' : secret_req.serve( self.scheduler ) } 
      self.id = secret_req.session_id
      if isinstance( self.id, SessionID ):
        self.next_mtype = 's_hand_and_app_secret'
      else:
        self.next_mtype = None
      
      
    elif mtype == 's_hand_and_app_secret':
      secret_req = SecretReq( payload[ 'secret_request' ], self.conf, mtype )
      self.handshake.insert( secret_req.hs_ctx )
      if isinstance( secret_req.ephemeral, Ephemeral ) is True:
        shared_secret  = secret_req.ephemeral.ecdhe
        if secret_req.ephemeral.method == 'secret_generated':
          self.handshake.update_server_key_share( secret_req.ephemeral )
      else:
        shared_secret = None
      self.scheduler.init_scheduler( shared_secret, psk )
      shared_secret  = secret_req.ephemeral.ecdhe 
      self.scheduler.process( secret_req.secret_list([ 'h_c', 'h_s', 'a_c', 'a_s' ] ), self.handshake )
      self.handshake.update_server_finished( self.scheduler )
      self.scheduler.process( secret_req.secret_list( [ 'x' ] ), self.handshake )
      
    else: 
      raise LURKError( mtype, "expecting %s mtype "%self.next_mtype, \
                       'invalid_request')
    
    return resp



class SessionDB:

  def __init__(self, ):

    self.db = {}

  def store( self, session:Session):
    self.session_db[ session.id.inbound ] = session

  def unstore( self, session_id:bytes ):
    return self.db[ session_id ]

  def search_session(psk_id:PskID) -> Session :  
    for session in self.db.values():
      for ticket in session.tickets:
        if ticket.ticket == psk_id.identity:
          return session
    raise LURKError( psk_id, "unable to find ticket", 'invalid_psk') 

class LURKExt:
  def __init__(self, conf=default_conf):
    ## configuration
    ## session DB
    self.session_db = SessionDB()


    
  def get_ctx_struct(self, status, mtype):
    ctx_struct = { '_type': mtype, '_status' : status}
    if mtype == 's_hand_and_app_secret':
      ctx_struct['_session_id_agreed'] = self.conf[mtype][0]['session_id_enable']
    return ctx_struct

  def parse( self, status, mtype, pkt_bytes ):
    """ parse payload """
    ctx_struct = self.get_ctx_struct(status, mtype)
    try:
      return LURKTLS13Payload.parse(pkt_bytes, **ctx_struct )
    except Error as e:
      self.treat_exception(e)

  def build( self, status, mtype, **kwargs):
    ctx_struct = self.get_ctx_struct(status, mtype)
    try:
      return LURKTLS13Payload.parse.build( **kwargs, **ctx_struct)
    except Error as e:
      self.treat_exception(e)

  def serve( self, mtype, request  ):
    try:
      if mtype in [ 's_init_early_secret', 's_init_cert_verify' ]:
        session = Session( self.conf )
        response  = session.serve( request, mtype, 'request')
        if session.id != None :
          self.session_db.store( session ) 
        return response
      elif mtype == 's_hand_and_app_secret':
        return s_hand_and_app.serve(request)
      elif mtype == 's_new_ticket':
        try:
          session = self.session_db.unstore( request['session_id' ] )
          response  = session.serve( request, mtype, 'request')
        except KeyError:
          raise LURKError( request, "session_id not found in DB", 'invalid_session_id')

    except Error as e:
      self.treat_exception(e)

  def check( self, status, mtype, payload ):
      return self.ext_class[ ( status, mtype ) ].check( payload )

  def show( self, status, mtype, pkt_bytes, prefix="", le_len=LINE_LEN ):
      return self.ext_class[ ( status, mtype ) ].show( pkt_bytes, \
                 prefix=prefix, line_len=line_len )

  def build_payload( self, status, mtype, payload ):
      return self.ext_class[ ( status, mtype ) ].build_payload(**kwargs )

  def treat_exception(self, e):
    ##return status_code
    pass


