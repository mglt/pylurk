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
from struct_tls13 import PskIdentity, Certificate, SignatureScheme, Handshake
from key_schedule import TlsHash, PSKWrapper
from conf import default_conf, SigScheme, CipherSuite
from lurk_lurk import LURKError, ImplementationError, ConfigurationError

import pkg_resources
data_dir = pkg_resources.resource_filename(__name__, '../data/')


from pickle import dumps, loads


## TODO:
## 1. check that sig_algo is present in the signature_extension. code + draft


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

class Tag:

  def __init__( self, tag:dict, mtype, tls13_conf, ctx=None ):
    self.conf = tls13_conf
    self.mtype = mtype
    self.last_exchange = tag[ 'last_exchange' ]

    if self.mtype in [ 's_init_cert_verify', 's_hand_and_app_secret'  ]:
      self.last_exchange = self.conf[ 'last_exchange' ][ self.mtype ]
    elif self.mtype == 's_new_ticket':
      if ctx >= self.conf[ 'max_tickets' ]:
        self.last_exchange = True
    elif self.mtype in [ 'c_init_client_finished' ]:
      ## ctx is the handshake
      self.last_exchange = self.conf[ 'last_exchange' ][ self.mtype ]
      if ctx.is_post_hand_auth_proposed() == False:
        self.last_exchange = True
    elif self.mtype in [ 'c_post_hand_auth' ]:
      if ctx >= self.conf[ 'max_post_handshake_authentication' ]:
        self.last_exchange = True
    else:
      raise ImplementationError( f"unknown type {self.mtype}" )

#  def resp( self, ctx=None ):
    self.resp = { 'last_exchange' : self.last_exchange }


class Ephemeral:

  def __init__(self, ephemeral:dict, mtype, tls13_conf, handshake=None ) -> None:
    """ initializes the object based on the structure """

    self.conf = tls13_conf
    self.ephemeral = ephemeral
    self.mtype = mtype
    self.method = self.ephemeral['method']
    self.handshake = handshake
#    ks = self.handhake.msg_list[ 1 ][ 'data' ][ 'extensions' ][ 0 ] [ 'extension_data' ] [  'server_share' ] [ 'key_exchange'  ]
#    print( f"Ephemeral : ks : {ks} / {ephemeral}" )
    self.sanity_check( )
    ## the entry for the key scheduler
    if self.conf[ 'role' ] == 'server':
      ## key is the server_share value which is a key share entry
      self.shared_secret, self.resp = self.compute_server_share( )
      self.server_share = self.resp[ 'key' ]
      ## self.server_key_share TO BE REPLACED by self.key[ 'key_exchange' ]
    elif self.conf[ 'role' ] == 'client':
      self.client_shares, self.private_key_list, self.resp = self.compute_client_shares( ) 
    else:
      raise ImplementationError( f"unknown role {self.conf[ 'role' ]}" )

  def sanity_check( self ):
    """ check coherence of ephemeral with mtype and handshake """

    if self.method not in self.conf['ephemeral_method_list']:
      raise LURKError( 'invalid_ephemeral', f"method {self.method} expected to be"\
                       "in {self.conf['ephemeral_method_list']}" )
    if ( self.mtype == 's_init_cert_verify' and self.method == 'no_secret' ) or\
       ( self.mtype == 'c_client_finished' and self.method == 'cs_generated' ) :
      raise LURKError( 'invalid_ephemeral', f"Incompatible {self.method} and {mtype}" )
    elif ( self.mtype == 's_hand_and_app_secret' and self.method == 'no_secret' ):
      if self.handshake.is_ks_agreed() :
        raise LURKError( 'invalid_ephemeral', f"unexpected key_share extension with 'no_secret'" )

    elif self.mtype == 'c_init_client_finished':
      if self.method == 'cs_generated' :
        raise LURKError( 'invalid_ephemeral', f"Incompatible {self.method} and {mtype}" )
      if self.method == 'no_secret' and not ( self.handshake.is_psk_proposed() and self.handshake.is_psk_agreed() ) : 
        raise LURKError( 'invalid_ephemeral', f"no (EC)DHE provided ({self.method})"\
                f"but PSK (without (EC)DHE) authentication is not agreed" )
      if self.method == 'e_generated' and not self.handshake.is_ks_agreed() : 
        raise LURKError( 'invalid_ephemeral', f"(EC)DHE provided ({self.method})"\
                f"but PSK-ECDHE or ECDHE authentication is not agreed" )
 
  def get_key_share_client_shares( self ): 
    """ returns the client key_shares (a list of key share entry) 
     
    key_shares is located in the ClientHello
    """
    ch_index = self.handshake.latest_client_hello_index( )
    client_hello_exts = self.handshake.msg_list[ ch_index][ 'data' ][ 'extensions' ]
    client_key_share = get_struct(client_hello_exts, 'extension_type', 'key_share' )
    return  client_key_share[ 'extension_data' ][ 'client_shares' ]

  def get_key_share_server_share( self ):
    """ returns the key_share entry of the serverHello """
    ch_index = self.handshake.latest_client_hello_index( )
    server_hello_exts = self.handshake.msg_list[ ch_index + 1 ][ 'data' ][ 'extensions' ]
    server_key_share = get_struct(server_hello_exts, 'extension_type', 'key_share' )
    return server_key_share[ 'extension_data' ][ 'server_share' ]


  def get_publickey_from_key_share_entry( self, ks_entry ):
    """ returns the public key associated to a key share entry """
    group = ks_entry[ 'group' ]
    key_exchange = ks_entry[ 'key_exchange' ]
    if group not in self.conf[ 'authorized_ecdhe_group' ]:
      raise LURKError( 'invalid_ephemeral', f"unsupported {self.group}" )
    if group in [ 'secp256r1', 'secp384r1', 'secp521r1' ]:
      if self.group ==  'secp256r1':
        curve =  SECP256R1()
      elif group ==  'secp394r1':
        curve = SECP384R1()
      elif group ==  'secp521r1':
        curve = SECP521R1()
      public_key = EllipticCurvePublicNumbers( key_exchange[ 'x' ],\
                     key_exchange[ 'y' ], curve ) 
    elif group  in [ 'x25519', 'x448' ]:
      if group == 'x25519':
        public_key = X25519PublicKey.from_public_bytes( key_exchange ) 
      elif group == 'x448':
        public_key = X448PublicKey.from_public_bytes( key_exchange ) 
    else: 
      raise LURKError( 'invalid_ephemeral', f"unknown group {group}" ) 
    return public_key

  def proceed_empty_key_share_entry( self, empty_ks_entry ):
    """ processes an  empty key share entry 

    Returns:
      - private key 
      - key share entry
    """ 
    group = empty_ks_entry[ 'group' ]
    key_exchange = empty_ks_entry[ 'key_exchange' ]
    if group not in self.conf[ 'authorized_ecdhe_group' ]:
      raise LURKError( 'invalid_ephemeral', f"unsupported {self.group}" )
    if key_exchange not in [ b'', None]:
      raise LURKError( 'invalid_ephemeral', f"expecting empty key share entry { empty_ks_entry}" )  
    if group in [ 'secp256r1', 'secp384r1', 'secp521r1' ]:
      if group ==  'secp256r1':
        curve =  SECP256R1()
      elif group ==  'secp394r1':
        curve = SECP384R1()
      elif group ==  'secp521r1':
        curve = SECP521R1()
      private_key = ec.generate_private_key( curve, default_backend())
      public_key = private_key.public_key()
      public_numbers = public_key.public_numbers()
      key_exchange = { 'legacy_form' : 4,
                       'x' : public_numbers.x, 
                       'y' : public_numbers.y }    
    elif group  in [ 'x25519', 'x448' ]:
      if group == 'x25519':
        private_key = X25519PrivateKey.generate()
      elif group == 'x448':
        private_key = X448PrivateKey.generate()
      public_key = private_key.public_key() 
      key_exchange = public_key.public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw)
    ks_entry = { 'group' : group, 
                 'key_exchange' : key_exchange }
    return private_key, ks_entry

  def compute_client_shares( self ):
    """ computes client_shares, private_keys and resp """ 
    client_shares = self.get_key_share_client_shares( )
    new_client_shares = []
    private_key_list = []
    resp = [] 
    for ks in client_shares :
      if ks[ 'key_exchange' ] in [ None, b'' ]: 
        private_key, ks_entry = self.proceed_empty_key_share_entry( ks )
        resp.append( { 'method' : 'cs_generated', 
                            'key' : ks_entry } )
      else: 
        private_key = None
        ks_entry = ks
        resp.append( { 'method' : 'e_generated', 
                            'key' : b'' } )
      new_client_shares.append( ks_entry )
      private_key_list.append( private_key )
#    resp = []
#    for ks in client_shares:
#      resp.append( { 'method' : self.method, 'key' : ks } )
      return new_client_shares, private_key_list, resp

  def get_key_share_entry_list_from_handshake( self ):
    """ return the client key share entry selected by the server 

    Given a ServerHello message and a ClientHello message, 
    """
    server_ks = self.get_key_share_server_share( )
    client_shares = self.get_key_share_client_shares( ) 
    selected_group = server_ks[ 'group' ]
    client_ks = None
    for ks in client_shares:
      if ks[ 'group' ] == selected_group :
        client_ks = ks
        break
    return client_ks, server_ks

  def  compute_share_secret( self, private_key, public_key, group ):
    """ compute the ecdhe ecdhe share key
 
    Args:
      public_key, private_key are key objects
      group : TLS designation of the group
    """
    if group in [ 'secp256r1', 'secp384r1', 'secp521r1' ]:
      shared_secret = private_key.exchange( ECDH(), public_key )
    elif group  in [ 'x25519', 'x448' ]:
      shared_secret = private_key.exchange( public_key )
    else: 
      raise LURKError( 'invalid_ephemeral', f"Unexpected group {group}" )
    return shared_secret

  def compute_client_share_secret( self ):

    if self.method == 'e_generated':
      shared_secret = self.ephemeral[ 'key' ][ 'shared_secret' ]
    elif self.method == 'cs_generated':
#      server_ks = self.handshake.get_key_share_server_share( ) 
#      selected_group = server_ks[ 'group' ]
#      client_ks = None
#      for ks in self.client_shares:
#        if ks[ 'group' ] == selected_group :
#          client_ks = ks
#          break
#      client_private_key = self.private_key_list[ self.client_shares.index( client_ks ) ]
#      if client_private_key is None:
#        raise LURKError( 'invalid_ephemeral', f"Unable to find corresponding\
#                          private key in {client_shares}" )
      client_ks, server_ks = self.get_key_share_entry_list_from_handshake( )
      client_private_key = self.private_key_list[ self.client_shares.index( client_ks ) ]
      if client_private_key is None:
        raise LURKError( 'invalid_ephemeral', f"Unable to find corresponding\
                          private key in {client_shares}" )
      server_public_key = get_publickey_from_key_share_entry( server_ks )
      share_secret = self.compute_share_secret( client_private_key, server_public_key, server_ks[ 'group' ] ) 
##      if selected_group in [ 'secp256r1', 'secp384r1', 'secp521r1' ]:
##        self.shared_secret = client_private_key.exchange( ECDH(), server_public_key )
##      elif selected_group  in [ 'x25519', 'x448' ]:
##        self.shared_secret = client_private_key.exchange( server_public_key )

    elif self.method == 'no_secret': 
      shared_secret = None
    else: 
      raise LURKError( 'invalid_ephemeral', f"Unexpected method {self.method}" )
    self.share_secret = share_secret


  def compute_server_share( self ):
    """ treat ephemeral extension and initializes self.ecdhe, self.server_key_exchange """ 
    if self.method == 'e_generated':
      shared_secret = self.ephemeral['key'][ 'shared_secret' ]
      resp = { 'method' : self.method,
               'key' : b'' }
    elif self.method == 'cs_generated':
#      server_ks = self.handshake.get_key_share_server_share( ) 
#      client_shares = self.handshake.get_key_share_client_shares( )
#      selected_group = server_ks[ 'group' ]
#      client_ks = None
#      for ks in client_shares:
#        if ks[ 'group' ] == selected_group :
#          client_ks = ks
#          break
#      client_ks = self.get_client_key_share_entry_from_server_share( )
      print( f"compute_server_share : 1 {self.ephemeral}" )
      print( f"{self.get_key_share_server_share()}" )

      client_ks, server_ks = self.get_key_share_entry_list_from_handshake( )
      print( f"compute_server_share : 2 {self.ephemeral}" )
      
      server_private_key, server_ks = self.proceed_empty_key_share_entry( server_ks )
#      client_ks = self.handshake.get_client_key_share_client_shares( )
      if client_ks is None:
        raise LURKError( 'invalid_ephemeral', f"Unable to find corresponding\
                key share entries in {client_shares} and {server_ks}" )
      client_public_key = self.get_publickey_from_key_share_entry( client_ks )

      shared_secret = self.compute_share_secret( server_private_key, client_public_key, server_ks[ 'group' ] ) 
##      if selected_group in [ 'secp256r1', 'secp384r1', 'secp521r1' ]:
##        self.shared_secret = server_private_key.exchange( ECDH(), client_public_key )
##      elif selected_group  in [ 'x25519', 'x448' ]:
##        self.shared_secret = server_private_key.exchange(client_public_key)
      resp = { 'method' : self.method,
               'key' : server_ks }
    
    elif self.method == 'no_secret': 
      shared_secret = None
      resp = { 'method' : self.method,
               'key' : b'' }
    else: 
      raise LURKError( 'invalid_ephemeral', f"Unexpected method {self.method}" )
    return shared_secret, resp
##  def compute_server_key_exchange( self ):
##    """ treat ephemeral extension and initializes self.ecdhe, self.server_key_exchange """ 
##    if self.method == 'shared_secret':
##      ## makes more sense if only one secret is sent, not a list
##      self.shared_secret = self.ephemeral['key'][ 'shared_secret' ]
##    if self.method == 'cs_generated':
##      ## key_shae is taken in the serverhello to make sure the extension
##      ## is in the same place. Note that inserting the extension
##      ## may require to update all length.
##      print( self.handshake.msg_type_list() )  
##      ch_index = self.handshake.latest_client_hello_index( )
##      server_hello_exts = self.handshake.msg_list[ ch_index +1 ][ 'data' ][ 'extensions' ]
##      server_key_share = get_struct(server_hello_exts, 'extension_type', 'key_share' )
##      self.group = server_key_share[ 'extension_data' ][ 'server_share' ][ 'group' ]
##      client_hello_exts = self.handshake.msg_list[ ch_index][ 'data' ][ 'extensions' ]
##      client_key_share = get_struct(client_hello_exts, 'extension_type', 'key_share' )
##      client_shares = client_key_share[ 'extension_data' ][ 'client_shares' ]
##      client_key_exchange = get_struct(client_shares, 'group', self.group)
##       
##      if self.group not in self.conf[ 'authorized_ecdhe_group' ]:
##        raise LURKError( 'invalid_ephemeral', f"unsupported {self.group}" )
##
##      client_public_key = client_key_exchange[ 'key_exchange' ]
##      if self.group in [ 'secp256r1', 'secp384r1', 'secp521r1' ]:
##        if self.group ==  'secp256r1':
##          curve =  SECP256R1()
##        elif self.group ==  'secp394r1':
##          curve = SECP384R1()
##        elif self.group ==  'secp521r1':
##          curve = SECP521R1()
##        server_private_key = ec.generate_private_key( curve, default_backend())
##        server_public_key = private_key.public_key()
##        server_public_numbers = server_public_key.public_numbers()
##        self.server_key_exchange = {'x' : server_public_numbers.x, 
##                                    'y' : server_public_numbers.y }    
##        client_public_key = EllipticCurvePublicNumbers( client_public_key[ 'x' ], 
##                              client_public_key[ 'y' ], curve) 
##        self.ecdhe = server_private_key.exchange( ECDH(), client_public_key())
##      elif self.group  in [ 'x25519', 'x448' ]:
##        if self.group == 'x25519':
##          server_private_key = X25519PrivateKey.generate()
##          client_public_key = X25519PublicKey.from_public_bytes(client_public_key) 
##        elif self.group == 'x448':
##          server_private_key = X448PrivateKey.generate()
##          client_public_key = X448PublicKey.from_public_bytes(client_public_key) 
##        server_public_key = server_private_key.public_key() 
##        self.server_key_exchange = server_public_key.public_bytes(
##          encoding=Encoding.Raw, format=PublicFormat.Raw)
##        self.shared_secret = server_private_key.exchange(client_public_key)

#  def resp( self):
#    if self.method == 'cs_generated' :
#      key = { 'group' : self.group, \
#              'key_exchange' : self.server_key_exchange }
#    elif self.method in [ 'no_secret', 'e_generated' ]: 
#      key = None
#    return { 'method' : self.method,
#             'key' : key } 
#    return resp

class SessionID:
  def __init__( self, session_id:bytes, tag=None ):
    if tag is None :
      self.cs = token_bytes( 4  )
      self.e = session_id
    else:
      if tag.last_exchange is False:
        self.cs = token_bytes( 4  )
        self.e = session_id
      else:
        self.cs = b''

  def is_in_session( self, mtype, status, session_id:bytes ):
    """ checks the session_id 

    Checks the value is aligned with the sessionID object of the session 
    """      
    
    if ( status == 'request' and 'init' in mtype and session_id == self.e ) or \
       ( status == 'request' and 'init' not in mtype and session_id == self.cs ) or \
       ( status != 'request' and 'init' in mtype and session_id == self.cs ) or \
       ( status != 'request' and 'init' not in mtype and session_id == self.e ) :
      return True
    raise LURKError( 'invalid_session_id', f"{mtype} - E ( {self.e} / CS {self.cs}" )


class Freshness:
  def __init__( self, freshness:str ):
      self.freshness_funct = freshness
  
  def update_random( self, role, random:bytes ):
    if role == 'server':
      ctx = "tls13 pfs srv"
    elif role == 'client':
     ctx = "tls13 pfs clt"
    if self.freshness_funct == 'sha256' :
      digest = Hash( SHA256() )
    elif self.freshness_funct == 'sha384' :
      digest = Hash( SHA384() )
    elif self.freshness_funct == 'sha512' :
      digest = Hash( SHA512() )
    else: 
      raise LURKError( 'invalid_freshness', f"{self.freshness_funct}" )
    digest.update( random )
    return digest.finalize()

class LurkCert:

  def __init__( self, lurk_cert:dict, mtype, tls13_conf, server, handshake=None ):
    """ Handles the treatment of LurkCert 
 
    Args:
      server (bool) indicates the nature of the certificate. 
        When 

    """
    self.conf = tls13_conf
    self.handshake = handshake
    self.cert_type = lurk_cert[ 'cert_type' ]
    self.uncompress_lurk_cert( lurk_cert )
    self.sanity_check( mtype, server ) 

  def uncompress_lurk_cert( self, lurk_cert ):
    """ decompress lurk_cert into a TLS 1.3 Certificate structure  """
    if self.cert_type == 'no_certificate' :
      self.certificate = None
    elif self.cert_type == 'uncompressed' :
      self.certificate = lurk_cert[ 'certificate' ]
    elif self.cert_type == 'compressed' :
      self.certificate = 'XXX'
    elif self.cert_type == 'finger_print' :
      finger_print_dict = self.conf[ '_finger_print_dict' ]
      cert_entry_list = []       
      finger_print_entry_list = lurk_cert[ 'certificate' ][ 'certificate_list' ]
      try: 
        for entry in finger_print_entry_list :
          cert_entry = { 'cert' : finger_print_dict[ entry[ 'finger_print' ] ], \
                         'extensions' : entry[ 'extensions' ][ : ] }
          cert_entry_list.append( cert_entry )
      except KeyError: 
        raise LURKError( 'invalid_certificate', f"unrecognized fingerprint "\
                         f"{finger_print_entry_list} {self.finger_print_dict}" )
      else:
        print( f"{self.conf[ 'role' ]}")
        if self.conf[ 'role' ] == 'server':
          cert_req_ctx = b''
        elif self.conf[ 'role' ] == 'client':
          cert_req_index = self.handshake.msg_type_list().index( 'certificate_request' )
          cert_req_ctx = self.handshake.msg_list[ cert_req_index ][ 'data' ][ 'certificate_request_context' ]
        else:
          raise ImplementationError( f"unknown role {self.conf[ 'role' ]}" )
        self.certificate = { 'certificate_request_context' : cert_req_ctx, \
                        'certificate_list' : cert_entry_list }
    else: 
      raise LURKError( 'invalid_certificate', "unknown cert_type {self.cert_type}" )
    if  self.certificate is not None:
      self.hs_cert_msg = { 'msg_type' : 'certificate', 
                           'data' : self.certificate }    
    else:
      self.hs_cert_msg = {}

  def sanity_check( self, mtype, server:bool ):
    if mtype == 's_new_ticket' :
      if self.cert_type == 'no_certificate' :
        if 'certificate_verify' in self.handshake.msg_type_list() :
          raise LURKError( 'invalid_certificate', f"Incompatible server " \
            f"cert_type {self.cert_type} with handshake. Unexpected "\
            f"CertificateVerify message - {self.handshake.msg_type_list()}" )
      else :
        if 'certificate_verify' not in self.handshake.msg_type_list() :
          raise LURKError( 'invalid_certificate', f"Incompatible server " \
            f"cert_type {self.cert_type} with handshake. Expected "\
            f"CertificateVerify message - {self.handshake.msg_type_list()}" )
    elif mtype == 'c_init_client_finished' :
      ## server certificate
      if server is True: 
        if self.cert_type == 'no_certificate' :
          if not self.handshake.is_psk_proposed()  or \
             not self.handshake.is_psk_agreed() :
            raise LURKError( 'invalid_certificate', f"Incompatible server " \
              f"cert_type {self.cert_type} with handshake. Expecting PSK "\
              f"authentication" )
        else:
          if not self.handshake.is_certificate_agree() :
            raise LURKError( 'invalid_certificate', f"Incompatible server " \
              f"cert_type {self.cert_type} with handshake. Expecting certificate "\
              f"authentication" )
      ## client certificate
      else :
        if  ( (self.cert_type != 'no_certificate' ) and self.handshake.is_certificate_request() ) is False:
          raise LURKError( 'invalid_certificate', f"Client certificate and " \
            f"CertificateRequest MUST either be together absent or present" )

          



class SecretReq:

  def __init__( self, secret_request:dict, mtype, tls13_conf, handshake=None ):
    print( f"SecretReq init start {secret_request}")

    self.conf = tls13_conf
    if mtype in [ 's_init_early_secret', 'c_init_client_hello' ]:
      mandatory = ['b']
      forbiden = [ 'h_c', 'h_s', 'a_c', 'a_s', 'x', 'r'] 
      optional = [ 'e_c', 'e_x' ]
    elif mtype in [ 's_init_cert_verify', 's_hand_and_app_secret', 'c_hand_and_app_secret']:
      mandatory = [ 'h_c', 'h_s']
      forbiden = [ 'b', 'e_c', 'e_x', 'r']
      optional = [ 'a_c', 'a_s', 'x' ]
    elif mtype in [ 's_new_ticket', 'c_register_ticket' ]:
      mandatory = []
      forbiden = [ 'b', 'e_c', 'e_x', 'h_c', 'h_s', 'a_c', 'a_s', 'x']
      optional = ['r'] 
    else:
      raise ImplementationError( f"unknown {mtype}" )
    
    self.authorized_secrets = mandatory
    ## building the list of requested secrets, that is
    ## those set to True in key_request 
    for key in secret_request.keys():
      if secret_request[ key ] == True and key not in forbiden :
        self.authorized_secrets.append( key )
    self.authorized_secrets = list( set( self.authorized_secrets ) )

    if mtype in [ 's_init_cert_verify', 'c_hand_and_app_secret' ] :
      if self.conf[ 'app_secret_authorized' ] == False :
        try:
          self.authorized_secrets.remove( 'a_c' )
          self.authorized_secrets.remove( 'a_s' )
        except KeyError:
          pass
      if self.conf[ 'exporter_secret_authorized' ] == False: 
        try:
          self.authorized_secrets.remove( 'x' )
        except KeyError:
          pass
    elif mtype == 's_new_ticket':
      if self.conf[ 'resumption_secret_authorized' ] == False: 
        try:
          self.authorized_secrets.remove( 'r' )
        except KeyError:
          pass
    elif mtype in [ 's_init_early_secret', 'c_init_early_secret' ]:
      if self.conf[ 'client_early_secret_authorized' ] ==  False:
        try:
          self.authorized_secrets.remove( 'e_c' )
        except KeyError:
          pass
      if self.conf[ 'early_exporter_secret_authorized' ] ==  False:
        try:
          self.authorized_secrets.remove( 'e_x' )
        except KeyError:
          pass

  def of( self, secret_candidates:list)-> list:
    """returns the sublist of secrets both authorized and requested.

     Usually useful to determine which secrets need to be computed """
    secret_list = []
    for secret in secret_candidates:
      if secret in self.authorized_secrets:
        secret_list.append( secret )
    return secret_list

  def resp( self, scheduler ):
    secret_list = []
    for secret_type in self.authorized_secrets:
      secret_list.append( \
        { 'secret_type' : secret_type, 
          'secret_data' : scheduler.secrets[ secret_type ] } ) 
    return secret_list 

class TlsHandshake:

  def __init__( self, role, tls13_conf=None ) -> None:
    self.role = role #tls13_conf[ 'role' ]  ## list of role
    ## mostly makes sense for the server side
    self.conf = tls13_conf
#    self.hs_cert_msg = \
#      { 'msg_type' : 'certificate',
#        'data' :  { 'certificate_request_context': b'',
#                    'certificate_list' : self.conf[ '_cert_entry_list' ] } }
#    self.cert_finger_print = self.conf[ '_cert_finger_print' ]
    if self.conf != None :
      self.finger_print_dict = self.conf[ '_finger_print_dict' ]
#    self.finger_print_entry_list =  self.conf[ '_finger_print_entry_list' ]
#    self.cert_entry_list = self.conf[ '_cert_entry_list' ]
#    self.cert_type =  self.conf[ '_cert_type' ]
      self.private_key = self.conf[ '_private_key' ]
    ## list of structures representing the TLS handshake messages
    self.msg_list = []
    self.cipher_suite = None 
    self.transcript = None
    ## define if a client certificate is requested / expected
    self.is_certificate_request_state = None
    ## define if a client has claimed supporting post handshake authentication 
    self.post_hand_auth_proposed = None
    ## transcript of the handshake
    ## to be re-used for the resumption secret and post handshake authentication
    ## transcript is expresssed in bytes. 
    self.transcript_r = None

#  def post_post_hand_auth( self ):
#    """ removes the CertificateRequest, Certificate and CErtificateVerify """
#    self.msg_list = self.msg_list[ :-3] 
#    self.update_msg_type_index()

  def msg_type_list( self ):
    """ returns the list of message types

    This is usefull to check a messgage is present in the handshake
    """
    return [ msg[ 'msg_type' ]for msg in self.msg_list ]  

  def latest_client_hello_index( self ):
    """ return the index of the latest client hello 

    The following cases are considered: 
      * [ clienthello]
      * [ clientHello, hello_retry_request]
      * [ clientHello, hello_retry_request, client_hello ]
      * [ client hello, server]
    """
    if self.msg_list[ 0 ][ 'msg_type' ] != 'client_hello' :
      raise LURKError( 'invalid_handshake', f"Expecting client hello"\
                       f" in first message {self.msg_list}" )
    if len( self.msg_list ) <= 2 :
      index = 0
    elif len( self.msg_list ) >= 3 :
      if self.msg_list[ 2 ][ 'msg_type' ] == 'client_hello':
        index = 2
      else:
        index = 0
    return index

  def client_hello_extension_list( self ):
    ch_index = self.latest_client_hello_index()
    ext_list = []
    for ext in self.msg_list[ ch_index ][ 'data' ][ 'extensions' ] :
      ext_list.append( ext[ 'extension_type' ] )
    return ext_list

  def server_hello_extension_list( self ):
    ## when self,msg_list starts with serverhello: s_hand_and_app
    if self.msg_list[ 0 ][ 'msg_type' ] == 'server_hello' : 
      sh_index = 0
    # when self.msg_list starts with client hello: s_init_cert_verify,   
    else:
      ch_index = self.latest_client_hello_index()
      if len( self.msg_list ) < ch_index + 1:
        raise ImplementationError( f"cannot find server hello {self.msg_list}" )
      sh_index = ch_index + 1
    ext_list = []
    for ext in self.msg_list[ sh_index ][ 'data' ][ 'extensions' ] :
      ext_list.append( ext[ 'extension_type' ] )
    return ext_list

  def is_psk_proposed( self )->bool :
    """ return True if self.msg_list has proposed PSK, False otherwise """
#    ch_index = self.latest_client_hello_index()
#    ext_list = []
#    for ext in self.msg_list[ ch_index ][ 'data' ][ 'extensions' ] :
#      ext_list.append( ext[ 'extension_type' ] )
    ext_list = self.client_hello_extension_list( )
    print( f"TlsHandshake : {ext_list}" )
    if 'pre_shared_key' in ext_list  and  'psk_key_exchange_modes' in ext_list :
      return True
    return False

  def is_psk_agreed( self ) -> bool :
    """ return True is PSK has been agreed, False otherwise """
#    ## when self,msg_list starts with serverhello: s_hand_and_app
#    if self.msg_list[ 0 ][ 'msg_type' ] == 'server_hello' : 
#      sh_index = 0
#    # when self.msg_list starts with client hello: s_init_cert_verify,   
#    else:
#      ch_index = self.latest_client_hello_index()
#      if len( self.msg_list ) < ch_index + 1:
#        raise ImplementationError( f"cannot find server hello {self.msg_list}" )
#      sh_index = ch_index + 1
#    ext_list = []
#    for ext in self.msg_list[ sh_index ][ 'data' ][ 'extensions' ] :
#      ext_list.append( ext[ 'extension_type' ] )
#    if 'pre_shared_key' in ext_list :
    if 'pre_shared_key' in self.server_hello_extension_list( ) :
      psk_agree = True
    else: 
      psk_agree = False
    return psk_agree
    
  def is_ks_proposed( self )->bool :
    """ return True if a key share extension is in the client_hello """
    if 'key_share' in self.client_hello_extension_list( ) :
      return True
    return False

  def is_ks_agreed( self ) -> bool :
    """ return True if a key_share extension is in the server hello """   
    if 'key_share' in self.server_hello_extension_list( )  :
      return True
    return False
   
  def is_certificate_request( self ):
    """ returns True is the handshake contains a CertificateRequest message 

    The checks performed by the TLS client or the TLS server are a bit different 
    as the tLS client also checks the presence of the CertificateVerify. 
    """
    if self.is_certificate_request_state is None:
      if 'certificate_request' in self.msg_type_list( ):
        self.is_certificate_request_state = True
      else: 
        self.is_certificate_request_state = False
    if self.role == 'client' and self.is_certificate_request_state is True:
      if 'certificate_verify' in self.msg_type_list( ):
        self.is_certificate_request_state = True
      else:
        self.is_certificate_request_state = False
    return self.is_certificate_request_state

  def is_certificate_agreed( self ):
    """ return True if the handshake is acceptable for a certificate authentication  """
    if self.is_ks_agreed( ) is True :
      if 'signature_algorithms' in self.client_hello_extension_list( ):
        return True
    return False

  def is_early_data_proposed( self ):
    """ returns True is the TLS client enable early_data """
    ch_index = self.latest_client_hello_index()
    ext_list = []
    for ext in self.msg_list[ ch_index ][ 'data' ][ 'extensions' ] :
      ext_list.append( ext[ 'extension_type' ] )
    if 'early_data' in ext_list :
      return True
    return False
    
  def is_post_hand_auth_proposed( self ):
    """ returns True if the TLS client supports post handshake authentication """
    if self.post_hand_auth_proposed is  None:
      if 'post_handshake_auth' in self.client_hello_extension_list( ):
        self.post_hand_auth_proposed = True
      else:
        self.post_hand_auth_proposed = False
    return self.post_hand_auth_proposed

  def sanity_check( self, mtype, session_ticket=None ):
    """ checks if the handshake is compatible with the lurk exchange """
    error_txt = ""
    if mtype == 's_init_cert_verify':
      ## determine is a client Certificate 
      ## is expected in the s_new_ticket 
      self.is_certificate_request( ) 
      if self.is_psk_agreed() == True or self.is_ks_proposed == False or\
         self.is_ks_agreed == False:
        raise LURKError('invalid_handshake', f"expecting ks_agreed and non psk_aghreed {self.msg_list}" ) 
    elif mtype == 's_new_ticket' :
      if self.is_certificate_agreed != self.is_certificate_request( ) is False :
        raise LURKError('invalid_handshake', f"incompatible client "\
                        f"Certificate / CertificateRequest" ) 
      if self.resumption_master_secret == None and self.msg_list == []:
        raise LURKError('invalid_handshake', f"expecting non empty handshake" )
    elif mtype == 's_init_early_secret':
      if self.is_psk_proposed() == False :
        raise LURKError('invalid_handshake', f"expecting psk_proposed {self.msg_list}" ) 
    elif mtype == 's_hand_and_app_secret':
      if self.is_psk_agreed() == False :
        raise LURKError('invalid_handshake', f"expecting psk_agreed {self.msg_list}" ) 
      ## checking the selected ticket indicated in the server hello is 
      ## the one selected by the engine (LURK client) in the previous exchange.  
      ## In the s_init_early_secrets, the engine indicates the ticket to be 
      ## considered. 
      ## That ticket has been used to initialize the handshake with the 
      ## cipher and the tls_hash. 
      ## Here we are checking the server hello actually reflect these choices.
      ## we also check the tickets ciphersuite match the one of te server hello.
      ## Note that the client hello is not available at that stage.
      server_hello_exts = self.msg_list[ 0 ][ 'data' ][ 'extensions' ] 
      sh_selected_identity = get_struct( server_hello_exts, 'extension_type',\
                             'pre_shared_key' )[ 'extension_data' ]
      if sh_selected_identity != session_ticket.selected_identity :
        raise LURKError( 'invalid_handshake', f"server hello not selecting "\
                f" currenlty used ticket: server hello {sh_selected_identity} "\
                f" expecting value: {session_ticket.selected_identity}" )
      self.cipher_suite = self.msg_list[ 0 ][ 'data' ][ 'cipher_suite' ]
      
      if type( CipherSuite( self.cipher_suite ).get_hash() ) != type( session_ticket.tls_hash ) :
        raise LURKError( 'invalid_handshake', f"TLS handshake cipher "\
                f"suite {self.get_cipher( )} and ticket cipher suites "\
                f"are not compatible {session_ticket.cipher}" )
    elif mtype == 'c_init_client_finished':
      if self.is_certificate_request is False and self.is_post_hand_auth_proposed() is False : 
        raise LURKError( 'invalid_handshake', "Expecting server certificate authentication" )
    elif mtype in [ 'c_init_post_hand_auth', 'c_post_hand_auth' ]:
      if self.is_post_hand_auth_proposed() == False:
        raise LURKError( 'invalid_handshake', "Post handshake authentication no enabled" )
    elif mtype == 'c_init_client_hello':
      if self.is_psk_proposed() == False and self.is_ks_proposed() == False:
        raise LURKError( 'invalid_handshake', "psk_proposed or ks_proposed expected." )
    elif mtype == 'c_init_ephemeral':
      if self.has_ext( 'psk', 'proposed' ) == True:
        error_txt = "psk proposed"
      if self.has_ext( 'key_share', 'proposed' ) == False:
        error_txt = "key_share not proposed"
    elif mtype == 'c_init_early_secret':
      if self.has_ext( 'psk', 'proposed' ) == False:
        error_txt = "psk not proposed"
    elif mtype == 'c_hand_and_app_secret':
      if self.has_ext( 'psk', 'proposed' ) == True: #c_init_early_secret
        pass     
      else: ## 'c_init_ephemeral
        pass ## no additional 
    else:
      raise ImplementationError( "unknown mtype {mtype}" )
    if error_txt != "":
      raise LURKError( 'invalid_handshake', f"{error_txt} for "\
              f"{self.msg( 'client_hello' )} and {self.msg( 'server_hello' )}" )


  def update_random(self, freshness):
    """ reads the engine nonce and computes the server_hello.random or client_hello.random 

    """
    if self.role == 'server' : ## updating server_hello
      if self.msg_list[0][ 'msg_type' ] == 'client_hello':
        ch_index = self.latest_client_hello_index( )
        sh_index = ch_index + 1
      elif  self.msg_list[0][ 'msg_type' ] == 'server_hello' :
        sh_index = 0
      else:
        raise ImplementationError( f"Expecting handshake starting with" \
                f"client_hello or server_hello {self.msg_list}" )
      engine_random = self.msg_list[ sh_index ] [ 'data' ][ 'random' ]
      server_random = freshness.update_random( self.role, engine_random )
      self.msg_list[ sh_index ] [ 'data' ][ 'random' ] = server_random
    elif self.role == 'client':
      ch_index = self.latest_client_hello_index( )
      ch_index_list = [ 0 ]
      if ch_index != 0: ## presence of an hello retry
        ch_index_list.append( ch_index )
      engine_random = self.msg_list[ 0 ] [ 'data' ][ 'random' ]
      client_random = freshness.update_random( self.role, engine_random )
      for ch_index in ch_index_list :
        self.msg_list[ ch_index ] [ 'data' ][ 'random' ] = client_random
    else:
        raise ImplementationError( f"unknown role {self.role}" )

##  def update_key_share( self, server_key_exchange ) -> NoReturn:
  def update_key_share( self, key_share_entry ) -> NoReturn:
    """ update key_exchange value of the CLientHello or ServerHello 

    On the server side, the key_share is the server key_share entry. 
    On the client side, the key_share is a list of key_share entries (client_shares)
    """
    print( f" update_key_share : {key_share_entry}" )
    if self.role == 'server':
      # update occurs in the server_hello
      if self.msg_list[ 0 ][ 'msg_type' ] == 'client_hello' :
        ch_index = self.latest_client_hello_index( )
        index = ch_index + 1
      elif self.msg_list[ 0 ][ ' msg_type' ] == 'server_hello' :
        index = 0
      ks_designation = 'server_share'
    elif self.role == 'client':
      # update the 'client_hello'
      index = self.latest_client_hello_index( )
      ks_designation = 'client_shares'
    else:
      raise ImplementationError( f"unknown role {self.role}" )

    exts = self.msg_list[ index][ 'data' ][ 'extensions' ] 
    key_share = get_struct( exts, 'extension_type', 'key_share' )
    key_share_index = exts.index( key_share )
    
#    self.msg_list[ index ][ 'data' ]\
#      [ 'extensions' ][ key_share_index ][ 'extension_data' ]\
#      [ 'server_share' ][ 'key_exchange' ] = server_key_exchange  
    self.msg_list[ index ][ 'data' ]\
      [ 'extensions' ][ key_share_index ][ 'extension_data' ]\
      [ ks_designation ] = key_share_entry  
#    print( f" update_key_share : {self.msg_list[ 1] }" )

  def update_certificate( self, lurk_cert, server=True ):
    """ build the various certificates payloads 
   
    The resulting Certificate message is then inserted in the payload. 
    The case considered are: the server and client Certificates on both 
    the TLS server and the TLS client. 
    
    Args:
      lurk_cert (obj) : the LurkCert object
      server (bool) indicates if the lurk_cert is a server (True) 
        or a client (False) certificate. 
    """
    print( f" role : {self.role} - server : {server}" ) 
    if self.role == 'server' and server == True or\
       ( self.role == 'client' and server is False ):
      self.msg_list.append( lurk_cert.hs_cert_msg )
    else: #self.role == 'client' and server is True :
      ## inserting the server Certificate
      msg_type_list = self.msg_type_list()
      if 'certificate_verify' not in msg_type_list :
        raise LURKError( 'invalid_handshake', f"CertificateVErify message "\
                                              f"not foun in {msg_type_list}" )
      self.msg_list.insert( msg_type_list.index( 'certificate_verify' ), \
                            lurk_cert.hs_cert_msg ) 

  def update_certificate_verify( self ) :
    """ update the handshake with the CertificateVerify """
    sig_scheme = SigScheme( self.conf[ 'sig_scheme' ][ 0 ] )
    string_64 = bytearray()
    for i in range(64):
      string_64.extend(b'\20')
    if self.role == 'server':
      ctx_string = b'server: TLS 1.3, server CertificateVerify'
      transcript_h = self.transcript_hash( 'sig' )
    elif self.role == 'client':
      ctx_string = b'client: TLS 1.3, client CertificateVerify'
      if self.transcript_r is None:
        transcript_h = self.transcript_hash( 'sig' )
      else: 
        transcript_h = self.transcript_hash( 'post_hand_auth_sig' )
    else:
        raise ImplementationError( f"unknown role {self.role}" )
    content = bytes( string_64 + ctx_string + b'\x00' + transcript_h )

    print( f"{type( self.private_key )}" )
    if sig_scheme.algo in [ 'ed25519', 'ed448' ]:
      signature = self.private_key.sign( content )
    ## ecdsa
    elif sig_scheme.algo == 'ecdsa':
      signature = self.private_key.sign( content, \
                    ECDSA( sig_scheme.hash ) )
    ## rsa
    elif 'rsa' in sig_scheme.algo:
      signature = self.private_key.sign( content, sig_scheme.pad, sig_scheme.hash )
    else:
      raise LURKError( 'invalid_signature_scheme', f"unknown {sig_scheme.algo}" )

    self.msg_list.append( { 'msg_type' : 'certificate_verify', 
                            'data' : { 'algorithm' : sig_scheme.name,
                                       'signature' : signature } } )
    
  def update_server_finished( self , scheduler):
    secret = scheduler.secrets[ 'h_s' ]
    verify_data = scheduler.tls_hash.verify_data( secret, self.transcript_hash( 'finished' ) )
    self.msg_list.append( { 'msg_type' : 'finished',
                            'data' : { 'verify_data' : verify_data } } )

  def get_cipher_suite( self ):
    if self.cipher_suite is None:
      ch_index = self.latest_client_hello_index( )
      self.cipher_suite = self.msg_list[ ch_index + 1 ][ 'data' ][ 'cipher_suite' ]
    return self.cipher_suite

  def get_tls_hash( self ):
    """ returns the instance of the hash function used in the TLS exchange 

    """
    return CipherSuite( self.get_cipher_suite() ).get_hash() 
       
  def append_transcript( self, upper_msg_index:int=None  ):
    """ provides a copy of the running transcript

    This transcript contains all or up to msg_index (excluded) 
    """
    ## for server we can read it from the configuration file.
    ## this does not considers the case of the client in which 
    ## case we will have to read it from the handshake
    ## problem may arise when different format are used between 
    ## the client and the server. 
#    ctx_struct = { '_certificate_type': self.cert_type }
    ctx_struct = { }
    ## finished message needs the _cipher to be specified
    if 'server_hello' in self.msg_type_list() :
      ctx_struct[ '_cipher' ] = self.get_cipher_suite()

    if upper_msg_index is None:
      msg_list = self.msg_list[ : ]
      del self.msg_list[ : ]
    else:
      msg_list = self.msg_list[ : upper_msg_index ]
      del self.msg_list[ : upper_msg_index ]
    print( f"{[ m[ 'msg_type' ] for m in msg_list ]}" )
    msg_bytes = bytearray()
    for msg in msg_list : 
      print( f"--- {msg}" )
      msg_bytes.extend( Handshake.build( msg, **ctx_struct ) )
      print( "--- construct: ok" )
    self.transcript.update( msg_bytes )
    transcript = self.transcript.copy()
    return transcript.finalize()

  def post_hand_auth_transcript( self ):
    """ post handshake authentication transcript is derived from the transcript 
        of the full handshake.
        This is a bit different from append transcript where messages are appened to
        a given transcript.
    """
    if self.transcript_r is None:
      raise ImplementationError( f"handshake transcript for the handshake"\
                                 f"has not been finalized - expected to be "\
                                 f"finalized for post hand authentication" )

#    transcript = self.transcript_r.copy() 
    transcript = self.transcript.copy() 
#    ctx_struct = { }
#    msg_list = self.msg_list[ : ]
    msg_bytes = bytearray()
    for msg in self.msg_list :  
      msg_bytes.extend( Handshake.build( msg ) ) 
#      msg_bytes.extend( Handshake.build( msg, **ctx_struct ) ) 
    transcript.update( msg_bytes )
    del self.msg_list[ : ]
    return transcript.finalize()
    
 
  def transcript_hash( self, transcript_type ) -> bytes:
    """ return the Transcript-Hash output for the key schedule 

    Performing the hash in the handshake class prevent the 
    handshake class to keep all exchanges.       
    """
    print( f"begining transcript_hash: {transcript_type} - {self.msg_type_list( )}")
    if self.transcript == None:
      self.transcript = Hash( self.get_tls_hash() )
    print( "self.transcript initialized" )     
    upper_msg_index = None 

    if transcript_type == 'h' : 
      if self.msg_list[ 0 ][ 'msg_type' ] == 'client_hello':
        upper_msg_index = self.latest_client_hello_index( ) + 2
      elif self.msg_list[ 0 ][ 'msg_type' ] == 'server_hello':
        upper_msg_index = 1
      if self.msg_type_list( )[ : upper_msg_index ] not in [ \
        ## 's_init_cert_verify'
        [ 'client_hello', 'server_hello' ], \
        [ 'client_hello', 'server_hello', 'client_hello', 'server_hello' ], 
        ## 's_hand_and_app_secret'
        [ 'server_hello' ], 
        ]:
        raise LURKError( 'invalid_handshake', f"unexpected handshake {self.msg_list}" )
    ## ClientHello with a HelloRetryRequest, the value of ClientHello1 is
    ## replaced with a special synthetic handshake message of handshake type
    ## "message_hash" containing Hash(ClientHello1).  I.e.,

    ## Transcript-Hash(ClientHello1, HelloRetryRequest, ... Mn) =
    ## Hash(message_hash ||        /* Handshake type */
    ## 00 00 Hash.length  ||  /* Handshake message length (bytes) */
    elif transcript_type == 'sig' :
      if self.msg_type_list( ) not in [ \
        ## 's_init_cert_verify'
        [ 'encrypted_extensions', 'certificate' ],\
        [ 'encrypted_extensions', 'certificate_request', 'certificate' ], \
        ## c_init_client_finished  
        [ 'encrypted_extensions', 'certificate_request', 'certificate', \
          'certificate_verify',  'finished', 'certificate' ] ]:
        raise LURKError( 'invalid_handshake', f"unexpected handshake {self.msg_type_list()}" )
    elif transcript_type == 'finished' :
      if self.msg_type_list( ) not in [ \
        ## 's_init_cert_verify', c_init_client_finished
        [ 'certificate_verify' ], \
        ## 's_hand_and_app_secret'
        [ 'encrypted_extensions' ], \
        [ 'encrypted_extensions', 'certificate_request' ] ] :
        raise ImplementationError( f"unexpected handshake {self.msg_type_list()}" )
    elif transcript_type == 'a' :
      if self.msg_type_list( ) not in [ \
        ## 's_init_cert_verify' 
        ## 's_hand_and_app_secret'
        [ 'finished' ], \
        ]:
        raise LURKError( 'invalid_handshake', f"unexpected handshake {self.msg_type_list()}" )
    elif transcript_type == 'r' : 
      if self.msg_type_list( ) not in [ \
        ## 's_new_ticket 
        [ 'finished' ], \
        [ 'certificate', 'certificate_verify', 'finished' ], \
        []] : ## when mutliple s_new_ticket are sent
        raise LURKError( 'invalid_handshake', f"unexpected handshake {self.msg_type_list()}" )
    elif transcript_type == 'e' :
      print( self.msg_type_list( ))
      if self.msg_type_list( ) not in [ \
        ## 's_init_early_secret'
        [ 'client_hello' ], \
        [ 'client_hello', 'server_hello', 'client_hello' ] ] :
        raise LURKError( 'invalid_handshake', f"unexpected handshake {self.msg_type_list()}" )
##    elif transcript_type == 'post_hand_auth' :
    elif transcript_type == 'post_hand_auth_sig' : 
      if self.msg_type_list( ) not in [ \
        ## c_post_hand_auth
        [ 'certificate_request', 'certificate'] ] :
        raise LURKError( 'invalid_handshake', f"unexpected handshake {self.msg_type_list()}" )
    else: 
          raise ImplementationError( f"Unexpected {transcript_type}" )
    ## 'r' may be asked multiple times
    ## in principle, E is expected to send an empty handshake, so that will just work.
    ## However, to support the case when E re-send the handshake messages.
    ## r should be stored and returned instead of being recomputed. 
    if transcript_type == 'r' and self.transcript_r != None:
#     self.transcript_r = self.transcript_r.copy()
#     self.transcript_r.finalize()
     transcript = self.transcript_r
#      transcript = self.transcript_r.copy()
#      transcript = transcript.finalize()
    elif transcript_type == 'post_hand_auth_sig' :
      transcript = self.post_hand_auth_transcript( )
#      transcript = transcript.finalize( )
    else :
      transcript = self.append_transcript( upper_msg_index )
      if transcript_type == 'r' :
        self.transcript_r = transcript
    return transcript 
#    return self.append_transcript( upper_msg_index )

  def get_ticket( self, selected_identity:int=None ):
    try:
      ch_index = self.latest_client_hello_index( ) 
      client_hello_exts = self.msg_list[ ch_index ][ 'data' ][ 'extensions' ]
      pre_shared_key = get_struct(client_hello_exts, 'extension_type', 'pre_shared_key' )
      identities = pre_shared_key[ 'extension_data' ][ 'identities' ]
   
      if selected_identity == None:
        return identities
      else:
        return identities[ selected_identity ]
    except:
      raise LURKError('invalid_handshake', f"unable to get psk_identity from {identities}" )



  def hs_client_hello_to_partial( self, binder_len ) -> bytes:
    """ generates the partial client hello 

    binder_len indicates the len as indicated in the length prefix
    
    """
    ch_index = self.latest_client_hello_index( ) 
    psk_ext = self.msg_list[ ch_index ][ -1 ] 
    ## binders is generated as a PskBinderEntry to ease the contrsuction
    binders = PskBinderEntry( binders_len - 1 )
    self.msg_list[ ch_index ][ -1 ][ 'extension_data' ][ 'binders' ] 
#    if 'extension_type' = 'pre_shared_key': 
#    client_hello_exts = self.msg( 'client_hello' )[ 'extensions' ]
#    pre_shared_key = get_struct( client_hello_exts, 'extension_type', 'pre_shared_key' )
#    binders = pre_shared_key[ 'extension_data' ][ 'binders' ]
#    l = 0
#    for binder in binders:
#      l += len( binder )
#    return HSClientHello.build( self.msg( 'client_hello' ) )[: -l ] 
    
    
  def hs_partial_to_client_hello ( self, bytes_client_hello ):
    """ makes HS partial ClientHello parsable. 

   fills the binders with zero bytes. The length is derived from 
   the difference between the received bytes and the indicated length.
   """
    ##session_ticket = SessionTicket( conf, psk_identity=psk_id ) )
    binders = bytearray( len( bytes_client_hello ) - int.from_bytes( bytes_client_hello[1:4] ) )## bytes 2, 3 and 4
    return Handshake.parse( bytes_client_hello + binders ) 
    
  def update_binders( self, scheduler_list ):
    binders = []
    msg = self.hs_client_hello_to_partial()
    for scheduler in scheduler_list :
      binders.append( scheduler.tls_hash.verify_data( scheduler.secrets[ 'b' ], msg ) )
    client_hello_exts = self.msg( 'client_hello' )[ 'extensions' ]
    pre_shared_key = get_struct(client_hello_exts, 'extension_type', 'pre_shared_key' )
    pre_shared_key_i = client_hello_exts.index( pre_shared_key )
    self.msg_list[ self.msg_i( 'client_hello' )[ -1 ] ][ pre_shared_key_i ]['binders' ] = binders



class SessionTicket:
## We need to be able to generate encrypted tickets.
  def __init__( self, tls13_conf, psk_identity:bin = None ):
    """ session ticket 

      psk_identity (bin): 
    """
    self.conf = tls13_conf
    self.psk_identity = psk_identity
    if psk_identity != None:
      self.read_ticket( psk_identity )
    ## This variable is used to identify the selection of the currenlty 
    ## used ticket. 
    ## This is used to check the server hello match the ticket that has 
    ## been used to generates the early secrets
    self.selected_identity = None      

  def new( self, scheduler, cipher ):
    self.cipher = cipher 
    self.tls_hash = CipherSuite( self.cipher ).get_hash() 
    ticket_nonce = token_bytes( self.conf[ 'ticket_nonce_len' ] )
    self.psk =  scheduler.compute_psk( ticket_nonce )
     
    ticket = dumps( { 'cipher' : cipher, 'psk': self.psk } )
    return { \
      'ticket_lifetime' : self.conf[ 'ticket_life_time' ], \
      'ticket_age_add' : randbits( 4 * 8 ), \
      'ticket_nonce' : ticket_nonce, \
      'ticket' : ticket, 
      'extensions' :[] }

  def read_ticket( self, psk_identity:dict ):
    
    ticket =  loads( psk_identity[ 'identity' ] )  
    self.cipher = ticket[ 'cipher' ]
    self.psk = ticket[ 'psk' ]
    self.tls_hash = CipherSuite( self.cipher ).get_hash()

  def init_handshake( self, handshake ):
    """initialize handshake from values stored in the ticket. 

    This is needed for example in the abscente of a server hello when 
    the hash function needs to be known to generates the early secrets.
    The hash function is in fact generated from the cipher suite, so the 
    hash is not directly configured. 
    see SInitEarlySecret for an example. 
    """
    handshake.cipher_suite = self.cipher

class KeyScheduler:

  def __init__( self, tls_hash, ecdhe:bytes=None, psk:bytes=None, is_ext=False): 
    self.secrets = { 'b' : None, 'e_c' : None, 'e_x' : None,\
                    'h_c' : None, 'h_s' : None, 'a_c' : None,\
                    'a_s' : None, 'x' : None, 'r' : None }
    self.tickets = []
    self.ecdhe = ecdhe
    self.psk = psk

    if isinstance( tls_hash, SHA256 ) :
      self.tls_hash = TlsHash( hashmod=hashlib.sha256 )
    elif isinstance( tls_hash, SHA384 ) :
      self.tls_hash = TlsHash( hashmod=hashlib.sha384 )
    elif isinstance( tls_hash, SHA512 ) :
      self.tls_hash = TlsHash( hashmod=hashlib.sha512 )
    else: 
      raise ImplementationError( f"unknown tls_hash {tls_hash} (SHA256 or SHA384)" )
    self.psk_wrapper = PSKWrapper( self.psk, self.tls_hash, is_ext = is_ext )
        
    self.scheduler = self.tls_hash.scheduler( self.ecdhe, self.psk )

  def process( self, secret_list:list, handshake:TlsHandshake ) -> None: 
  
    if 'b' in secret_list:
      self.secrets[ 'b' ] = self.psk_wrapper.binder_key()
    if 'e_c' in secret_list or  'e_x' in secret_list:
      transcript_h = handshake.transcript_hash( 'e' )
      if 'e_c' in secret_list:
        self.secrets[ 'e_c' ] = \
          self.psk_wrapper.client_early_traffic_secret( transcript_h )
      if 'e_x' in secret_list:
        self.secrets[ 'e_x' ] = \
          self.psk_wrapper.early_exporter_master_secret( transcript_h )
    elif 'h_c' in secret_list or  'h_c' in secret_list:
      transcript_h = handshake.transcript_hash( 'h' )
      if 'h_c' in secret_list:
        self.secrets[ 'h_c' ] = \
          self.scheduler.client_handshake_traffic_secret( transcript_h )
        self.secrets[ 'h_s' ] = \
          self.scheduler.server_handshake_traffic_secret( transcript_h )
    elif 'a_c' in secret_list or  'a_c' in secret_list or\
       'x' in secret_list:
      transcript_h = handshake.transcript_hash( 'a' )
      if 'a_c' in secret_list: 
        self.secrets[ 'a_c' ] =\
          self.scheduler.client_application_traffic_secret_0( transcript_h )
      if 'a_s' in secret_list: 
        self.secrets[ 'a_s' ] =\
          self.scheduler.server_application_traffic_secret_0( transcript_h )
      if 'x' in secret_list: 
        self.secrets[ 'x' ] = self.scheduler.exporter_master_secret( transcript_h )
    elif 'r' in secret_list:
      transcript_h = handshake.transcript_hash( 'r' )
      self.secrets[ 'r' ] = self.scheduler.resumption_master_secret( transcript_h )

  def compute_psk( self, ticket_nonce ) -> bytes: ## or None
    return self.tls_hash.hkdf_expand_label( self.secrets[ 'r' ] , b"resumption",\
             ticket_nonce, self.tls_hash.hash_len )

class SInitCertVerifyReq:

  def __init__(self, req, tls13_conf ):
    self.conf = tls13_conf
    self.mtype = 's_init_cert_verify'
    self.next_mtype = 's_new_ticket'
   
    self.freshness = Freshness( req[ 'freshness' ] )
    self.secret_request = SecretReq(req[ 'secret_request' ], self.mtype, self.conf )
    self.sig_algo = SigScheme( req[ 'sig_algo' ] )
    self.handshake = TlsHandshake( 'server', self.conf )
    self.handshake.msg_list.extend( req[ 'handshake' ] )
    self.handshake.sanity_check( self.mtype )
    self.handshake.update_random( self.freshness )
    self.cert = LurkCert( req[ 'certificate' ], self.mtype, self.conf, True, \
                          self.handshake )
    ks = self.handshake.msg_list[ 1 ][ 'data' ][ 'extensions' ][ 0 ] [ 'extension_data' ] [  'server_share' ] [ 'key_exchange'  ]
    print( f"SInitCertVerifyReq : ks : {ks} / {req[ 'ephemeral' ][ 'method' ]}" )
    self.ephemeral = Ephemeral( req[ 'ephemeral' ], self.mtype, self.conf, self.handshake )
    self.scheduler = None

    if self.ephemeral.method == 'cs_generated':
      self.handshake.update_key_share( self.ephemeral.server_share )
    self.scheduler = KeyScheduler( self.handshake.get_tls_hash(), \
                                   ecdhe=self.ephemeral.shared_secret )
    self.scheduler.process( self.secret_request.of([ 'h_c', 'h_s' ] ), self.handshake )
    self.handshake.update_certificate( self.cert )
    self.handshake.update_certificate_verify( )
    ## get sig from freshly generated certificate_verify 
    sig = self.handshake.msg_list[ 0 ][ 'data' ]['signature' ] 
    self.handshake.update_server_finished( self.scheduler )
    self.scheduler.process( self.secret_request.of( [ 'a_c', 'a_s', 'x' ] ), self.handshake )
    self.tag = Tag( req[ 'tag' ], self.mtype, self.conf )
    self.session_id = SessionID( req[ 'session_id' ], self.tag )
    self.resp = { 'tag' : self.tag.resp,
                  'session_id' : self.session_id.cs,
                  'ephemeral' : self.ephemeral.resp,
                  'secret_list' : self.secret_request.resp( self.scheduler ),
                  'signature' : sig }

class SNewTicketReq:

  def __init__( self, req, tls13_conf, handshake, scheduler, session_id, \
                ticket_counter ):
    self.conf = tls13_conf
    self.mtype = 's_new_ticket'
    self.handshake = handshake
    self.scheduler = scheduler
    self.ticket_counter = ticket_counter

    self.handshake.msg_list.extend( req[ 'handshake' ] )
    self.cert = LurkCert( req[ 'certificate' ], self.mtype, self.conf, False, \
                          self.handshake ) 
    if self.cert.cert_type != 'no_certificate' :
      print( f" {self.handshake.msg_type_list()} - {self.cert.cert_type}" )
      self.handshake.update_certificate( self.cert, server=False )
    self.secret_request = SecretReq(req[ 'secret_request' ], self.mtype, self.conf )
    self.scheduler.process( self.secret_request.of( [ 'r' ] ), self.handshake )
    self.next_mtype = 's_new_ticket'

    ticket_nbr = self.nbr( req[ 'ticket_nbr' ] )
    ticket_list = []
    ticket = SessionTicket( self.conf ) 
    for t in range( ticket_nbr ):
      ticket_list.append( \
        ticket.new( self.scheduler, self.handshake.get_cipher_suite() ) )
    self.tag = Tag( req[ 'tag' ], self.mtype, self.conf, ctx=ticket_nbr ) 

    self.resp =  { 'tag' : self.tag.resp,
              'session_id' : session_id.e,
              'secret_list' : self.secret_request.resp( self.scheduler ),
              'ticket_list' : ticket_list }


  def nbr( self, ticket_nbr ):
    """ determine the maximum number of tickets that can be emitted 

    use to compute self.ticket_nbr
    """
    if self.ticket_counter <= self.conf[ 'max_tickets' ]:
      n =  min( ticket_nbr, self.conf[ 'max_tickets' ] ) 
      self.ticket_counter += n
    else: 
      n = 0
    return n
  
class SInitEarlySecretReq:

  def __init__( self, req, tls13_conf ):
    self.conf = tls13_conf
    self.mtype = 's_init_early_secret'
    self.next_mtype = 's_hand_and_app_secret'
   
    self.freshness = Freshness( req[ 'freshness' ] )
    
    self.handshake = TlsHandshake( 'server', self.conf )
    self.handshake.msg_list.extend( req[ 'handshake' ] )
    self.handshake.sanity_check( self.mtype )
    print( f"checking early_data {req[ 'secret_request' ]}" ) 
    print( f"checking early_data {self.handshake.is_early_data_proposed( )}" ) 
    if self.handshake.is_early_data_proposed( ) is False and\
       'e_c' in req[ 'secret_request' ] :
      req[ 'secret_request' ].remove( 'e_c' )
    print( f"checked early_data {req[ 'secret_request' ]}" ) 
    ## the binary format of the ticket 
    psk_identity = self.handshake.get_ticket( req[ 'selected_identity' ] )
    self.session_ticket = SessionTicket( self.conf, psk_identity=psk_identity )
    ## to enable to check the server hello is conformed with the ticket in used. 
    self.session_ticket.selected_identity = req[ 'selected_identity' ] 
    self.session_ticket.init_handshake( self.handshake )
    self.secret_request = SecretReq(req[ 'secret_request' ], \
                          self.mtype, self.conf, handshake=self.handshake )
    self.scheduler = KeyScheduler( self.session_ticket.tls_hash, \
                                   psk=self.session_ticket.psk, is_ext=False)
#    self.last_exchange = None 
    self.session_id = SessionID( req[ 'session_id' ] )
    self.scheduler.process( self.secret_request.of([ 'b', 'e_c', 'e_x' ] ), self.handshake )
    self.resp = { 'session_id' : self.session_id.cs,
             'secret_list' : self.secret_request.resp( self.scheduler ) }
#    return  { 'session_id' : self.session_id.resp( ),
#              'secret_list' : self.secret_request.resp( self.scheduler ) }

class SHandAndAppSecretReq: 

  def __init__( self, req, tls13_conf, handshake, scheduler, session_id, session_ticket, freshness ):
    self.conf = tls13_conf
    self.mtype = 's_hand_and_app_secret'
    self.next_mtype = 's_new_ticket'
    self.freshness = freshness
    self.handshake = handshake
    self.secret_request = SecretReq(req[ 'secret_request' ], self.mtype, self.conf )
    self.handshake.msg_list.extend( req[ 'handshake' ] )
    self.scheduler = scheduler
    self.session_ticket = session_ticket 
    self.handshake.sanity_check( self.mtype, session_ticket=session_ticket )
    self.handshake.update_random( self.freshness )
    print( f"initilaizing ephemeral {req[ 'ephemeral' ]} - {self.mtype} - {self.handshake.msg_type_list()}" )
    self.ephemeral = Ephemeral( req[ 'ephemeral' ], self.mtype, self.conf, self.handshake)
      
    print("initialized SHandAndAppSecretReq")

#    self.ephemeral.compute_server_key_exchange( self.handshake ) 
    if self.ephemeral.method == 'cs_generated':
      self.handshake.update_key_share( self.ephemeral.server_share )
    self.scheduler.ecdhe = self.ephemeral.shared_secret 
    self.scheduler.process( self.secret_request.of( [ 'h_c', 'h_s'] ), self.handshake )
    self.handshake.update_server_finished( self.scheduler )
    self.scheduler.process( self.secret_request.of( [ 'a_c', 'a_s', 'x' ] ), self.handshake )
    self.tag = Tag( req[ 'tag' ], self.mtype, self.conf )
    self.resp =  { 'tag' : self.tag.resp,
                   'session_id' : session_id.e,
                   'ephemeral' : self.ephemeral.resp,
                   'secret_list' : self.secret_request.resp( self.scheduler ) }

class SSession:

  def __init__( self, tls13_conf, session_db=None, ticket_db=None ): # type Conf
    """ handles the various requests associated to a given session """ 
    self.conf = tls13_conf 
    self.next_mtype = None
    self.scheduler = None
    self.handshake = None
    self.session_id = None
    self.freshness = None
    self.next_mtype = None
    self.last_exchange = None
    self.ticket_counter = 0
    self.session_db = session_db
    self.ticket_db = ticket_db

  def is_expected_message( self, mtype, status ):
    if status != 'request':
      raise LURKError( 'invalid_status', "unexpected status {status}"\
              f"expecting 'request'" )
    if ( self.next_mtype == None and 'init' in mtype ) or\
       mtype == self.next_mtype:
      pass
    else: 
      raise LURKError( 'invalid_type', f"unexpected request {mtype} "\
              f"expecting {self.next_mtype} or initial request" )

  def serve( self, payload, mtype, status ):
    self.is_expected_message( mtype, status )
    if mtype == 's_init_cert_verify':
      req = SInitCertVerifyReq( payload, self.conf )
      self.scheduler = req.scheduler
      self.handshake = req.handshake
      self.session_id = req.session_id
      self.last_exchange = req.tag.last_exchange
    elif mtype == 's_new_ticket':
      req = SNewTicketReq( payload, self.conf, self.handshake,\
              self.scheduler, self.session_id, self.ticket_counter )
      self.ticket_counter = req.ticket_counter 
      self.last_exchange = req.tag.last_exchange
    elif mtype == 's_init_early_secret':
      req = SInitEarlySecretReq( payload, self.conf )
      self.scheduler = req.scheduler
      self.handshake = req.handshake
      self.session_id = req.session_id
      self.freshness = req.freshness
      self.session_ticket = req.session_ticket
    elif mtype == 's_hand_and_app_secret':
      req = SHandAndAppSecretReq( payload, self.conf, self.handshake,\
              self.scheduler, self.session_id, self.session_ticket, self.freshness )
      self.last_exchange = req.tag.last_exchange
    else: 
      raise LURKError( 'invalid_request', "unexpected request {mtype}"\
              f"expecting {self.next_mtype} or initial request" )
    print( f" -- {req}" )
    self.next_mtype = req.next_mtype
    return req.resp



class CInitClientFinishedReq:

  def __init__(self, req, tls13_conf ):
    self.conf = tls13_conf
    self.mtype = 'c_init_client_finished'
    self.next_mtype = 'c_post_hand_auth'
   
    self.session_id = SessionID( req[ 'session_id' ], self.mtype )
#    freshness = Freshness( req[ 'freshness' ] )
    
    psk = req[ 'psk' ]
    self.handshake = TlsHandshake( 'client', self.conf )
    self.handshake.msg_list.extend( req[ 'handshake' ] )
    self.handshake.sanity_check( self.mtype )
    server_cert = LurkCert( req[ 'server_certificate' ], self.mtype, self.conf, \
                    True, self.handshake )
    client_cert = LurkCert( req[ 'client_certificate' ], self.mtype, self.conf, \
                    False, self.handshake )
    self.handshake.update_random( Freshness( req[ 'freshness' ] ) )
    if server_cert[ 'cert_type' ] != 'no_certificate' : 
      self.handshake.update_certificate( server_cert, server=True )
    self.scheduler = None


    self.tag = Tag( req[ 'tag' ], self.mtype, self.conf, ctx=self.handshake )
    ephemeral = Ephemeral( req[ 'ephemeral' ], self.mtype, self.conf, self.handshake )

    self.scheduler = KeyScheduler( self.handshake.get_tls_hash(), \
                                   ecdhe=ephemeral.shared_secret, psk=psk )
    ### the current handshake.msg_list is up to early data
    ## we need to make sur we limit ourselves to the ClientHello...ServerHello
    self.scheduler.process( [ 'h_c', 'h_s' ], self.handshake )
    print( f"after h : {self.handshake.msg_type_list()}" ) 
    self.handshake.update_certificate( self.client_cert, server=False )
    print( f"client cert inserted : {self.handshake.msg_type_list()}" ) 
    self.handshake.update_certificate_verify( )
    ## get sig from freshly generated certificate_verify 
    sig = self.handshake.msg_list[ 0 ][ 'data' ]['signature' ]
    ## generating Finished message and generating the transcript of the full handshake
    if self.tag.last_exchange == False:
      self.handshake.update_server_finished( self.scheduler )
      self.scheduler.process( [ 'r' ], self.handshake )
    self.resp = { 'tag' : self.tag.resp,
                  'session_id' : self.session_id.cs,
                  'signature' : sig }


class CPostHandAuthReq:

  def __init__(self, req, tls13_conf, handshake, scheduler, session_id, post_hand_auth_counter ):
    self.conf = tls13_conf
    self.mtype = 'c_post_hand_auth'
    self.next_mtype = 'c_post_hand_auth'
   
    self.handshake = handshake
    self.handshake.msg_list.extend( req[ 'handshake' ] )
    self.handshake.update_certificate( req[ 'certificate' ], server=False )
    self.handshake.sanity_check( self.mtype )
    self.post_hand_auth_counter = post_hand_auth_counter + 1
    self.scheduler = scheduler

    ## the signature is performed for a post handshake transcript
    self.handshake.update_certificate_verify( )
    print( self.handshake.msg_list )
    sig = self.handshake.msg_list[ 0 ][ 'data' ]['signature' ]
    del self.handshake.msg_list[ : ]

    self.tag = Tag( req[ 'tag' ], self.mtype, self.conf, ctx=self.post_hand_auth_counter )
    self.resp =  { 'tag' : tag.resp,
                   'session_id' : session_id.e,
                   'signature' : sig }

class CInitClientHelloReq:

  def __init__(self, req, tls13_conf ):
    self.conf = tls13_conf
    self.mtype = 'c_init_client_hello'
    self.next_mtype = 'c_client_finished'
   
    self.handshake = TlsHandshake( 'client', self.conf )
    self.handshake.msg_list.extend( req[ 'handshake' ] )
    self.handshake.update_random( Freshness( req[ 'freshness' ] ) )
    ## keyshare
    self.ephemeral = Ephemeral( { 'method' : 'cs_generated' }, self.mtype, self.conf, self.handshake )
    self.handshake.update_key_share( self.ephemeral.client_shares )
    ## pre-shared-key extension
    secret_list = []
    ## the dictionaries are only filled when PSK are proposed and 
    ## hosted by the CS.
#    self.session_ticket_dict = {}
    self.scheduler_list = []
    psk_metadata_list = req[ 'psk_metadata_list' ]
    print( f"-- CInitClientHelloReq {self.handshake.msg_list}" )
    if self.handshake.is_psk_proposed( ) is True:
      offered_psk = self.get_offered_psks( )
      for psk in offered_psk[ 'identities' ] :
        ## not protected by cs
        if psk_index_list[ offered_psk[ 'identities' ].index( psk ) ] is True :
          psk_bytes = psk[ 'key' ]
          tls_hash = psk[ 'h' ]
        else:
          psk_identity = self.handshake.get_ticket( offered_psk[ 'identities' ][ psk_index ] )
          ## generates ticket from identity 
          session_ticket = SessionTicket( self.conf, psk_identity=psk_identity )
          ## store potential ticket, scheduler
#          self.self.session_ticket_dict[ psk_index ] = session_ticket 
          psk_bytes = self.session_ticket.psk
          tls_hash = self.session_ticket.tls_hash
        ks = KeyScheduler( tls_hash, psk=psk_bytes, is_ext=False )
        secret_request = SecretReq({ 'b' : True }, \
                          self.mtype, self.conf, handshake=self.handshake )
        ks.process( secret_request.of( [ 'b', 'e_s', 'e_x' ] ), self.handshake )
        self.scheduler_list.append( ks ) 
      secret_list = secret_request.resp( self.scheduler_list[ 0 ] ) 
    else: 
      secret_list = []
    self.handshake.sanity_check( self.mtype )

    self.session_id = SessionID( req[ 'session_id' ] )
    self.resp = { 'session_id' : self.session_id.cs,
                  'ephemeral_list' : self.ephemeral.resp, 
                  'secret_list' : secret_list  }

  def get_offered_psks( self ):
    """ returns the OfferedPSK structure in the ClientHello """
    ch_index = self.handshake.latest_client_hello_index( )
    last_ext = self.msg_list[ ch_index][ 'extensions' ][ -1 ]
    if last_ext[ 'extension_type' ] == 'pre_shared_key' :
      return last_ext[ 'extension_data' ]
    return []

##    pre_shared_key = get_struct(client_hello_exts, 'extension_type', 'pre_shared_key' )
    
class CClientHelloFinishedReq:

  def __init__(self, req, tls13_conf, handshake, scheduler_dict, session_ticket_dict, session_id ):
    self.conf = tls13_conf

#class CInitPostHandAuthReq:
# 
#  def __init__(self, req, tls13_conf ):
#    self.conf = tls13_conf
#    self.mtype = 'c_init_post_hand_auth'
#   
#    self.tag = Tag( req[ 'tag' ], self.mtype, self.conf )
#    self.session_id = SessionID( req[ 'session_id' ], self.mtype )
#    self.freshness = Freshness( req[ 'freshness' ] )
#    self.sig_algo = SigScheme( req[ 'sig_algo' ] )
#    self.cert = req[ 'certificate' ]
#    
#    self.handshake = TlsHandshake( 'client',  self.conf )
#    self.handshake.msg_list.extend( req[ 'handshake' ] )
#    self.handshake.sanity_check( self.mtype )
#    cert_req_ctx = self.handshake.msg( 'certificate_request', ith=-1 )['certificate_request_context']  
#    ## check why cert are generated
###    self.conf.load_cert( cert_req_ctx=cert_req_ctx )
#    self.hs_cert_msg = { 'msg_type' : 'certificate',
#                         'data' :  { 'certificate_request_context': cert_req_ctx,
#                                     'certificate_list' : self.conf[ '_cert_list' ] } }
#
#    self.last_exchange = None 
#    if self.conf[ 'post_handshake_authentication' ] == True:
#      self.next_mtype = 'c_post_hand_auth'
#    self.next_mtype = 'c_post_hand_auth'
#
#  def resp( self ):
#    self.handshake.update_certificate( self.cert )
#    self.handshake.update_certificate_verify( )
#    tag_resp = self.tag.resp( )
#    self.last_exchange  = tag_resp[ 'last_exchange' ]
#    sig = self.handshake.msg( 'certificate_verify', ith=-1 )[ 'signature' ]
#    self.handshake.post_post_hand_auth()
#    return { 'tag' : tag_resp,
#             'session_id' : self.session_id.resp( tag_resp=tag_resp ),
#             'signature' : sig }
#

#class CInitEphemeralReq:
#
#  def __init__(self, req, tls13_conf ):
#    self.conf = tls13_conf
#    self.mtype = 'c_init_ephemeral'
#   
#    self.session_id = SessionID( req[ 'session_id' ], self.mtype )
#    self.freshness = Freshness( req[ 'freshness' ] )
#    
#    self.handshake = TlsHandshake( 'client', self.conf )
#    client_hello = self.handshake.hs_partial_to_client_hello ( req[ 'handshake'] [0] )
#    self.handshake.msg_list.extend( [ client_hello ] )
#    self.handshake.sanity_check( self.mtype )
#    self.ephemeral = Ephemeral( req[ 'ephemeral' ], self.mtype, self.conf, self.handshake)
#
#    self.next_mtype = 'c_hand_and_app_secret'
#
#  def resp( self ):
##    self.ephemeral.compute_server_key_exchange( self.handshake ) 
#    self.handshake.update_key_share( self.ephemeral.server_key_exchange )
#    return { 'session_id' : self.session_id.resp( tag_resp=tag_resp ),
#             'ephemeral' : self.ephemeral.resp() }
#

##class CInitEarlySecretReq:
##
##  def __init__( self, req, tls13_conf ):
##    self.conf = tls13_conf
##    self.mtype = 'c_init_early_secret'
##   
##    self.session_id = SessionID( req[ 'session_id' ], self.mtype )
##    self.freshness = Freshness( req[ 'freshness' ] )
##    
##    self.ephemeral = Ephemeral( req[ 'ephemeral' ], self.mtype, self.conf )
##    self.handshake = TlsHandshake( 'client', self.conf )
##    client_hello = self.handshake.hs_partial_to_client_hello ( req[ 'handshake'] [0] )
##    self.handshake.msg_list.extend( [ client_hello ] )
##    self.handshake.sanity_check( self.mtype )
##    self.scheduler_list = []
##    self.next_mtype = 'c_hand_and_app_secret'
##    
##    for psk_id in self.handshake.get_ticket():
##      session_ticket = SessionTicket( self.conf, psk_identity=psk_id )
##      scheduler = KeyScheduler( session_ticket.tls_hash, \
##                                psk=session_ticket.psk, is_ext=False)
##      scheduler.process( self.secret_request.of([ 'b' ] ), self.handshake )
##      self.scheduler_list.append( scheduler ) 
####       
####    
####      binders.append( )
####      self.scheduler_list.
####    self.session_ticket = SessionTicket( conf, \
####      psk_identity=self.handshake.get_ticket( req[ 'selected_identity' ] ) )
####
##    self.secret_request = SecretReq(req[ 'secret_request' ], \
##                          self.mtype, self.conf, handshake=self.handshake )
##    self.last_exchange = None 
##    self.next_mtype = 's_hand_and_app_secret'
##  
##  def resp( self ):
##    self.ephemeral.compute_server_key_exchange( self.handshake )
##    if self.ephemeral.method == 'cs_generated':
##      self.handshake.update_key_share( self.ephemeral.server_key_exchange )
##    self.handshake_update_binders( self.scheduler_list )
##    secret_list_list = [] 
##    for scheduler in self.scheduler_list:
##      scheduler.process( self.secret_request.of([ 'b', 'e_c', 'e_x' ] ), self.handshake )
##      secret_list_list.append( self.secret_request.resp( scheduler )) 
##    return  { 'session_id' : self.session_id.resp( ),
##              'ephemeral' : self.ephemeral.resp,
##              'secret_list_list' : self.secret_request.resp( self.scheduler ) }
##
class CHandAndAppSecretReq: 

  def __init__( self, payload, tls13_conf, handshake, scheduler_list, session_id, ephemeral_method ):
    self.conf = tls13_conf
    self.mtype = 'c_hand_and_app_secret'
    self.tag = Tag( req[ 'tag' ], self.mtype, self.conf )
    self.session_id = session_id
    self.session_id.update( self.mtype )
    self.ephemeral = Ephemeral( req[ 'ephemeral' ], self.mtype,\
                                self.conf, ephemeral_method )

    self.handshake = handshake
    self.secret_request = SecretReq(req[ 'secret_request' ], self.mtype, self.conf )
    self.handshake.msg_list.extend( req[ 'handshake' ][0] ) ## ServerHello
    self.tls_cipher_text = req[ 'handshake' ][1]
    if len( req[ 'handshake' ] ) > 2:
      self.handshake_remainder =  req[ 'handshake' ] [ 1: ] 
    else:
      self.handshake_remainder = None
    if self.handshake.has_ext( 'key_share', 'agreed' ):
      self.ephemeral.compute_server_key_exchange( self.handshake )
    if self.hanshake.has_ext( 'psk', 'proposed' ) == False: 
    ## ecdhe-only c_init_ephemeral
        self.scheduler = KeyScheduler( self.handshake.get_tls_hash(), \
                                ecdhe=self.ephemeral.shared_secret, is_ext=False)
    else:
    ## presence of psk/psk-echde in ClientHello indicates c_init_early_secret
      if self.handshake.has_ext( 'psk', 'agreed' ) == True:
        selected_identity = self.handshake.get_selected_identity() 
        self.scheduler = self.scheduler_list( selected_identity )
      else: ## ecdhe
        self.scheduler = KeyScheduler( self.handshake.get_tls_hash(), \
                                ecdhe=self.ephemeral.shared_secret, is_ext=False)
    ## do we need the ticket
##    self.session_ticket = session_ticket 
##    self.handshake.sanity_check( self.mtype, session_ticket=session_ticket )
##    self.handshake.update_random( self.freshness )
    self.next_mtype = []
    if ( 'c_post_auth' ) in self.conf[ 'type_authorized' ] and \
         self.handshake.has_ext( 'post_handshake_auth', 'proposed') == True :
      self.next_mtype.append( 'c_post_hand_auth' )
    self.next_mtype = [ 'c_register_tickets' ]
      

  def resp( self ):
    self.scheduler.process( self.secret_request.of([ 'h_c', 'h_s' ] ), self.handshake )
    ## decrypt handshake
    secret = self.scheduler.secret_list[ 'h_s' ] 
##    server_write_key = self.sheduler.tls_hash.derive_key( secret, )  
##    server_write_iv =  self.sheduler.tls_hash.derive_key( secret, )
##   
    ## from section 5.2
    ## encrypted packet is:
    ##  struct {
##          ContentType opaque_type = application_data; /* 23 */
##          ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
##          uint16 length;
##          opaque encrypted_record[TLSCiphertext.length];
##      } TLSCiphertext;

    ## additional data = opaque || legacy || length
## section 5.3 describes how the nonce is derived
## iv_length define dby the cipher suite
## seq = 0 (length = iv_length )
## seq xor server_write_iv
##
##    plaintext of encrypted_record =
##      AEAD-Decrypt(peer_write_key, nonce,
##                       additional_data, AEADEncrypted)
##      struct {
##          opaque content[TLSPlaintext.length];
##          ContentType type;
##          uint8 zeros[length_of_padding];
##      } TLSInnerPlaintext;
    cipher = self.handshake.get_cipher_suite() 
    if cipher == 'TLS_CHACHA20_POLY1305_SHA256' :
      aead == TLS_CHACHA20_POLY1305_SHA256( secret )
    elif cipher == 'TLS_AES_128_GCM_SHA256':
      aead = TLS_AES_128_GCM_SHA256( secret )
    elif cipher == 'TLS_AES_256_GCM_SHA256' :
      aead = TLS_AES_256_GCM_SHA256( secret )
    elif cipher == 'TLS_AES_256_GCM_SHA384' : 
      aead = TLS_AES_256_GCM_SHA384()
    elif cipher == 'TLS_AES_128_CCM_SHA256' :
      aead = TLS_AES_128_CCM_SHA256( secret )
    elif cipher == 'TLS_AES_128_CCM_8_SHA256' :
      aead = TLS_AES_128_CCM_8_SHA256( secret )
    bytes_tls_cipher_text = TLSCiphertext.build( self.tls_cipher_text )
    additional_data = bytes_tls_cipher_text[:5] 
    bytes_plain_text = aead.decrypt( \
      self.tls_cipher_text[ 'encrypted_record' ], additional_data )
    length_of_padding = 0
    while bytes_plain_text[ -1 -length_of_padding ] == '\x00':
      length_of_padding += 1
    plain_text = TLSInnerPlaintext.parse( bytes_plain_text, \
                   _length_of_padding=length_of_padding ) 
    content = plain_text[ 'content' ]
    ## content = {EncryptedExtensions}, {CertificateRequest*},  
    ## {Certificate*}, {CertificateVerify*}  {Finished}
    encrypted_msgs = ClearTextHSMsgs.parse()
    self.handshake.msg_list.extend( encrypted_msgs )
    if self.handshake_remainder != None:
      self.handshake.insert( self.handshake_remainder )
    self.scheduler.process( self.secret_request.of([ 'h_c', 'h_s', 'x' ] ), self.handshake )

    ## generates messages
    cert_req = self.handshake.msg( 'certificate_request' )
    if cert_req != None:
      cert_req_ctx = cert_req[ 'certificate_request_context' ]
      ## why do we have load cert 
#      self.conf.load_cert( cert_req_ctx=cert_req_ctx )
      self.handshake_update_certificate()
      self.handshake.update_certificate_verify( )
    self.handshake.update_client_finished( self.scheduler )
    
    self.scheduler.process( self.secret_request.of( [ 'r' ] ), self.handshake )
    tag_resp = self.tag.resp( )
    self.last_exchange  = tag_resp[ 'last_exchange' ]
    cert_verify = self.handshake.msg( 'certificate_verify', -1 )
    return { 'tag' : tag_resp,
             'session_id' : self.session_id.resp( tag_resp=tag_resp ),
             'LURKTLS13Certificate': cert, 
             'sig_algo' : cert_verify[ 'algorithm' ], 
             'signature' : cert_verify[ 'signature' ],
             'secret_list' : self.secret_request.resp( self.scheduler ) }

class register_tickets:

  def resp( self ):
    tag_resp = self.tag.resp( )
    self.last_exchange  = tag_resp[ 'last_exchange' ]
    return { 'tag' : tag_resp,
             'session_id' : self.session_id.resp( tag_resp=tag_resp ) }




##class CSession:
##  def __init__( self, tls13_conf, session_db=None, ticket_db=None ): # type Conf
##    """ handles the various requests associated to a given session """ 
##    self.conf = tls13_conf
##    self.next_mtype = None
##    self.scheduler = None
##    self.handshake = None
##    self.session_id = None
##    self.next_mtype = None
##    self.last_exchange = None
##    self.ticket_counter = 0
##    self.session_db = session_db
##    self.ticket_db = ticket_db
##    self.scheduler_list = None
##
##  def save_session_ctx( self, req ):
##    """ saves context for next messages"""
##    if req.mtype == 'c_init_client_finished':
##      self.last_exchange = True
##    elif req.mtype == 'c_init_post_auth':
##      self.handshake = req.handshake
##      self.session_id = req.session_id
##    elif req.mtype == 'c_post_auth':
##      self.handshake = req.handshake
##      self.session_id = req.session_id
##      self.post_hand_auth_counter += 1
##    elif req.mtype == 'c_init_ephemeral':
##      self.handshake = req.handshake
##      self.session_id = req.session_id
##      self.ephemeral_method = req.ephemeral.method
##    elif req.mtype == 'c_init_early_secret':
##      self.session_id = req.session_id
##      self.scheduler_list = req.scheduler_list
##      self.handshake = req.handshake
##      self.ephemeral_method = req.ephemeral.method
##    elif req.mtype == 'c_hand_and_app_secret':
##      self.last_exchange = req.last_exchange
##      self.post_hand_auth_counter = 0
##    else: 
##      raise ImplementationError( "unknown mtype {req.mtype}" )
##    self.next_mtype = req.next_mtype
##    
##  def is_expected_message( self, mtype, status ): 
##    if status != 'request':
##      raise LURKError( 'invalid_request', "unexpected status {status}"\
##              f"expecting 'request'" )
##    if ( self.next_mtype == None and 'init' in mtype ) or\
##       mtype == self.next_mtype:
##      pass
##    else: 
##      raise LURKError( 'invalid_request', "unexpected request {mtype}"\
##              f"expecting {self.next_mtype} or initial request" )
##
##  def serve( self, payload, mtype, status ):
##    self.is_expected_message( mtype, status )
##    if mtype == 'c_init_post_hand_auth':
##      req = CInitPostHandAuthReq( payload, self.conf )
##    elif mtype == 'c_post_hand_auth':
##      req = CPostHandAuthReq( payload, self.conf, self.handshake, self.session_id, post_hand_auth_counter=self.post_hand_auth_counter )
##    elif mtype == 'c_init_ephemeral': ## only ECDHE
##      req = CInitEphemeralReq( payload, self.conf )
##    elif mtype == 'c_init_early_secret':
##      req = CInitEarlySecret( payload, self.conf )
##    elif mtype == 'c_hand_and_app_secret':
##      req = CHandAndAppSecret( payload, self.conf, self.handshake, \
##              self.scheduler_list, self.session_id,\
##              self.ephemeral_method )
##    else: 
##      raise LURKError( 'invalid_request', "unexpected request {mtype}"\
##              f"expecting {self.next_mtype} or initial request" )
##    resp = req.resp()
##    self.save_session_ctx( req )
##    return resp

class CSession(SSession) :

#  def save_session_ctx( self, req ):
#    """ saves context for next messages"""
#    if req.mtype == 'c_init_client_finished':
#      self.scheduler = req.scheduler
#      self.handshake = req.handshake
#      self.session_id = req.session_id
#      self.last_exchange = req.tag.last_exchange
#      self.post_hand_auth_counter = 0
#    elif req.mtype  == 'c_post_hand_auth':
#      self.last_exchange = req.last_exchange
#      self.post_hand_auth_counter = req.post_hand_auth_counter
#
#
#    elif req.mtype == 's_new_ticket':
#      self.ticket_counter = req.ticket_counter 
#      self.last_exchange = req.last_exchange
#    else: 
#      raise ImplementationError( f"unknown mtype {req.mtype}" )
#    self.next_mtype = req.next_mtype

  def serve( self, payload, mtype, status ):
    ## check request and next_
    self.is_expected_message( mtype, status )
    if mtype == 'c_init_client_finished':
      req = CInitClientFinishedReq( payload, self.conf )
      self.scheduler = req.scheduler
      self.handshake = req.handshake
      self.session_id = req.session_id
      self.last_exchange = req.tag.last_exchange
      self.post_hand_auth_counter = 0
    elif mtype == 'c_post_hand_auth':
      req = CPostHandAuthReq( payload, self.conf, self.handshake, self.scheduler,\
                           self.session_id, self.post_hand_auth_counter )
      self.last_exchange = req.last_exchange
      self.post_hand_auth_counter = req.post_hand_auth_counter
    elif mtype == 'c_init_client_hello':
      req = CInitClientHelloReq( payload, self.conf )
      self.scheduler_list = req.scheduler_list
#      self.session_ticket_dict = req.session_ticket_dict
      self.handshake = req.handshake
      self.session_id = req.session_id
      self.ephemeral = req.ephemeral
    else: 
      raise LURKError( 'invalid_request', "unexpected request {mtype}" )
    self.next_mtype = req.next_mtype
    return req.resp

class SessionDB:

  def __init__(self, ):

    self.db = {}

  def store( self, session:SSession):
    self.db[ session.session_id.cs ] = session

  def unstore( self, session_id:bytes ):
    return self.db[ session_id ]

  def delete( self, session:SSession):
    del self.db[ session.session_id.cs ]
##  def search_session(psk_id:PskID) -> Session :  
##    for session in self.db.values():
##      for ticket in session.tickets:
##        if ticket.ticket == psk_id.identity:
##          return session
##    raise LURKError( psk_id, "unable to find ticket", 'invalid_psk') 

class TicketDb:

  def __init__( self ):
    pass

def nothing( req ):
  return 'nothing'

class Tls13Ext:
  def __init__(self, conf=default_conf):
    ## configuration
    ## session DB
    self.session_db = SessionDB()

    self.conf = conf 
  
  def payload_resp( self, req:dict ) -> dict :
      req_type = req[ 'type' ]
      req_payload = req[ 'payload' ]
      if req_type in [ 's_init_early_secret', 's_init_cert_verify' ]:
        session = SSession( self.conf )
        payload  = session.serve( req_payload, req_type, 'request')
        if session.session_id != None :
          self.session_db.store( session ) 
      elif req_type == 's_hand_and_app_secret':
        try:
          session = self.session_db.unstore( req_payload[ 'session_id' ] )
        except KeyError:
          raise LURKError( 'invalid_session_id', f"{req} session_id not found in DB" )
        payload = session.serve( req_payload, req_type, 'request' )
      elif req_type == 's_new_ticket':
        try:
          session = self.session_db.unstore( req_payload[ 'session_id' ] )
        except KeyError:
          raise LURKError( 'invalid_session_id', f"{req} session_id not found in DB" )
        payload  = session.serve( req_payload, req_type, 'request')
      else:
        raise LURKError( 'invalid_type', f"{req_type}" )
        if session.last_exchange is True:
          self.session_db.delete( session )          
      return payload
  
