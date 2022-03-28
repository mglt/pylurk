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
from cryptography import x509
from cryptography.x509.oid import NameOID

from cryptography.hazmat.primitives.asymmetric import padding
import datetime


from construct.core import *
from construct.lib import *
from pylurk.tls13.struct_tls13 import PskIdentity, Certificate, SignatureScheme, Handshake, OfferedPsks
from pylurk.tls13.key_schedule import TlsHash, PSKWrapper
from pylurk.conf import default_conf, SigScheme, CipherSuite
from pylurk.lurk.lurk_lurk import LURKError, ImplementationError, ConfigurationError


from pickle import dumps, loads


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

class Tag:

  def __init__( self, tag:dict, mtype, tls13_conf, ctx=None ):
    self.conf = tls13_conf
    self.mtype = mtype
    self.last_exchange = tag[ 'last_exchange' ]

    if self.mtype in [ 's_init_cert_verify', 's_hand_and_app_secret'  ]:
      self.last_exchange = self.conf[ 'last_exchange' ][ self.mtype ]
    elif self.mtype in [ 's_new_ticket', 'c_register_tickets' ]:
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
    elif self.mtype in [ 'c_client_finished' ]:
      ## ctx is the handshake
      self.last_exchange = self.conf[ 'last_exchange' ][ self.mtype ]
      if ctx.is_post_hand_auth_proposed() == False and\
         ctx.msg_list[ 0 ][ 'msg_type' ] == 'server_hello' :
        self.last_exchange = True
    else:
      raise ImplementationError( f"unknown type {self.mtype}" )

    self.resp = { 'last_exchange' : self.last_exchange }


class Ephemeral:

  def __init__(self, ephemeral:dict, mtype, tls13_conf, handshake=None,\
               client_hello_ephemeral=None  ) -> None:
    """ initializes the object based on the structure """

    self.conf = tls13_conf
    self.ephemeral = ephemeral
    self.mtype = mtype
    ## The s_init_early_data only requires to store the cliemt_shares
    if ephemeral != {}:
      self.method = self.ephemeral['method']
    self.handshake = handshake
    self.sanity_check( )
    ## the entry for the key scheduler
    if self.conf[ 'role' ] == 'server':
      if self.mtype == 's_init_cert_verify':
        self.shared_secret, self.resp = self.compute_server_share( )
        self.server_share = self.resp[ 'key' ]
      if self.mtype == 's_init_early_secret' :
        self.client_shares = self.get_key_share_client_shares()
      elif self.mtype == 's_hand_and_app_secret':
        self.shared_secret, self.resp = self.compute_server_share( client_hello_ephemeral.client_shares )
        self.server_share = self.resp[ 'key' ]
      ## key is the server_share value which is a key share entry
    elif self.conf[ 'role' ] == 'client':
      if self.mtype == 'c_init_client_hello':
        self.client_shares, self.private_key_list, self.resp = self.compute_client_shares( )
#      elif self.mtype == 'c_server_hello' :
#        self.shared_secret = self.
    else:
      raise ImplementationError( f"unknown role {self.conf[ 'role' ]}" )

  def sanity_check( self ):
    """ check coherence of ephemeral with mtype and handshake """
    if self.mtype == 's_init_early_secret' and self.ephemeral == {}:
      pass
    elif self.method not in self.conf['ephemeral_method_list']:
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
    elif self.mtype == 'c_init_client_hello':
      pass
    elif self.mtype == 'c_server_hello':
      if self.method in [ 'cs_generated', 'e_generated' ] and not self.handshake.is_ks_agreed() :
        raise LURKError( 'invalid_ephemeral', f"(EC)DHE provided ({self.method}) "\
                f"but PSK-ECDHE or ECDHE authentication is not agreed "\
                f"{self.handshake.msg_list}" )
      elif self.method == 'no_secret' and self.handshake.is_ks_agreed() :
        raise LURKError( 'invalid_ephemeral', f"(EC)DHE not provided ({self.method})"\
                f"but PSK-ECDHE or ECDHE authentication is agreed" )


  def get_key_share_client_shares( self ): 
    """ returns the client key_shares (a list of key share entry) 
     
    key_shares is located in the ClientHello
    """
    ch_index = self.handshake.latest_client_hello_index( )
    client_hello_exts = self.handshake.msg_list[ ch_index][ 'data' ][ 'extensions' ]
    print( f" --- client_hello_exts : {client_hello_exts}" )
    e_list = [ e[ 'extension_type' ] for e in client_hello_exts ] 
    if 'key_share' in e_list: 
      return  client_hello_exts[ e_list.index( 'key_share' ) ][ 'extension_data' ][ 'client_shares' ]
    return []

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
      elif group ==  'secp384r1':
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
    print( f"-- client_shares: {client_shares}" )
    for ks in client_shares :
      print( f" ks : {ks} " )
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
    return new_client_shares, private_key_list, resp

  def get_key_share_entry_list_from_handshake( self, client_shares=None ):
    """ return the client key share entry selected by the server 

    Given a ServerHello message and a ClientHello message, 
    the function selects the key_share extension of the ServerHello
    It selects the client_shares from teh ClientHello and returns the 
    entry that match the group selected by the key_share extension 
    of the ServerHello
    """

    ## getting the server key share extension
    sh_index = self.handshake.server_hello_index()
    for ext in self.handshake.msg_list[ sh_index ][ 'data' ][ 'extensions' ] :
      if ext[ 'extension_type' ] == 'key_share':
        server_ks = ext[ 'extension_data' ][ 'server_share' ]
        break

    ## get client shares
    if client_shares is None:
      client_shares = self.get_key_share_client_shares( ) 
    else: 
      client_shares = client_shares
    selected_group = server_ks[ 'group' ]
    client_ks = None
    for ks in client_shares:
      if ks[ 'group' ] == selected_group :
        client_ks = ks
        break
    ## select the client key_share extension 
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

  def compute_client_share_secret( self, c_init_client_hello_ephemeral ):
    """ compute the share secret on the client side 

    The current object is generated from the ephemeral provided by E during the 
    c_server_hello exchange. 
    On the other hand private keys have been generated during the 
    c_init_client_hello exchange. 
    This latest ephemeral is used as th einput. 
    """
    if self.method == 'e_generated':
      shared_secret = self.ephemeral[ 'key' ][ 'shared_secret' ]
    elif self.method == 'cs_generated':
      client_ks, server_ks = self.get_key_share_entry_list_from_handshake( client_shares=c_init_client_hello_ephemeral.client_shares )
      print( f"client_ks: {client_ks} / server_ks: {server_ks}" )
      client_ks_index = c_init_client_hello_ephemeral.client_shares.index( client_ks )
      print( f"client_ks_index: {client_ks_index}" ) 
      client_private_key = c_init_client_hello_ephemeral.private_key_list[ client_ks_index ]
      print( f"c_init_client_hello_ephemeral.private_key_list: {c_init_client_hello_ephemeral.private_key_list}" )
      print( f"client_private_key: {client_private_key}" ) 
      if client_private_key is None:
        raise LURKError( 'invalid_ephemeral', f"Unable to find corresponding\
                          private key in {client_shares}" )
      server_public_key = self.get_publickey_from_key_share_entry( server_ks )
      shared_secret = self.compute_share_secret( client_private_key, server_public_key, server_ks[ 'group' ] ) 

    elif self.method == 'no_secret': 
      shared_secret = None
    else: 
      raise LURKError( 'invalid_ephemeral', f"Unexpected method {self.method}" )
    self.shared_secret = shared_secret


  def compute_server_share( self, client_shares=None ):
    """ treat ephemeral extension and initializes self.ecdhe, self.server_key_exchange 

    This function is responsible for generating the server (EC)DHE public key, 
    computing the shared secret as well as generating the key_share extension 
    of the ServerHello.
    self.shared_secret contains the shared secret key, the server (EC)DHE public key 
    is taken from the reurned resp and stored in self.server_share

    see __init__( ) fucntion:
      self.shared_secret, self.resp = self.compute_server_share( )
      self.server_share = self.resp[ 'key' ]
    """
    ## with method 'e_generated' the shared_secret is explictly provided
    if self.method == 'e_generated':
      shared_secret = self.ephemeral['key'][ 'shared_secret' ]
      resp = { 'method' : self.method,
               'key' : b'' }
    ## with method 'cs_generated' the cs needs to generate the public key, 
    ## private key, take the client public key and compute the shared secret
    elif self.method == 'cs_generated':
      ## retrieve the server key_share entry and seklect the client key_share entry
      ## since method is 'cs_generated' the server key_share entry MUST be empty
      client_ks, server_ks = self.get_key_share_entry_list_from_handshake( client_shares=client_shares)
      server_private_key, server_ks = self.proceed_empty_key_share_entry( server_ks )
      if client_ks is None:
        raise LURKError( 'invalid_ephemeral', f"Unable to find corresponding\
                key share entries in {client_shares} and {server_ks}" )
      client_public_key = self.get_publickey_from_key_share_entry( client_ks )

      shared_secret = self.compute_share_secret( server_private_key, client_public_key, server_ks[ 'group' ] ) 
      resp = { 'method' : self.method,
               'key' : server_ks }
    
    elif self.method == 'no_secret': 
      shared_secret = None
      resp = { 'method' : self.method,
               'key' : b'' }
    else: 
      raise LURKError( 'invalid_ephemeral', f"Unexpected method {self.method}" )
    return shared_secret, resp

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
      optional = [ 'e_s', 'e_x' ]
    elif mtype in [ 's_init_cert_verify', 's_hand_and_app_secret' ]:
      mandatory = [ 'h_c', 'h_s']
      forbiden = [ 'b', 'e_s', 'e_x', 'r']
      optional = [ 'a_c', 'a_s', 'x' ]
    elif mtype in [ 's_new_ticket', 'c_register_ticket' ]:
      mandatory = []
      forbiden = [ 'b', 'e_s', 'e_x', 'h_c', 'h_s', 'a_c', 'a_s', 'x']
      optional = ['r'] 
    elif mtype in [ 'c_server_hello' ]:
      mandatory = [ 'h_c', 'h_s' ]
      forbiden = [ 'b', 'e_s', 'e_x', 'a_c', 'a_s', 'x', 'r']
      optional = [] 
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
    elif mtype in [ 's_init_early_secret', 'c_init_client_hello' ]:
      if self.conf[ 'client_early_secret_authorized' ] ==  False:
        try:
          self.authorized_secrets.remove( 'e_s' )
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
    if self.conf != None :
      self.finger_print_dict = self.conf[ '_finger_print_dict' ]
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
    self.ks_proposed = None
    self.psk_proposed = None

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

  def server_hello_index( self ):
    """ returns the index of the server_hello message """
    ## when self,msg_list starts with serverhello: s_hand_and_app
    if self.msg_list[ 0 ][ 'msg_type' ] == 'server_hello' : 
      sh_index = 0
    # when self.msg_list starts with client hello: s_init_cert_verify,   
    else:
      ch_index = self.latest_client_hello_index()
      if len( self.msg_list ) < ch_index + 1:
        raise ImplementationError( f"cannot find server hello {self.msg_list}" )
      sh_index = ch_index + 1
    return sh_index

  def client_hello_extension_list( self ):
    ch_index = self.latest_client_hello_index()
    ext_list = []
    for ext in self.msg_list[ ch_index ][ 'data' ][ 'extensions' ] :
      ext_list.append( ext[ 'extension_type' ] )
    return ext_list

  def server_hello_extension_list( self ):
    sh_index = self.server_hello_index()
    ext_list = []
    for ext in self.msg_list[ sh_index ][ 'data' ][ 'extensions' ] :
      ext_list.append( ext[ 'extension_type' ] )
    return ext_list

  def is_psk_proposed( self )->bool :
    """ return True if self.msg_list has proposed PSK, False otherwise """
    if self.psk_proposed != None:
      return self.psk_proposed

    ext_list = self.client_hello_extension_list( )
    print( f"TlsHandshake : {ext_list}" )
    print( f"--- self.psk_proposed : {self.psk_proposed} {self.client_hello_extension_list( )}" )
    if 'pre_shared_key' in ext_list  and  'psk_key_exchange_modes' in ext_list :
      self.psk_proposed = True
    else:
      self.psk_proposed = False
    print( f"--- self.psk_proposed : {self.psk_proposed} {self.client_hello_extension_list( )}" )
    return self.psk_proposed

  def is_psk_agreed( self ) -> bool :
    """ return True is PSK has been agreed, False otherwise """
    ext_list = self.server_hello_extension_list( )
    if 'pre_shared_key' in ext_list :
      psk_agree = True
    else: 
      psk_agree = False
    return psk_agree
    
  def is_ks_proposed( self )->bool :
    """ return True if a key share extension is in the client_hello """

    if self.ks_proposed != None:
      return self.ks_proposed
    
    print( f"--- self.ks_proposed : {self.ks_proposed} {self.client_hello_extension_list( )}" )
    ext_list = self.client_hello_extension_list( )
    if 'key_share' in ext_list :
      self.ks_proposed = True
    else:
      self.ks_proposed = False
    print( f"--- self.ks_proposed : {self.ks_proposed} {self.client_hello_extension_list( )}" )
    return self.ks_proposed

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
    elif mtype == 'c_server_hello':
      pass 
    elif mtype == 'c_client_finished':
      pass
    else:
      raise ImplementationError( "unknown mtype {mtype}" )


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
      elif self.msg_list[ 0 ][ 'msg_type' ] == 'server_hello' :
        index = 0
      ks_designation = 'server_share'
    elif self.role == 'client':
      # update the 'client_hello'
      index = self.latest_client_hello_index( )
      ks_designation = 'client_shares'
    else:
      raise ImplementationError( f"unknown role {self.role}" )

    exts = self.msg_list[ index][ 'data' ][ 'extensions' ]
    if 'key_share' in [ e[ 'extension_type' ] for e in exts ] :
      key_share = get_struct( exts, 'extension_type', 'key_share' )
      key_share_index = exts.index( key_share )
      
      self.msg_list[ index ][ 'data' ]\
        [ 'extensions' ][ key_share_index ][ 'extension_data' ]\
        [ ks_designation ] = key_share_entry  

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
      if self.msg_list[ 0 ][ 'msg_type' ] == 'server_hello':
        sh_index = 0
      else:
        ch_index = self.latest_client_hello_index( )
        sh_index = ch_index + 1
      self.cipher_suite = self.msg_list[ sh_index ][ 'data' ][ 'cipher_suite' ]
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

    transcript = self.transcript.copy() 
    msg_bytes = bytearray()
    for msg in self.msg_list :  
      msg_bytes.extend( Handshake.build( msg ) ) 
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
          'certificate_verify',  'finished', 'certificate' ], 
        ## c_init_client_finished 
        [ 'end_of_early_data', 'certificate' ],
        [ 'certificate'], 
        ['server_hello', 'encrypted_extensions', 'certificate_request',\
         'certificate', 'certificate_verify', 'finished', 'certificate'] ]:
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
        ## c_client_finished
        [ 'server_hello', 'encrypted_extensions', 'certificate_request', 'certificate', 'certificate_verify', 'finished' ], \
        [ 'server_hello', 'encrypted_extensions', 'certificate', 'certificate_verify', 'finished' ], \
        [ 'server_hello', 'encrypted_extensions', 'finished' ], \
        [ 'encrypted_extensions', 'certificate_request', 'certificate', 'certificate_verify', 'finished' ], \
        [ 'encrypted_extensions', 'certificate', 'certificate_verify', 'finished' ], \
        [ 'encrypted_extensions', 'finished' ], \
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
     transcript = self.transcript_r
    elif transcript_type == 'post_hand_auth_sig' :
      transcript = self.post_hand_auth_transcript( )
    else :
      transcript = self.append_transcript( upper_msg_index )
      if transcript_type == 'r' :
        self.transcript_r = transcript
    return transcript 

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
    self.secrets = { 'b' : None, 'e_s' : None, 'e_x' : None,\
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
    if 'e_s' in secret_list or  'e_x' in secret_list:
        
      transcript_h = handshake.transcript_hash( 'e' )
      if 'e_s' in secret_list:
        self.secrets[ 'e_s' ] = \
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
    if self.handshake.is_early_data_proposed( ) is False :
      req[ 'secret_request' ][ 'e_s' ] = False
    ## the binary format of the ticket 
    psk_identity = self.handshake.get_ticket( req[ 'selected_identity' ] )
    self.session_ticket = SessionTicket( self.conf, psk_identity=psk_identity )
    ## to enable to check the server hello is conformed with the ticket in used. 
    self.session_ticket.selected_identity = req[ 'selected_identity' ] 
    self.session_ticket.init_handshake( self.handshake )
    self.secret_request = SecretReq(req[ 'secret_request' ], \
                          self.mtype, self.conf, handshake=self.handshake )
    ## only to store the client ephemeral that will be used in 
    ## SHandAndAppSecret exchange
    self.ephemeral = None
    if self.handshake.is_ks_proposed( ) is True:
      self.ephemeral = Ephemeral( {}, self.mtype, self.conf, self.handshake )
    self.scheduler = KeyScheduler( self.session_ticket.tls_hash, \
                                   psk=self.session_ticket.psk, is_ext=False)
#    self.last_exchange = None 
    self.session_id = SessionID( req[ 'session_id' ] )
    self.scheduler.process( self.secret_request.of([ 'b', 'e_s', 'e_x' ] ), self.handshake )
    self.resp = { 'session_id' : self.session_id.cs,
             'secret_list' : self.secret_request.resp( self.scheduler ) }
#    return  { 'session_id' : self.session_id.resp( ),
#              'secret_list' : self.secret_request.resp( self.scheduler ) }

class SHandAndAppSecretReq: 

  def __init__( self, req, tls13_conf, handshake, scheduler, session_id,\
                session_ticket, freshness, client_hello_ephemeral ):
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
    self.ephemeral = Ephemeral( req[ 'ephemeral' ], self.mtype, self.conf,\
                                self.handshake, client_hello_ephemeral )
      
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
    """ check the message type is expected """
    error = True
    if status == 'request':
      error = False 
    if self.next_mtype is None and 'init' in mtype :
      error = False
    if isinstance( self.next_mtype, str ):
      if mtype == self.next_mtype:
        error = False
    elif isinstance( self.next_mtype, list ):
      if mtype in self.next_mtype:
        error = False

    if error is True:
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
      self.ephemeral = req.ephemeral
    elif mtype == 's_hand_and_app_secret':
      req = SHandAndAppSecretReq( payload, self.conf, self.handshake,\
              self.scheduler, self.session_id, self.session_ticket, \
              self.freshness, self.ephemeral )
      self.last_exchange = req.tag.last_exchange
    else: 
      raise LURKError( 'invalid_request', f"unexpected request {mtype}"\
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
    if server_cert.cert_type != 'no_certificate' : 
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
    self.next_mtype = [ 'c_server_hello', 'c_client_finished' ]
   
    self.handshake = TlsHandshake( 'client', self.conf )
    self.handshake.msg_list.extend( req[ 'handshake' ] )
    self.handshake.update_random( Freshness( req[ 'freshness' ] ) )
    ## keyshare
    self.ephemeral = Ephemeral( { 'method' : 'cs_generated' }, self.mtype, \
      self.conf, self.handshake )
    print( f"client_shares {self.ephemeral.client_shares} " )
    self.handshake.update_key_share( self.ephemeral.client_shares )
    ## pre-shared-key extension
    secret_list = []
    binder_key_list = []
    ## the dictionaries are only filled when PSK are proposed and 
    ## hosted by the CS.
#    self.session_ticket_dict = {}
    self.scheduler_list = []
    psk_metadata_list = req[ 'psk_metadata_list' ]
    print( f"-- CInitClientHelloReq {self.handshake.msg_list}" )
    print( f"-- psk_metadata_list {psk_metadata_list}" )
    self.handshake.is_post_hand_auth_proposed( )
    if self.handshake.is_psk_proposed( ) is True:
      self.scheduler_list = self.update_binders( psk_metadata_list )
      binder_key_list = [ { 'secret_type' : 'b', 'secret_data' : ks.secrets[ 'b' ] } for ks in self.scheduler_list  ]
      secret_request = SecretReq( req[ 'secret_request' ] , self.mtype, self.conf, \
                       handshake=self.handshake )
      ## we need to provide the hash function because handshake 
      ## define the hash fcuntion from the ciphersuite. The ciphersuite 
      ## is in the serverHello
      ks = self.scheduler_list[ 0 ]
      h_name = ks.tls_hash.hashmod.__name__
      if h_name == 'openssl_sha256':
        tls_hash = SHA256()
      elif h_name == 'openssl_sha384':
        tls_hash = SHA384()
      elif h_name == 'openssl_sha512':
        tls_hash = SHA512()
      self.handshake.transcript = Hash( tls_hash )
      ks.process( secret_request.of( [ 'e_s', 'e_x' ] ), self.handshake )
      secret_list = secret_request.resp( ks ) 
      print( f"secret_list : {secret_list}" )
      self.handshake.transcript = None

    self.session_id = SessionID( req[ 'session_id' ] )
    self.resp = { 'session_id' : self.session_id.cs,
                  'ephemeral_list' : self.ephemeral.resp,
                  'binder_key_list' : binder_key_list,
                  'secret_list' : secret_list }

  def update_binders( self, psk_metadata_list ):
    """ 
    Firstly it computes all binder_keys from a partial client_hello. Then, 
    it computes the binders and early secrets. 
    """
    offered_psk = self.get_offered_psks( )
    sha256_0 = b''
    for i in range( 32 ):
      sha256_0 += b'\x00'
    sha384_0 = b''
    for i in range( 48 ):
      sha384_0 += b'\x00'
    sha512_0 = b''
    for i in range( 64 ):
      sha512_0 += b'\x00'

    if len( psk_metadata_list ) > 0:
      current_meta = psk_metadata_list.pop( 0 )
    else :
      current_meta = None
    binder_list = []
    scheduler_list = []
    binder_len = 0
    for psk_identity in offered_psk[ 'identities' ] :
      ## check ther is metada associated to that psk
      metadata_match = False
      if current_meta is not None:
        psk_identity_index = offered_psk[ 'identities' ].index( psk_identity )   
        if current_meta[ 'identity_index' ] == psk_identity_index :
          metadata_match = True
          psk_bytes = current_meta[ 'psk_bytes' ]
          tls_hash = current_meta[ 'tls_hash' ]
          psk_type = current_meta[ 'psk_type' ]
          if len( psk_metadata_list ) > 0:
            current_meta = psk_metadata_list.pop( 0 )
          else: 
            current_meta = None
      ## no metadata matches 
      ## generates ticket from identity 
      if metadata_match is False :
        session_ticket = SessionTicket( self.conf, psk_identity=psk_identity )
        psk_bytes = self.session_ticket.psk
        tls_hash = self.session_ticket.tls_hash
        psk_type = 'resumption'
      ## updating binders 
      if tls_hash == 'sha256' : 
        binder_list.append(  { 'binder' : sha256_0 } )
        tls_hash = SHA256()
      elif tls_hash == 'sha384' : 
        binder_list.append(  { 'binder' : sha384_0 } )
        tls_hash = SHA384()
      elif tls_hash == 'sha512' : 
        binder_list.append(  { 'binder' : sha512_0 } )
        tls_hash = SHA512()
      binder_len += 2 + len( binder_list[ -1 ] )
      if psk_type == 'resumption' :
        is_ext = False
      elif psk_type == 'external' :
        is_ext = True
      ks = KeyScheduler( tls_hash, psk=psk_bytes, is_ext=is_ext )
      ## building binder_keys
      secret_req = {} 
      for k in [ 'e_s', 'e_x', 'h_c', 'h_s', 'a_c', 'a_s', 'x', 'r' ]:
        secret_req[ k ] = False
      secret_req[ 'b' ] = True
      binder_request = SecretReq( secret_req, self.mtype, self.conf, \
        handshake=self.handshake )
      ks.process( binder_request.of( [ 'b' ] ), self.handshake )
      scheduler_list.append( ks ) 
    
    ## building the partial client hello 
    self.handshake.msg_list[ -1 ][ 'data' ][ 'extensions' ][ -1 ][  'extension_data'] [ 'binders' ] = binder_list  
    partial_client_hello_bytes = b''
    for msg in self.handshake.msg_list:
      last_ext = msg[ 'data' ][ 'extensions' ][ -1 ]
      partial_client_hello_bytes += Handshake.build( msg )
    partial_client_hello_bytes = partial_client_hello_bytes[ : -binder_len ]
    binder_list = []
    ## building all binder_key and binders
    for psk_identity in offered_psk[ 'identities' ] :
      psk_identity_index = offered_psk[ 'identities' ].index( psk_identity )   
      ks = scheduler_list[ psk_identity_index ]
      binder_key = ks.secrets[ 'b' ] 
      binder = ks.tls_hash.verify_data( binder_key, partial_client_hello_bytes )
      binder_list.append( { 'binder' : binder } ) 
    ch_index = self.handshake.latest_client_hello_index( )
    self.handshake.msg_list[ ch_index ][ 'data' ][ 'extensions' ][ -1 ][  'extension_data'] [ 'binders' ] = binder_list 
    return scheduler_list 

  def get_offered_psks( self ):
    """ returns the OfferedPSK structure in the ClientHello """
    ch_index = self.handshake.latest_client_hello_index( )
    last_ext = self.handshake.msg_list[ ch_index][ 'data' ][ 'extensions' ][ -1 ]
    if last_ext[ 'extension_type' ] == 'pre_shared_key' :
      return last_ext[ 'extension_data' ]
    return []

class CServerHelloReq:

  def __init__(self, req, tls13_conf, handshake, client_hello_ephemeral,\
               scheduler_list, session_id ):
    self.conf = tls13_conf
    self.mtype = 'c_server_hello'
    self.next_mtype = 'c_client_finished'

    self.handshake = handshake
    self.handshake.msg_list.extend( req[ 'handshake' ] )
    self.handshake.sanity_check( self.mtype )
    secret_req = { 'h_s' : True, 'h_c' : True } 
    for k in [ 'b', 'e_s', 'e_x', 'a_c', 'a_s', 'x', 'r' ]:
      secret_req[ k ] = False
    secret_request = SecretReq( secret_req, self.mtype, self.conf, \
                                handshake=self.handshake )
    ephemeral = Ephemeral( req[ 'ephemeral' ], self.mtype, \
                                self.conf, self.handshake )
    ephemeral.compute_client_share_secret( client_hello_ephemeral )
    print("-- ephemeral.shared_secret {ephemeral.shared_secret}" )
    if self.handshake.is_psk_agreed( ):
      pre_shared_key = self.handshake.msg_list[ 0 ][ 'data' ][ 'extensions' ][ -1 ]
      if pre_shared_key[ 'extension_type' ] != 'pre_shared_key' :
        raise LURKError( 'invalid_handshake', f"Expecting pre_shared_key "\
                         f"extention {pre_shared_key}" )
      print( f"--- pre_shared_key: {pre_shared_key}" )
      selected_identity = pre_shared_key[ 'extension_data' ]
      self.scheduler = scheduler_list[ selected_identity ] 
    else: 
      self.scheduler = KeyScheduler( self.handshake.get_tls_hash(), \
                                     ecdhe=ephemeral.shared_secret )
    self.scheduler.process( [ 'h_c', 'h_s' ], self.handshake )
    self.session_id = session_id

    self.resp = { 'session_id' : session_id.e, 
                  'secret_list' : secret_request.resp( self.scheduler ) }

class CClientFinishedReq:

  def __init__(self, req, tls13_conf, handshake, scheduler, session_id ):
    self.conf = tls13_conf
    self.mtype = 'c_client_finished'
    self.next_mtype = [ 'c_post_hand_auth', 'c_register_ticket' ]
    ## scheduler is None when not being selected during the c_server_hello
    ## This means that only the certificate verify (signature) is generated
    self.scheduler = scheduler
    self.handshake = handshake
    self.handshake.msg_list.extend( req[ 'handshake' ] )
    self.handshake.sanity_check( self.mtype )
    self.tag = Tag( req[ 'tag' ], self.mtype, self.conf, ctx=self.handshake )
    server_cert = LurkCert( req[ 'server_certificate' ], self.mtype, self.conf, \
                    True, self.handshake )
    client_cert = LurkCert( req[ 'client_certificate' ], self.mtype, self.conf, \
                    False, self.handshake )
    if server_cert.cert_type != 'no_certificate' : 
      self.handshake.update_certificate( server_cert, server=True )
    ## scheduler is initialized in CServerHello and CServerHello
    ## may be skipped when the client knows PSK and ECDHE secrets
    ## In this situation, the sheduler is not needed.
    if self.scheduler is None: ## we need to initialize transcript
      print( f"-- {self.handshake.msg_type_list()}" )
      self.handshake.transcript = Hash( self.handshake.get_tls_hash() )
    else:  
      self.scheduler.process( [ 'a_c', 'a_s' ], self.handshake )
    self.handshake.update_certificate( client_cert, server=False )
    print( f"client cert inserted : {self.handshake.msg_type_list()}" ) 
    self.handshake.update_certificate_verify( )
    ## get sig from freshly generated certificate_verify 
    sig = self.handshake.msg_list[ 0 ][ 'data' ]['signature' ]
    ## generating Finished message and generating the transcript of the full handshake
    if self.tag.last_exchange == False:
      self.handshake.update_server_finished( self.scheduler )
      self.scheduler.process( [ 'r' ], self.handshake )
    self.resp = { 'tag' : self.tag.resp,
                  'session_id' : session_id.cs,
                  'signature' : sig }


class CRegisterTicketsReq:

  def __init__( self, req, tls13_conf, ticket_db, transcript_r:bytes,\
                cipher_suite:str, tls_hash, ticket_counter, session_id ):
    self.conf = tls13_conf
    self.mtype = 'c_register_tickets'
    self.next_mtype = [ 'c_post_hand_auth', 'c_register_ticket' ]

    self.ticket_counter = ticket_counter
    self.tag = Tag( req[ 'tag' ], self.mtype, self.conf, ctx=self.ticket_counter )
    for new_session_ticket in req[ 'ticket_list' ]:
      self.ticket_counter += 1
      if self.ticket_counter > self.conf[ 'max_tickets' ]:
        raise LURKError( 'max_tickets_reached' )
      psk = tls_hash.hkdf_expand_label( transcript_r, b"resumption", \
                                        new_session_ticket[ 'ticket_nonce' ],\
                                        tls_hash.hash_len )
      ticket = new_session_ticket[ 'ticket' ]
      
      ticket_db.register( ticket, { 'new_session_ticket' : new_session_ticket, 
                                   'psk' : psk,
                                   'cipher_suite' : cipher_suite } )
    self.resp = { 'tag' : self.tag.resp,
                  'session_id' : session_id.cs }

class CSession(SSession) :

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
      self.handshake = req.handshake
      self.session_id = req.session_id
      self.ephemeral = req.ephemeral
      self.scheduler_list = req.scheduler_list
    elif mtype == 'c_server_hello' :
      req = CServerHelloReq( payload, self.conf, self.handshake, self.ephemeral,\
                             self.scheduler_list, self.session_id )
      self.handshake = req.handshake
      self.scheduler = req.scheduler
    elif mtype == 'c_client_finished' :
      req = CClientFinishedReq( payload, self.conf, self.handshake, self.scheduler,\
                             self.session_id )
      ## saving context for the register_tickets
      self.transcript_r = req.handshake.transcript_r
      self.cipher_suite = req.handshake.cipher_suite
      ## the scheduler is set to None when the TLS client knwos both PSK and 
      ## ECDHE shared secret. In that case, last_exchange MUST be set to True
      if req.scheduler is not None:
        self.tls_hash = req.scheduler.tls_hash
      self.last_exchange = req.tag.last_exchange
      self.ticket_counter = 0
    elif mtype == 'c_register_tickets' :
      req = CRegisterTicketsReq( payload, self.conf, self.ticket_db,\
              self.transcript_r, self.cipher_suite, self.tls_hash,\
              self.ticket_counter, self.session_id )
      self.ticket_counter = req.ticket_counter
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

class TicketDB:

  def __init__( self ):
    self.db = {}

  def register( self, ticket, full_ticket_context ):
    
    self.db[ ticket ] = full_ticket_context

class Tls13Ext:
  def __init__(self, conf=default_conf, ticket_db=None, session_db=None ):
    if session_db is None:
      self.session_db = SessionDB()
    else: 
      self.session_db = session_db
    if ticket_db is None:
      self.ticket_db = TicketDB()
    else: 
      self.ticket_db = ticket_db
    self.conf = conf 
  
  def payload_resp( self, req:dict ) -> dict :
      req_type = req[ 'type' ]
      req_payload = req[ 'payload' ]
#      if req_type in [ 's_init_early_secret', 's_init_cert_verify' ]:
      if 'init' in req_type : #in [ 's_init_early_secret', 's_init_cert_verify' ]:
        if req_type[ :7 ] == 's_init_': 
          session = SSession( self.conf, session_db=self.session_db,\
                              ticket_db=self.ticket_db )
        elif req_type[ :7 ] == 'c_init_' : 
          session = CSession( self.conf, session_db=self.session_db,\
                              ticket_db=self.ticket_db  )
        else:
          raise LURKError( 'invalid_type', f"{req_type}" )
        print( f" --- reqq: {req}" )
        payload  = session.serve( req_payload, req_type, 'request')
        if session.session_id != None :
          self.session_db.store( session ) 
#      elif req_type in [ 's_hand_and_app_secret', 's_new_ticket' ]:
      else :
        try:
          session = self.session_db.unstore( req_payload[ 'session_id' ] )
        except KeyError:
          raise LURKError( 'invalid_session_id', f"{req} session_id not found in DB" )
        payload = session.serve( req_payload, req_type, 'request' )
      if session.last_exchange is True:
        self.session_db.delete( session )          
      return payload
  
