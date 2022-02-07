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
from conf import default_conf, SigScheme
from lurk_lurk import LURKError, ImplementationError, ConfigurationError

import pkg_resources
data_dir = pkg_resources.resource_filename(__name__, '../data/')


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


def get_structs(l: list, key: str, value) -> list :
  """ return the list of structures that contains  key:value """
  sub_list = []
  for e in l:
    if e['key'] == value:
      sub_list.append(e)
  return sub_list

class Tag:

  def __init__( self, tag:dict, mtype, tls13_conf ):
    self.last_exchange = tag[ 'last_exchange' ]
    self.conf = tls13_conf
    self.mtype = mtype

  def resp( self, ctx=None ):
    last_exchange = self.last_exchange
    if self.mtype in [ 's_init_cert_verify', 's_hand_and_app_secret' ]:
      last_exchange = self.conf[ 'last_exchange' ][ self.mtype ]
    elif self.mtype == 's_new_ticket':
      if ctx >= self.conf[ 'max_tickets' ]:
        last_exchange = True
    elif self.mtype == [ 'c_post_hand_auth' ]:
      if ctx >= self.conf[ 'max_post_handshake_authentication' ]:
        last_exchange = True

    return { 'last_exchange' : last_exchange }


class Ephemeral:

  def __init__(self, ephemeral:dict, mtype, tls13_conf, handshake=None,\
               ephemeral_method=None ) -> None:
    """ initializes the object based on the structure """

    self.struct = ephemeral
    self.conf = tls13_conf
    self.mtype = mtype
    self.method = self.struct['ephemeral_method']

    error = False
    if self.method not in self.conf['ephemeral_method_list']:
      raise LURKError( 'invalid_ephemeral', f"method {self.method} expected to be"\
                       "in {self.conf['ephemeral_method_list']}" )
    if ( mtype == 's_init_cert_verify' and self.method == 'no_secret' ) or\
       ( mtype == 'c_init_ephemeral' and self.method != 'cs_generated' ) or\
       ( mtype == 'c_init_early_secret' and self.method == 'e_generated' ):
      raise LURKError( 'invalid_ephemeral', f"Incompatible {self.method} and {mtype}" )
    elif ( mtype == 's_hand_and_app_secret' and self.method == 'no_secret' ):
      if handshake.is_ks_agreed() :
        raise LURKError( 'invalid_ephemeral', f"unexpected key_share extension with 'no_secret'" )
    elif  mtype == 'c_hand_and_app_secret' :
     if handshake.has_ext( 'psk', 'proposed' ) == False: ## c_init_ephemeral
       if self.method != 'no_secret':
         error = True
     else: ## c_init_early_secret
       if  ( self.ephemeral_method == 'cs_generated' and self.method != 'no_secret' ) or\
           ( self.ephemeral_method == 'no_secret' and self.method != 'cs_generated'):
         error = True 
    if error == True:
      raise LURKError( 'invalid_ephemeral', \
              f"unsupported ephemeral method {ephemeral}" \
              f"not in {self.conf[ 'ephemeral_method_list' ]}" )
    self.server_key_exchange = None
    self.shared_secret = None 
      
  def compute_server_key_exchange(self, handshake ):
    """ treat ephemeral extension and initializes self.ecdhe, self.server_key_exchange """ 
    if self.method == 'shared_secret':
      ## makes more sense if only one secret is sent, not a list
      self.shared_secret = self.struct['key'][ 'shared_secret' ]
    elif self.method == 'cs_generated':
      ## key_shae is taken in the serverhello to make sure the extension
      ## is in the same place. Note that inserting the extension
      ## may require to update all length.
      print( handshake.msg_type_list() )  
      ch_index = handshake.latest_client_hello_index( )
      server_hello_exts = handshake.msg_list[ ch_index +1 ][ 'data' ][ 'extensions' ]
      server_key_share = get_struct(server_hello_exts, 'extension_type', 'key_share' )
      self.group = server_key_share[ 'extension_data' ][ 'server_share' ][ 'group' ]
      client_hello_exts = handshake.msg_list[ ch_index][ 'data' ][ 'extensions' ]
      client_key_share = get_struct(client_hello_exts, 'extension_type', 'key_share' )
      client_shares = client_key_share[ 'extension_data' ][ 'client_shares' ]
      client_key_exchange = get_struct(client_shares, 'group', self.group)
       
      if self.group not in self.conf[ 'authorized_ecdhe_group' ]:
        raise LURKError( 'invalid_ephemeral', f"unsupported {self.group}" )

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
          client_public_key = X448PublicKey.from_public_bytes(client_public_key) 
        server_public_key = server_private_key.public_key() 
        self.server_key_exchange = server_public_key.public_bytes(
          encoding=Encoding.Raw, format=PublicFormat.Raw)
        self.shared_secret = server_private_key.exchange(client_public_key)

  def resp( self):
    resp = { 'ephemeral_method' : self.method }
    if self.method == 'cs_generated' :
      key = { 'group' : self.group, \
              'key_exchange' : self.server_key_exchange }
    elif self.method in [ 'no_secret', 'e_generated' ]: 
      key = None
    resp[ 'key' ] = key 
    return resp

class SessionID:
  def __init__( self, session_id:bytes, mtype):
    self.outbound =  session_id
    self.inbound = token_bytes( 4  )
    self.mtype = mtype

  def resp ( self, tag_resp=None ):
    if self.mtype in [ 's_init_cert_verify', 'c_init_post_hand_auth' ] :
      if tag_resp == True: ## tag value in the request
        resp = None
      else:
        resp =  self.inbound
    elif self.mtype == 's_init_early_secret':
        resp =  self.inbound
    else:
      resp = self.outbound
    return resp

  def update( self, mtype):
    self.mtype = mtype

  def is_in_session( self, mtype, status, session_id:bytes ):
    """ checks the session_id 

    Checks the value is aligned with the sessionID object of the session 
    """      
    if status == 'request':
      if session_id != self.inbound:
        raise LURKError( 'invalid_session_id',  
                f"unknown {session_id} inbound:{self.inbound}" )
    elif status == 'request':
      if session_id != self.outbound:
        raise LURKError( 'invalid_session_id',  
                f"unknown {session_id} outbound:{self.outbound}" )
    self.mtype = mtype
    return True

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
    
class SecretReq:

  def __init__( self, secret_request:dict, mtype, tls13_conf, handshake=None ):
    print( f"SecretReq init start {secret_request}")

    self.conf = tls13_conf
    if mtype in [ 's_init_early_secret', 'c_init_early_secret' ]:
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
    self.hs_cert_msg = \
      { 'msg_type' : 'certificate',
        'data' :  { 'certificate_request_context': b'',
                    'certificate_list' : self.conf[ '_cert_list' ] } }
    self.cert_finger_print = self.conf[ '_cert_finger_print' ]
    self.cert_type =  self.conf[ '_cert_type' ]
    self.private_key = self.conf[ '_private_key' ]
    ## list of structures representing the TLS handshake messages
    self.msg_list = []
    self.cipher_suite = None 
    self.transcript = None

  def post_post_hand_auth( self ):
    """ removes the CertificateRequest, Certificate and CErtificateVerify """
    self.msg_list = self.msg_list[ :-3] 
    self.update_msg_type_index()

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

  def is_psk_proposed( self )->bool :
    """ return True if self.msg_list has proposed PSK, False otherwise """
    ch_index = self.latest_client_hello_index()
    ext_list = []
    for ext in self.msg_list[ ch_index ][ 'data' ][ 'extensions' ] :
      ext_list.append( ext[ 'extension_type' ] )
    if 'pre_shared_key' in ext_list  and  'psk_key_exchange_modes' in ext_list :
      return True
    return False

  def is_psk_agreed( self ) -> bool :
    """ return True is PSK has been agreed, False otherwise """
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
    if 'pre_shared_key' in ext_list :
      psk_agree = True
    else: 
      psk_agree = False
    return psk_agree
    
  def is_ks_proposed( self )->bool :
    """ return True if a key share extension is in the client_hello """
    ch_index = self.latest_client_hello_index()
    ext_list = []
    for ext in self.msg_list[ ch_index ][ 'data' ][ 'extensions' ] :
      ext_list.append( ext[ 'extension_type' ] )
    if 'key_share' in ext_list :
      return True
    return False

  def is_ks_agreed( self ) -> bool :
    """ return True if a key_share extension is in the server hello """   
    ## when self,msg_list starts with serverhello: 
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
    if 'key_share' in ext_list :
      ks_agree = True
    else: 
      ks_agree = False
    return ks_agree
    
  def sanity_check( self, mtype, session_ticket=None ):
    """ checks if the handshake is compatible with the lurk exchange """
    error_txt = ""
    if mtype == 's_init_cert_verify':
      if self.is_psk_agreed() == True or self.is_ks_proposed == False or\
         self.is_ks_agreed == False:
        raise LURKError('invalid_handshake', f"expecting ks_agreed and non psk_aghreed {self.msg_list}" ) 
    elif mtype == 's_new_ticket' :
      pass
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
      
      if type( SigScheme( self.cipher_suite ).get_hash() ) != type( session_ticket.tls_hash ) :
        raise LURKError( 'invalid_handshake', f"TLS handshake cipher "\
                f"suite {self.get_cipher( )} and ticket cipher suites "\
                f"are not compatible {session_ticket.cipher}" )
    elif mtype == 'c_init_cert_verify':
      if self.has_ext( 'psk', 'agreed' ) == True:
        error_txt += "psk agreed"
      if self.has_ext( 'key_share', 'agreed' ) == False:
        error_txt += "key_share not agreed"
      if self.msg( 'certificate_request' ) == None:
        error_txt += "no certificate_request"
    elif mtype in [ 'c_init_post_hand_auth', 'c_post_hand_auth' ]:
      if self.has_ext( 'post_handshake_auth', 'proposed' ) == False:
        error_txt += "post_handshake_auth missing"
      client_finished_i = self.msg_i( 'finished' )[1] 
      if self.msg_i( 'certificate_request' )[ -1 ] <= client_finished_i:
        error_txt += "certificate_request (after client finished) missing" 
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
    role = self.role
    if role == 'server' : ## updating server_hello
      if self.msg_list[0][ 'msg_type' ] == 'client_hello':
        ch_index = self.latest_client_hello_index( )
        sh_index = ch_index + 1
      elif  self.msg_list[0][ 'msg_type' ] == 'server_hello' :
        sh_index = 0
      else:
        raise ImplementationError( f"Expecting handshake starting with" \
                f"client_hello or server_hello {self.msg_list}" )
      engine_random = self.msg_list[ sh_index ] [ 'data' ][ 'random' ]
      server_random = freshness.update_random( role, engine_random )
      self.msg_list[ sh_index ] [ 'data' ][ 'random' ] = server_random
    elif role == 'client':
      ch_index_list = [ 0 ]
      if ch_index != 0: ## presence of an hello retry
        ch_index_list.append( ch_index )
      engine_random = self.msg_list[ 0 ] [ 'data' ][ 'random' ]
      client_random = freshness.update_random( role, engine_random )
      for ch_index in ch_index_list :
        self.msg_list[ sh_index ] [ 'data' ][ 'random' ] = client_random
    else:
        raise ImplementationError( f"unknown role {self.role}" )

  def update_key_share( self, server_key_exchange ) -> NoReturn:
    """ update key_exchange value of the CLientHello or ServerHello  """
    if self.role == 'server':
      # update occurs in the server_hello
      if self.msg_list[ 0 ][ 'msg_type' ] == 'client_hello' :
        ch_index = self.latest_client_hello_index( )
        index = ch_index + 1
      elif self.msg_list[ 0 ][ ' msg_type' ] == 'server_hello' :
        index = 0
    elif self.role == 'client':
      # update the 'client_hello'
      index = self.latest_client_hello_index( )
    else:
      raise ImplementationError( f"unknown role {self.role}" )

    exts = self.msg_list[ index][ 'data' ][ 'extensions' ] 
    key_share = get_struct( exts, 'extension_type', 'key_share' )
    key_share_index = exts.index( key_share )
    
    self.msg_list[ index ][ 'data' ]\
      [ 'extensions' ][ key_share_index ][ 'extension_data' ]\
      [ 'server_share' ][ 'key_exchange' ] = server_key_exchange  


  def update_certificate( self, lurk_cert:dict ):
    """ build the various certificates payloads """
    
    if lurk_cert[ 'certificate_type' ] == 'no_certificate' : 
      raise LURKError( 'invalid_certificate', f"no valid PSK/ECDHE "
            f"authentication with empty certificate" )
    elif lurk_cert[ 'certificate_type' ] == 'uncompressed' :
      hs_cert_msg = { 'msg_type' : 'certificate', 
               'data' : lurk_cert[ 'certificate_data' ] }    
    elif lurk_cert[ 'certificate_type' ] == 'compressed' :
      hs_cert_msg = 'XXX'
    elif lurk_cert[ 'certificate_type' ] == 'finger_print' :
      if lurk_cert[ 'certificate_data' ] != self.cert_finger_print :
        raise LURKError( 'invalid_certificate', \
                f"fingerprint {self.cert_finger_print} npot matching conf " \
                f"{sel.tls13_onf[ '_cert_finger_print' ] }" )
      hs_cert_msg = self.conf[ '_hs_certificate' ]
    else: 
      raise ImplementationError( "unable to generate certificate message" )
    self.msg_list.append( hs_cert_msg )

  def update_certificate_verify( self, sig_scheme ) :
    """ update the handshake with the CertificateVerify """ 
    string_64 = bytearray()
    for i in range(64):
      string_64.extend(b'\20')
    if self.role == 'server':
      ctx_string = b'server: TLS 1.3, server CertificateVerify'
      transcript_h = self.transcript_hash( 'sig' )
    elif self.role == 'client':
      ctx_string = b'client: TLS 1.3, client CertificateVerify'
      if len( self.msg_i( 'finished' ) ) == 1 :
        handshake_ctx = self.ctx( 'client_certificate_verify' ) 
      elif len( self.msg_i( 'finished' ) ) == 2 :
        handshake_ctx = self.ctx( 'post_handshake_auth' ) 
      else: 
        raise ImplementationError( f"{self.msg_i} unexpected number of finished messages" )
    else:
        raise ImplementationError( f"unknown role {self.role}" )
    content = bytes( string_64 + ctx_string + b'\x00' + transcript_h )

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
    return SigScheme( self.get_cipher_suite() ).get_hash() 
       
  def append_transcript( self, upper_msg_index:int=None  ):
    """ provides the transcript of all or up to msg_index (excluded) """
    ## for server we can read it from the configuration file.
    ## this does not considers the case of the client in which 
    ## case we will have to read it from the handshake
    ## problem may arise when different format are used between 
    ## the client and the server. 
    ctx_struct = { '_certificate_type': self.cert_type }
    ## finished message needs the _cipher to be specified
    if 'server_hello' in self.msg_type_list() :
      ctx_struct[ '_cipher' ] = self.get_cipher_suite()

    if upper_msg_index is None:
      msg_list = self.msg_list[ : ]
      del self.msg_list[ : ]
    else:
      msg_list = self.msg_list[ : upper_msg_index ]
      del self.msg_list[ : upper_msg_index ]
    print( f"msg_list {msg_list}" )
    msg_bytes = bytearray()
    for msg in msg_list :  
      msg_bytes.extend( Handshake.build( msg, **ctx_struct ) ) 
    self.transcript.update( msg_bytes )
    transcript = self.transcript.copy()
    return transcript.finalize()

  def transcript_hash( self, transcript_type ) -> bytes:
    """ return the Transcript-Hash output for the key schedule 

    Performing the hash in the handshake class prevent the 
    handshake class to keep all exchanges.       
    """
    print("begining transcript_hash")
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
        raise ImplementationError( f"unexpected handshake {self.msg_list}" )
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
        [ 'encrypted_extensions', 'certificate_request', 'certificate' ] ] :
        raise ImplementationError( f"unexpected handshake {self.msg_list}" )
    elif transcript_type == 'finished' :
      if self.msg_type_list( ) not in [ \
        ## 's_init_cert_verify'
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
        raise ImplementationError( f"unexpected handshake {self.msg_type()}" )
    elif transcript_type == 'r' : 
      if self.msg_type_list( ) not in [ \
        ## 's_new_ticket'
        [ 'finished' ], \
        [ 'certificate', 'certificate_verify', 'finished' ] ] :
        raise ImplementationError( f"unexpected handshake {self.msg_type_list()}" )
    elif transcript_type == 'e' :
      print( self.msg_type_list( ))
      if self.msg_type_list( ) not in [ \
        ## 's_init_early_secret'
        [ 'client_hello' ], \
        [ 'client_hello', 'server_hello', 'client_hello' ] ] :
        raise ImplementationError( f"unexpected handshake {self.msg_type_list()}" )
    else: 
          raise ImplementationError( f"Unexpected {transcript_type}" )
    print( "starting append_transcript" )
    return self.append_transcript( upper_msg_index )

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

  def update_binders( self, scheduler_list ):
    binders = []
    msg = self.hs_client_hello_to_partial()
    for scheduler in scheduler_list :
      binders.append( scheduler.tls_hash.verify_data( scheduler.secrets[ 'b' ], msg ) )
    client_hello_exts = self.msg( 'client_hello' )[ 'extensions' ]
    pre_shared_key = get_struct(client_hello_exts, 'extension_type', 'pre_shared_key' )
    pre_shared_key_i = client_hello_exts.index( pre_shared_key )
    self.msg_list[ self.msg_i( 'client_hello' )[ -1 ] ][ pre_shared_key_i ]['binders' ] = binders

  def hs_client_hello_to_partial( self ) -> bytes:
    client_hello_exts = self.msg( 'client_hello' )[ 'extensions' ]
    pre_shared_key = get_struct( client_hello_exts, 'extension_type', 'pre_shared_key' )
    binders = pre_shared_key[ 'extension_data' ][ 'binders' ]
    l = 0
    for binder in binders:
      l += len( binder )
    return HSClientHello.build( self.msg( 'client_hello' ) )[: -l ] 
    
    
  def hs_partial_to_client_hello ( self, bytes_client_hello ):
    """ makes HS partial ClientHello parsable. 

   fills the binders with zero bytes. The length is derived from 
   the difference between the received bytes and the indicated length.
   """
    ##session_ticket = SessionTicket( conf, psk_identity=psk_id ) )
    binders = bytearray( len( bytes_client_hello ) - int.from_bytes( bytes_client_hello[1:4] ) )## bytes 2, 3 and 4
    return Handshake.parse( bytes_client_hello + binders ) 
    


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
    self.tls_hash = SigScheme( self.cipher ).get_hash() 
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
    self.tls_hash = SigScheme( self.cipher ).get_hash()

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
   
    self.tag = Tag( req[ 'tag' ], self.mtype, self.conf )
    self.session_id = SessionID( req[ 'session_id' ], self.mtype )
    self.freshness = Freshness( req[ 'freshness' ] )
    self.ephemeral = Ephemeral( req[ 'ephemeral' ], self.mtype, self.conf )
    self.secret_request = SecretReq(req[ 'secret_request' ], self.mtype, self.conf )
    self.sig_algo = SigScheme( req[ 'sig_algo' ] )
    self.cert = req[ 'certificate' ]
    self.handshake = TlsHandshake( 'server', self.conf )
    self.handshake.msg_list.extend( req[ 'handshake' ] )
    self.handshake.sanity_check( self.mtype )
    self.handshake.update_random( self.freshness )
    self.scheduler = None
    self.last_exchange = None 
    self.next_mtype = 's_new_ticket'

  def resp( self ):
    self.ephemeral.compute_server_key_exchange( self.handshake ) 
    if self.ephemeral.method == 'cs_generated':
      self.handshake.update_key_share( self.ephemeral.server_key_exchange )
    self.scheduler = KeyScheduler( self.handshake.get_tls_hash(), \
                                   ecdhe=self.ephemeral.shared_secret )
    self.scheduler.process( self.secret_request.of([ 'h_c', 'h_s' ] ), self.handshake )
    self.handshake.update_certificate( self.cert )
    self.handshake.update_certificate_verify( self.sig_algo )
    ## get sig from freshly generated certificate_verify 
    sig = self.handshake.msg_list[ 0 ][ 'data' ]['signature' ] 
    self.handshake.update_server_finished( self.scheduler )
    self.scheduler.process( self.secret_request.of( [ 'a_c', 'a_s', 'x' ] ), self.handshake )
    tag_resp = self.tag.resp( )
    self.last_message  = tag_resp[ 'last_exchange' ]
    return { 'tag' : tag_resp,
             'session_id' : self.session_id.resp( tag_resp=tag_resp ),
             'ephemeral' : self.ephemeral.resp(),
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

    self.tag = Tag( req[ 'tag' ], self.mtype, self.conf )
    self.session_id = session_id
    self.session_id.update( self.mtype )
    self.session_id.is_in_session( self.mtype, 'request', req[ 'session_id' ])
    print( f" - init: {self.handshake.msg_list}")
    self.handshake.msg_list.extend( req[ 'handshake' ] )
    print( f" - initialized: {self.handshake.msg_list}")
    self.cert = req[ 'certificate' ]
    self.ticket_nbr = self.nbr( req[ 'ticket_nbr' ] )
    self.secret_request = SecretReq(req[ 'secret_request' ], self.mtype, self.conf )
    self.last_exchange = None 
    self.next_mtype = 's_new_ticket'
    self.ticket_list = []

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
  
  def resp( self ):
    self.scheduler.process( self.secret_request.of( [ 'r' ] ), self.handshake )
    tag_resp = self.tag.resp( ctx=self.ticket_counter )
    self.last_message  = tag_resp[ 'last_exchange' ]
    ticket = SessionTicket( self.conf ) 
    for t in range( self.ticket_nbr ):
      self.ticket_list.append( \
        ticket.new( self.scheduler, self.handshake.get_cipher_suite() ) )
    tag_resp = self.tag.resp( ctx=self.ticket_nbr )
    self.last_message  = tag_resp[ 'last_exchange' ]
    return { 'tag' : tag_resp,
             'session_id' : self.session_id.resp( tag_resp=tag_resp ),
             'secret_list' : self.secret_request.resp( self.scheduler ),
             'ticket_list' : self.ticket_list }

    
class SInitEarlySecretReq:

  def __init__( self, req, tls13_conf ):
    self.conf = tls13_conf
    self.mtype = 's_init_early_secret'
   
    self.session_id = SessionID( req[ 'session_id' ], self.mtype )
    self.freshness = Freshness( req[ 'freshness' ] )
    
    self.handshake = TlsHandshake( 'server', self.conf )
    self.handshake.msg_list.extend( req[ 'handshake' ] )
    self.handshake.sanity_check( self.mtype )
    ## the binary format of the ticket 
    psk_identity=self.handshake.get_ticket( req[ 'selected_identity' ] )
    self.session_ticket = SessionTicket( self.conf, psk_identity=psk_identity )
    ## to enable to check the server hello is conformed with the ticket in used. 
    self.session_ticket.selected_identity = req[ 'selected_identity' ] 
    self.session_ticket.init_handshake( self.handshake )
    self.secret_request = SecretReq(req[ 'secret_request' ], \
                          self.mtype, self.conf, handshake=self.handshake )
    self.scheduler = KeyScheduler( self.session_ticket.tls_hash, \
                                   psk=self.session_ticket.psk, is_ext=False)
    self.last_exchange = None 
    self.next_mtype = 's_hand_and_app_secret'

  def resp( self ):
    self.scheduler.process( self.secret_request.of([ 'b', 'e_c', 'e_x' ] ), self.handshake )
    return  { 'session_id' : self.session_id.resp( ),
              'secret_list' : self.secret_request.resp( self.scheduler ) }

class SHandAndAppSecretReq: 

  def __init__( self, req, tls13_conf, handshake, scheduler, session_id, session_ticket, freshness ):
    self.conf = tls13_conf
    self.mtype = 's_hand_and_app_secret'
    self.tag = Tag( req[ 'tag' ], self.mtype, self.conf )
    self.session_id = session_id
    self.session_id.update( self.mtype )
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
    self.next_mtype = 's_new_ticket'
      
    print("initialized SHandAndAppSecretReq")

  def resp( self ):
    self.ephemeral.compute_server_key_exchange( self.handshake ) 
    if self.ephemeral.method == 'cs_generated':
      self.handshake.update_key_share( self.ephemeral.server_key_exchange )
    self.scheduler.ecdhe = self.ephemeral.shared_secret 
    self.scheduler.process( self.secret_request.of( [ 'h_c', 'h_s'] ), self.handshake )
    self.handshake.update_server_finished( self.scheduler )
    self.scheduler.process( self.secret_request.of( [ 'a_c', 'a_s', 'x' ] ), self.handshake )
    tag_resp = self.tag.resp( )
    self.last_exchange  = tag_resp[ 'last_exchange' ]
    return { 'tag' : tag_resp,
             'session_id' : self.session_id.resp( tag_resp=tag_resp ),
             'ephemeral' : self.ephemeral.resp(),
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

  def save_session_ctx( self, req ):
    """ saves context for next messages"""
    if req.mtype in 's_init_cert_verify':
      self.scheduler = req.scheduler
      self.handshake = req.handshake
      self.session_id = req.session_id
      self.last_exchange = req.last_exchange
    elif req.mtype == 's_new_ticket':
      self.ticket_counter = req.ticket_counter 
      self.last_exchange = req.last_exchange
    elif req.mtype == 's_init_early_secret':
      self.scheduler = req.scheduler
      self.handshake = req.handshake
      self.session_id = req.session_id
      self.freshness = req.freshness
      self.session_ticket = req.session_ticket
    elif req.mtype == 's_hand_and_app_secret':
      self.last_exchange = req.last_exchange
    else: 
      raise ImplementationError( f"unknown mtype {req.mtype}" )
    self.next_mtype = req.next_mtype
    
  def is_expected_message( self, mtype, status ):
    if status != 'request':
      raise LURKError( 'invalid_request', "unexpected status {status}"\
              f"expecting 'request'" )
    if ( self.next_mtype == None and 'init' in mtype ) or\
       mtype == self.next_mtype:
      pass
    else: 
      raise LURKError( 'invalid_request', f"unexpected request {mtype} "\
              f"expecting {self.next_mtype} or initial request" )

  def serve( self, payload, mtype, status ):
    self.is_expected_message( mtype, status )
    if mtype == 's_init_cert_verify':
      
      req = SInitCertVerifyReq( payload, self.conf )
    elif mtype == 's_new_ticket':
      req = SNewTicketReq( payload, self.conf, self.handshake,\
              self.scheduler, self.session_id, self.ticket_counter )
    elif mtype == 's_init_early_secret':
      req = SInitEarlySecretReq( payload, self.conf )
    elif mtype == 's_hand_and_app_secret':
      req = SHandAndAppSecretReq( payload, self.conf, self.handshake,\
              self.scheduler, self.session_id, self.session_ticket, self.freshness )
    else: 
      raise LURKError( 'invalid_request', "unexpected request {mtype}"\
              f"expecting {self.next_mtype} or initial request" )
    resp = req.resp()
    self.save_session_ctx( req )
    return resp

class CInitCertVerify:

  def __init__(self, req, tls13_conf ):
    ## self.secret_req = secret_req 
    self.conf = tls13_conf
    self.mtype = 'c_init_cert_verify'
   
    self.freshness = Freshness( req[ 'freshness' ] )
    self.sig_algo = SigScheme( req[ 'sig_algo' ] )
    self.cert = req[ 'certificate' ]
    
    self.handshake = TlsHandshake( 'client',  self.conf )
#    self.handshake.insert( req[ 'handshake' ] )
    self.handshake.msg_list.extend( req[ 'handshake' ] )
    self.handshake.sanity_check( self.mtype )
    self.last_exchange = None 
    if self.conf[ 'post_handshake_authentication' ] == True:
      self.next_mtype = 'c_post_hand_auth'
    self.next_type = None

  def resp( self ):
    self.handshake.update_certificate( self.cert )
    self.handshake.update_certificate_verify( self.sig_algo )
    return { 'signature' : self.handshake.msg( 'certificate_verify' )[ 'signature' ] }



class CInitPostHandAuthReq:
 
  def __init__(self, req, tls13_conf ):
    self.conf = tls13_conf
    self.mtype = 'c_init_post_hand_auth'
   
    self.tag = Tag( req[ 'tag' ], self.mtype, self.conf )
    self.session_id = SessionID( req[ 'session_id' ], self.mtype )
    self.freshness = Freshness( req[ 'freshness' ] )
    self.sig_algo = SigScheme( req[ 'sig_algo' ] )
    self.cert = req[ 'certificate' ]
    
    self.handshake = TlsHandshake( 'client',  self.conf )
    self.handshake.msg_list.extend( req[ 'handshake' ] )
    self.handshake.sanity_check( self.mtype )
    cert_req_ctx = self.handshake.msg( 'certificate_request', ith=-1 )['certificate_request_context']  
    ## check why cert are generated
##    self.conf.load_cert( cert_req_ctx=cert_req_ctx )
    self.hs_cert_msg = { 'msg_type' : 'certificate',
                         'data' :  { 'certificate_request_context': cert_req_ctx,
                                     'certificate_list' : self.conf[ '_cert_list' ] } }

    self.last_exchange = None 
    if self.conf[ 'post_handshake_authentication' ] == True:
      self.next_mtype = 'c_post_hand_auth'
    self.next_mtype = 'c_post_hand_auth'

  def resp( self ):
    self.handshake.update_certificate( self.cert )
    self.handshake.update_certificate_verify( self.sig_algo )
    tag_resp = self.tag.resp( )
    self.last_message  = tag_resp[ 'last_exchange' ]
    sig = self.handshake.msg( 'certificate_verify', ith=-1 )[ 'signature' ]
    self.handshake.post_post_hand_auth()
    return { 'tag' : tag_resp,
             'session_id' : self.session_id.resp( tag_resp=tag_resp ),
             'signature' : sig }

class CPostHandAuthReq:

  def __init__(self, req, tls13_conf, handshake, session_id, post_hand_auth_counter ):
    self.conf = tls13_conf
    self.mtype = 'c_post_hand_auth'
   
    self.tag = Tag( req[ 'tag' ], self.mtype, self.conf )
    self.session_id = session_id 
    self.session_id.update( self.mtype )
    self.sig_algo = SigScheme( req[ 'sig_algo' ] )
    self.cert = req[ 'certificate' ]
    
    self.handshake = handshake
    self.handshake.msg_list.extend( req[ 'handshake' ] )
    self.handshake.sanity_check( self.mtype )
    cert_req_ctx = self.handshake.msg( 'certificate_request', ith=-1 )['certificate_request_context']  
#    self.conf.load_cert( cert_req_ctx=cert_req_ctx )

    self.last_exchange = None 
    self.next_mtype = 'c_post_hand_auth'
    self.post_hand_auth_counter += 1
    if self.post_hand_auth_counter <= self.conf.msg( self.mtype )[ 'max_post_handshake_authentication' ] == True:
      self.next_mtype = 'c_post_hand_auth'
    self.next_mtype = None

  def resp( self ):
    self.handshake.update_certificate( self.cert )
    self.handshake.update_certificate_verify( self.sig_algo )
    tag_resp = self.tag.resp( ctx=self.post_hand_auth_counter )
    self.last_message  = tag_resp[ 'last_exchange' ]
    sig = self.handshake.msg( 'certificate_verify', ith=-1 )[ 'signature' ]
    self.handshake.post_post_hand_auth()
    return { 'tag' : tag_resp,
             'session_id' : self.session_id.resp( tag_resp=tag_resp ),
             'signature' : sig }


class CInitEphemeralReq:

  def __init__(self, req, tls13_conf ):
    self.conf = tls13_conf
    self.mtype = 'c_init_ephemeral'
   
    self.session_id = SessionID( req[ 'session_id' ], self.mtype )
    self.freshness = Freshness( req[ 'freshness' ] )
    self.ephemeral = Ephemeral( req[ 'ephemeral' ], self.mtype, self.conf )
    
    self.handshake = TlsHandshake( 'client', self.conf )
    client_hello = self.handshake.hs_partial_to_client_hello ( req[ 'handshake'] [0] )
    self.handshake.msg_list.extend( [ client_hello ] )
    self.handshake.sanity_check( self.mtype )

    self.next_mtype = 'c_hand_and_app_secret'

  def resp( self ):
    self.ephemeral.compute_server_key_exchange( self.handshake ) 
    self.handshake.update_key_share( self.ephemeral.server_key_exchange )
    return { 'session_id' : self.session_id.resp( tag_resp=tag_resp ),
             'ephemeral' : self.ephemeral.resp() }


class CInitEarlySecretReq:

  def __init__( self, req, tls13_conf ):
    self.conf = tls13_conf
    self.mtype = 'c_init_early_secret'
   
    self.session_id = SessionID( req[ 'session_id' ], self.mtype )
    self.freshness = Freshness( req[ 'freshness' ] )
    
    self.ephemeral = Ephemeral( req[ 'ephemeral' ], self.mtype, self.conf )
    self.handshake = TlsHandshake( 'client', self.conf )
    client_hello = self.handshake.hs_partial_to_client_hello ( req[ 'handshake'] [0] )
    self.handshake.msg_list.extend( [ client_hello ] )
    self.handshake.sanity_check( self.mtype )
    self.scheduler_list = []
    self.next_mtype = 'c_hand_and_app_secret'
    
    for psk_id in self.handshake.get_ticket():
      session_ticket = SessionTicket( self.conf, psk_identity=psk_id )
      scheduler = KeyScheduler( session_ticket.tls_hash, \
                                psk=session_ticket.psk, is_ext=False)
      scheduler.process( self.secret_request.of([ 'b' ] ), self.handshake )
      self.scheduler_list.append( scheduler ) 
##       
##    
##      binders.append( )
##      self.scheduler_list.
##    self.session_ticket = SessionTicket( conf, \
##      psk_identity=self.handshake.get_ticket( req[ 'selected_identity' ] ) )
##
    self.secret_request = SecretReq(req[ 'secret_request' ], \
                          self.mtype, self.conf, handshake=self.handshake )
    self.last_exchange = None 
    self.next_mtype = 's_hand_and_app_secret'
  
  def resp( self ):
    self.ephemeral.compute_server_key_exchange( self.handshake )
    if self.ephemeral.method == 'cs_generated':
      self.handshake.update_key_share( self.ephemeral.server_key_exchange )
    self.handshake_update_binders( self.scheduler_list )
    secret_list_list = [] 
    for scheduler in self.scheduler_list:
      scheduler.process( self.secret_request.of([ 'b', 'e_c', 'e_x' ] ), self.handshake )
      secret_list_list.append( self.secret_request.resp( scheduler )) 
    return  { 'session_id' : self.session_id.resp( ),
              'ephemeral' : self.ephemeral.resp(),
              'secret_list_list' : self.secret_request.resp( self.scheduler ) }

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
      self.handshake.update_certificate_verify()
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




class CSession:
  def __init__( self, tls13_conf, session_db=None, ticket_db=None ): # type Conf
    """ handles the various requests associated to a given session """ 
    self.conf = tls13_conf
    self.next_mtype = None
    self.scheduler = None
    self.handshake = None
    self.session_id = None
    self.next_mtype = None
    self.last_exchange = None
    self.ticket_counter = 0
    self.session_db = session_db
    self.ticket_db = ticket_db
    self.scheduler_list = None

  def save_session_ctx( self, req ):
    """ saves context for next messages"""
    if req.mtype == 'c_init_cert_verify':
      self.last_exchange = True
    elif req.mtype == 'c_init_post_auth':
      self.handshake = req.handshake
      self.session_id = req.session_id
    elif req.mtype == 'c_post_auth':
      self.handshake = req.handshake
      self.session_id = req.session_id
      self.post_hand_auth_counter += 1
    elif req.mtype == 'c_init_ephemeral':
      self.handshake = req.handshake
      self.session_id = req.session_id
      self.ephemeral_method = req.ephemeral.method
    elif req.mtype == 'c_init_early_secret':
      self.session_id = req.session_id
      self.scheduler_list = req.scheduler_list
      self.handshake = req.handshake
      self.ephemeral_method = req.ephemeral.method
    elif req.mtype == 'c_hand_and_app_secret':
      self.last_exchange = req.last_exchange
      self.post_hand_auth_counter = 0
    else: 
      raise ImplementationError( "unknown mtype {req.mtype}" )
    self.next_mtype = req.next_mtype
    
  def is_expected_message( self, mtype, status ): 
    if status != 'request':
      raise LURKError( 'invalid_request', "unexpected status {status}"\
              f"expecting 'request'" )
    if ( self.next_mtype == None and 'init' in mtype ) or\
       mtype == self.next_mtype:
      pass
    else: 
      raise LURKError( 'invalid_request', "unexpected request {mtype}"\
              f"expecting {self.next_mtype} or initial request" )

  def serve( self, payload, mtype, status ):
    self.is_expected_message( mtype, status )
    if mtype == 'c_init_post_hand_auth':
      req = CInitPostHandAuthReq( payload, self.conf )
    elif mtype == 'c_post_hand_auth':
      req = CPostHandAuthReq( payload, self.conf, self.handshake, self.session_id, post_hand_auth_counter=self.post_hand_auth_counter )
    elif mtype == 'c_init_ephemeral': ## only ECDHE
      req = CInitEphemeralReq( payload, self.conf )
    elif mtype == 'c_init_early_secret':
      req = CInitEarlySecret( payload, self.conf )
    elif mtype == 'c_hand_and_app_secret':
      req = CHandAndAppSecret( payload, self.conf, self.handshake, \
              self.scheduler_list, self.session_id,\
              self.ephemeral_method )
    else: 
      raise LURKError( 'invalid_request', "unexpected request {mtype}"\
              f"expecting {self.next_mtype} or initial request" )
    resp = req.resp()
    self.save_session_ctx( req )
    return resp

class SessionDB:

  def __init__(self, ):

    self.db = {}

  def store( self, session:SSession):
    self.db[ session.session_id.inbound ] = session

  def unstore( self, session_id:bytes ):
    return self.db[ session_id ]

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
      return payload
  
