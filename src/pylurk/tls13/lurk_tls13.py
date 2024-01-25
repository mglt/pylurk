from secrets import randbits, token_bytes
#from  os.path import join
from pickle import dumps, loads
#from copy import deepcopy
import time


#from typing import Union, NoReturn, TypeVar, List

#from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
#from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey

#from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
#from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
#from cryptography.hazmat.primitives.asymmetric import rsa
#from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
#from cryptography.hazmat.primitives.asymmetric import ec
#from cryptography.hazmat.primitives.asymmetric.ec import
# SECP256R1, SECP384R1, SECP521R1, ECDSA, EllipticCurvePublicNumbers, ECDH
#, EllipticCurvePrivateKey, EllipticCurvePublicKey

from cryptography.hazmat.primitives.hashes import Hash, SHA256, SHA384, SHA512
#from cryptography.hazmat.primitives.serialization import load_der_private_key, 
#load_pem_private_key, NoEncryption, Encoding, PrivateFormat, PublicFormat
#from cryptography import x509
#from cryptography.x509.oid import NameOID

#from cryptography.hazmat.primitives.asymmetric import padding
#from cryptography.hazmat.primitives import serialization
#from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
#from cryptography.hazmat.primitives.hmac import HMAC

#import datetime
#import hashlib

#from construct.core import *
#from construct.lib import *

import pylurk.debug
#import pylurk.tls13.struct_tls13 as lurk
#from pylurk.debug import get_struct, get_struct_index
from pylurk.tls13.key_scheduler import KeyScheduler
from pylurk.tls13.tls_handshake import TlsHandshake
import pylurk.tls13.crypto_suites

import pylurk.conf
from pylurk.tls13.crypto_suites import SigScheme, CipherSuite
from pylurk.lurk.lurk_lurk import LURKError, ImplementationError
#, ConfigurationError
import pylurk


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
      if ctx.is_post_hand_auth_proposed() is False:
        self.last_exchange = True
    elif self.mtype in [ 'c_post_hand_auth' ]:
      if ctx >= self.conf[ 'max_post_handshake_authentication' ]:
        self.last_exchange = True
    elif self.mtype in [ 'c_client_finished' ]:
      ## ctx is the handshake
      self.last_exchange = self.conf[ 'last_exchange' ][ self.mtype ]
      if ctx.is_post_hand_auth_proposed() is False and\
         ctx.msg_list[ 0 ][ 'msg_type' ] == 'server_hello' :
        self.last_exchange = True
    else:
      raise ImplementationError( f"unknown type {self.mtype}" )

    self.resp = { 'last_exchange' : self.last_exchange }


class Ephemeral:

  def __init__(self, ephemeral:dict, mtype, tls13_conf, handshake=None,\
               client_hello_ephemeral=None, debug=None ) -> None:
    """ initializes the object based on the structure """

    self.conf = tls13_conf
    self.ephemeral = ephemeral
    self.mtype = mtype
    self.debug = debug
    ## The s_init_early_data only requires to store the cliemt_shares
    if ephemeral != {}:
      self.method = self.ephemeral['method']
    self.handshake = handshake
    self.sanity_check( )
    ## the entry for the key scheduler
    if self.conf[ 'role' ] == 'server':
      if self.mtype == 's_init_cert_verify':
        self.shared_secret, self.resp = self.server_shared_secret( )
        self.server_share = self.resp[ 'key' ]
      if self.mtype == 's_init_early_secret' :
        #self.client_ecdhe_key_list = self.get_key_share_client_shares()
        self.client_ecdhe_key_list = self.client_shares()
      elif self.mtype == 's_hand_and_app_secret':
        self.shared_secret, self.resp = self.server_shared_secret( client_hello_ephemeral )
        self.server_share = self.resp[ 'key' ]
      ## key is the server_share value which is a key share entry
    elif self.conf[ 'role' ] == 'client':
      if self.mtype == 'c_init_client_hello':
        self.client_ecdhe_key_list, self.resp = self.client_shares( )
      if self.mtype == 'c_init_client_finished':
        if self.method == 'e_generated':
          self.shared_secret = self.ephemeral[ 'key' ][ 'shared_secret' ]
        elif self.method == 'no_secret':
          self.shared_secret = None
    else:
      raise ImplementationError( f"unknown role {self.conf[ 'role' ]}" )

    ## attributes defined latter
    self.server_ecdhe_key = None


  def sanity_check( self ):
    """ check coherence of ephemeral with mtype and handshake """
    if self.mtype == 's_init_early_secret' and self.ephemeral == {}:
      pass
    elif self.method not in self.conf['ephemeral_method_list']:
      raise LURKError( 'invalid_ephemeral', f"method {self.method} expected to be"\
                       "in {self.conf['ephemeral_method_list']}" )
    if ( self.mtype == 's_init_cert_verify' and self.method == 'no_secret' ) or\
       ( self.mtype == 'c_client_finished' and self.method == 'cs_generated' ) :
      raise LURKError( 'invalid_ephemeral',\
              f"Incompatible {self.method} and {self.mtype}" )
    elif ( self.mtype == 's_hand_and_app_secret' and self.method == 'no_secret' ):
      if self.handshake.is_ks_agreed() :
        raise LURKError( 'invalid_ephemeral', \
                "unexpected key_share extension with 'no_secret'" )

    elif self.mtype == 'c_init_client_finished':
      if self.method == 'cs_generated' :
        raise LURKError( 'invalid_ephemeral', \
                f"Incompatible {self.method} and {self.mtype}" )
      if self.method == 'no_secret' and\
              not ( self.handshake.is_psk_proposed() \
              and self.handshake.is_psk_agreed() ) :
        raise LURKError( 'invalid_ephemeral', f"no (EC)DHE provided ({self.method})"\
                f"but PSK (without (EC)DHE) authentication is not agreed" )
      if self.method == 'e_generated' and not self.handshake.is_ks_agreed() :
        raise LURKError( 'invalid_ephemeral', \
                f"(EC)DHE provided ({self.method})"\
                f"but PSK-ECDHE or ECDHE authentication is not agreed" )
    elif self.mtype == 'c_init_client_hello':
      pass
    elif self.mtype == 'c_server_hello':
      if self.method in [ 'cs_generated', 'e_generated' ] and not self.handshake.is_ks_agreed() :
        raise LURKError( 'invalid_ephemeral', \
                f"(EC)DHE provided ({self.method}) "\
                f"but PSK-ECDHE or ECDHE authentication is not agreed "\
                f"{self.handshake.msg_list}" )
      elif self.method == 'no_secret' and self.handshake.is_ks_agreed() :
        raise LURKError( 'invalid_ephemeral', \
                f"(EC)DHE not provided ({self.method})"\
                f"but PSK-ECDHE or ECDHE authentication is agreed" )

  def proceed_empty_key_share_entry( self, empty_ks_entry ):
    """ processes an  empty key share entry

    Returns:
      - private key
      - key share entry
    """
    group = empty_ks_entry[ 'group' ]
    key_exchange = empty_ks_entry[ 'key_exchange' ]
    if group not in self.conf[ 'authorized_ecdhe_group' ]:
      raise LURKError( 'invalid_ephemeral', f"unsupported {group}" )
    if key_exchange not in [ b'', None]:
      raise LURKError( 'invalid_ephemeral', \
              f"expecting empty key share entry {empty_ks_entry}" )
###
    ecdhe_key = pylurk.tls13.crypto_suites.ECDHEKey()
    ecdhe_key.group = group
    ## try to read value from test_vector file
    if self.debug is not None and self.debug.test_vector is True:
      key =f"{self.conf[ 'role' ]}_{group}_ecdhe_private"
      if key in self.debug.db.keys():
        ecdhe_key.generate_from_pem( self.debug.read_bin( key ) )
      if self.debug.check is True:
        self.debug.check_bin( ecdhe_key.pkcs8(), self.debug.read_bin( key ) )
    elif ecdhe_key.private is None and ecdhe_key.public is None:
      ecdhe_key.generate( group )
    return ecdhe_key

  def client_shares( self ):
    """ computes client_shares, private_keys and resp """
    client_shares = self.handshake.get_key_share( side='client' )
    ecdhe_key_list = []
    resp = []
    for ks in client_shares :
      if ks[ 'key_exchange' ] in [ None, b'' ]:
        ecdhe_key = self.proceed_empty_key_share_entry( ks )
        resp.append( { 'method' : 'cs_generated',
                          'key' : ecdhe_key.ks_entry() } )
      else:
        ecdhe_key = pylurk.tls13.crypto_suites.ECDHEKey( )
        ecdhe_key.generate_from_ks_entry( ks )
        resp.append( { 'method' : 'e_generated',
                            'key' : b'' } )
    ecdhe_key_list.append( ecdhe_key )
    return ecdhe_key_list, resp

  def client_shared_secret( self, c_init_client_hello_ephemeral ):
    """ compute the share secret on the client side

    The current object is generated from the ephemeral provided by E during the
    c_server_hello exchange.
    On the other hand private keys have been generated during the
    c_init_client_hello exchange.
    This latest ephemeral is used as th einput.
    """

    if self.method == 'e_generated':
      self.shared_secret = self.ephemeral[ 'key' ][ 'shared_secret' ]
    elif self.method == 'cs_generated':
      self.server_ecdhe_key = pylurk.tls13.crypto_suites.ECDHEKey( )
      self.server_ecdhe_key.generate_from_ks_entry( self.handshake.get_key_share( side='server' ) )
      for key in c_init_client_hello_ephemeral.client_ecdhe_key_list :
        if self.server_ecdhe_key.group == key.group :
          self.shared_secret = self.server_ecdhe_key.shared_secret( key )
          break
    elif self.method == 'no_secret':
      self.shared_secret = None
    else:
      raise LURKError( 'invalid_ephemeral', f"Unexpected method {self.method}" )

  def server_shared_secret( self, client_hello_ephemeral=None ):
    """ treat ephemeral extension and initializes self.ecdhe, self.server_key_exchange

    This function is responsible for generating the server (EC)DHE public key,
    computing the shared secret as well as generating the key_share extension
    of the ServerHello.
    self.shared_secret contains the shared secret key, the server (EC)DHE public key
    is taken from the reurned resp and stored in self.server_share

    see __init__( ) fucntion:
      self.shared_secret, self.resp = self.server_shared_secret( )
      self.server_share = self.resp[ 'key' ]
    """
    ## with method 'e_generated' the shared_secret is explictly provided
    if self.method == 'e_generated':
      self.shared_secret = self.ephemeral['key'][ 'shared_secret' ]
      resp = { 'method' : self.method,
               'key' : b'' }
    ## with method 'cs_generated' the cs needs to generate the public key,
    ## private key, take the client public key and compute the shared secret
    elif self.method == 'cs_generated':
      ## retrieve the server key_share entry and seklect the client key_share entry
      ## since method is 'cs_generated' the server key_share entry MUST be empty
      self.server_ecdhe_key = pylurk.tls13.crypto_suites.ECDHEKey()
      server_ks = self.handshake.get_key_share( side='server' )
      self.server_ecdhe_key.generate( group=server_ks[ 'group' ] )

      if client_hello_ephemeral is None:
        self.client_ecdhe_key_list, tmp_resp = self.client_shares()
      else:
        self.client_ecdhe_key_list = client_hello_ephemeral.client_ecdhe_key_list
      for key in self.client_ecdhe_key_list:
        if key.group == self.server_ecdhe_key.group :
          self.shared_secret = key.shared_secret( self.server_ecdhe_key )
          break
      resp = { 'method' : self.method,
               'key' : self.server_ecdhe_key.ks_entry()  }
    elif self.method == 'no_secret':
      self.shared_secret = None
      resp = { 'method' : self.method,
               'key' : b'' }
    else:
      raise LURKError( 'invalid_ephemeral', f"Unexpected method {self.method}" )
    return self.shared_secret, resp

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
    if self.freshness_funct == 'null' :
      return random
    if role == 'server':
      ctx = b"tls13 pfs srv"
    elif role == 'client':
      ctx = b"tls13 pfs clt"
    if self.freshness_funct == 'sha256' :
      digest = Hash( SHA256() )
    elif self.freshness_funct == 'sha384' :
      digest = Hash( SHA384() )
    elif self.freshness_funct == 'sha512' :
      digest = Hash( SHA512() )
    else:
      raise LURKError( 'invalid_freshness', f"{self.freshness_funct}" )
    ## random does not include ctx
    ## this needs to be changed
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
                         f"{finger_print_entry_list} {finger_print_dict}" )
      else:
        if self.conf[ 'role' ] == 'server':
          cert_req_ctx = b''
        elif self.conf[ 'role' ] == 'client':
          cert_req_index = self.handshake.msg_type_list().index( 'certificate_request' )
          cert_req_ctx = self.handshake.msg_list[ cert_req_index ]\
                            [ 'data' ][ 'certificate_request_context' ]
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
          if not self.handshake.is_certificate_agreed() :
            raise LURKError( 'invalid_certificate', f"Incompatible server " \
              f"cert_type {self.cert_type} with handshake. Expecting certificate "\
              f"authentication" )
      ## client certificate
      else :
        if  ( (self.cert_type != 'no_certificate' ) and \
            self.handshake.is_certificate_request() ) is False:
          raise LURKError( 'invalid_certificate', \
                  "Client certificate and CertificateRequest " +\
                  "MUST either be together absent or present" )

class SecretReq:

#  def __init__( self, secret_request:dict, mtype,\
#        tls13_conf, handshake=None ):
  def __init__( self, secret_request:dict, mtype, tls13_conf ):

    self.conf = tls13_conf
    if mtype in [ 's_init_early_secret', 'c_init_client_hello' ]:
      mandatory = ['b' ]
      forbiden = [ 'h_c', 'h_s', 'a_c', 'a_s', 'x', 'r' ]
      optional = [ 'e_s', 'e_x' ]
    elif mtype in [ 's_init_cert_verify', 's_hand_and_app_secret' ]:
      mandatory = [ 'h_c', 'h_s' ]
      forbiden = [ 'b', 'e_s', 'e_x', 'r' ]
      optional = [ 'a_c', 'a_s', 'x' ]
    elif mtype in [ 's_new_ticket', 'c_register_ticket' ]:
      mandatory = []
      forbiden = [ 'b', 'e_s', 'e_x', 'h_c', 'h_s', 'a_c', 'a_s', 'x' ]
      optional = ['r']
    elif mtype in [ 'c_server_hello' ]:
      mandatory = [ 'h_c', 'h_s' ]
      forbiden = [ 'b', 'e_s', 'e_x', 'a_c', 'a_s', 'x', 'r' ]
      optional = []
    elif mtype in [ 'c_client_finished' ]:
      mandatory = [ 'a_c', 'a_s' ]
      forbiden = [ 'b', 'e_s', 'e_x', 'a_c', 'a_s', 'x' ]
      optional = [ 'x', 'r' ]
    else:
      raise ImplementationError( f"unknown {mtype}" )

    self.authorized_secrets = mandatory
    ## building the list of requested secrets, that is
    ## those set to True in key_request
    for key in secret_request.keys():
      if secret_request[ key ] is True and key not in forbiden :
        self.authorized_secrets.append( key )
    self.authorized_secrets = list( set( self.authorized_secrets ) )

    if mtype in [ 's_init_cert_verify', 'c_hand_and_app_secret' ] :
      if self.conf[ 'app_secret_authorized' ] is False :
        try:
          self.authorized_secrets.remove( 'a_c' )
          self.authorized_secrets.remove( 'a_s' )
        except KeyError:
          pass
      if self.conf[ 'exporter_secret_authorized' ] is False:
        try:
          self.authorized_secrets.remove( 'x' )
        except KeyError:
          pass
    elif mtype == 's_new_ticket':
      if self.conf[ 'resumption_secret_authorized' ] is False:
        try:
          self.authorized_secrets.remove( 'r' )
        except KeyError:
          pass
    elif mtype in [ 's_init_early_secret', 'c_init_client_hello' ]:
      if self.conf[ 'client_early_secret_authorized' ] is False:
        try:
          self.authorized_secrets.remove( 'e_s' )
        except KeyError:
          pass
      if self.conf[ 'early_exporter_secret_authorized' ] is False:
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

class SessionTicket:
  """ TLS Session Tickets for session resumption

  Attributes:
    conf: a dictionary containing the TLS 1.3 configuration 
      parameters
    psk_identity: the identity of the PSK expressed in bytes
    cipher: the TLS cipher suite
    tls_hash: The TLS hash function. Currenlty its is directly genberated from the cipher suite.
    psk: The PSK 

  """
## We need to be able to generate encrypted tickets.
  def __init__( self, tls13_conf:dict, psk_identity:bin = None ):
    """ session ticket

      psk_identity (bin):
    """
    self.conf = tls13_conf
    self.psk_identity = psk_identity
    self.cipher = None
    self.tls_hash = None
    self.psk = None

    if psk_identity is not None:
      self.read_ticket( psk_identity )
    ## This variable is used to identify the selection of the currenlty
    ## used ticket.
    ## This is used to check the server hello match the ticket that has
    ## been used to generates the early secrets
    self.selected_identity = None


  def new( self, scheduler, cipher:str ) -> dict :
    """ creates a new session ticket

    Args:
      scheduler: the scheduler object from which the psk will
        be generated
      cipher: the TLS cipher associated to the Ticket Session
        will be generated
    Returns:
      the structure of a New Session Ticket
    """
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

class SInitCertVerifyReq:

  def __init__(self, req, tls13_conf, debug=None ):
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
                                   shared_secret=self.ephemeral.shared_secret )
    self.scheduler.process( self.secret_request.of([ 'h_c', 'h_s' ] ), self.handshake )
    self.handshake.update_certificate( self.cert )
    self.handshake.update_certificate_verify( )
    ## get sig from freshly generated certificate_verify
    sig = self.handshake.msg_list[ 0 ][ 'data' ]['signature' ]
#    self.handshake.update_server_finished( self.scheduler )
    self.handshake.update_finished( self.scheduler )
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
                ticket_counter, debug=None ):
    self.conf = tls13_conf
    self.mtype = 's_new_ticket'
    self.handshake = handshake
    self.scheduler = scheduler
    self.ticket_counter = ticket_counter

    self.handshake.msg_list.extend( req[ 'handshake' ] )
    self.cert = LurkCert( req[ 'certificate' ], self.mtype, self.conf, False, \
                          self.handshake )
    if self.cert.cert_type != 'no_certificate' :
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

  def __init__( self, req, tls13_conf, debug=None ):
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
                          self.mtype, self.conf )
    ## only to store the client ephemeral that will be used in
    ## SHandAndAppSecret exchange
    self.ephemeral = None
    if self.handshake.is_ks_proposed( ) is True:
      self.ephemeral = Ephemeral( {}, self.mtype, self.conf, self.handshake )
    self.scheduler = KeyScheduler( self.session_ticket.tls_hash, \
                                   psk=self.session_ticket.psk, is_ext=False, debug=debug )
#    self.last_exchange = None
    self.session_id = SessionID( req[ 'session_id' ] )
    self.scheduler.process( self.secret_request.of([ 'b', 'e_s', 'e_x' ] ), self.handshake )
    self.resp = { 'session_id' : self.session_id.cs,
             'secret_list' : self.secret_request.resp( self.scheduler ) }

class SHandAndAppSecretReq:

  def __init__( self, req, tls13_conf, handshake, scheduler, session_id,\
                session_ticket, freshness, client_hello_ephemeral, debug=None ):
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
    self.ephemeral = Ephemeral( req[ 'ephemeral' ], self.mtype, self.conf,\
                                self.handshake, client_hello_ephemeral )

    if self.ephemeral.method == 'cs_generated':
      self.handshake.update_key_share( self.ephemeral.server_share )
    self.scheduler.shared_secret = self.ephemeral.shared_secret
    self.scheduler.process( self.secret_request.of( [ 'h_c', 'h_s'] ), self.handshake )
    self.handshake.update_server_finished( self.scheduler )
    self.scheduler.process( self.secret_request.of( [ 'a_c', 'a_s', 'x' ] ), self.handshake )
    self.tag = Tag( req[ 'tag' ], self.mtype, self.conf )
    self.resp =  { 'tag' : self.tag.resp,
                   'session_id' : session_id.e,
                   'ephemeral' : self.ephemeral.resp,
                   'secret_list' : self.secret_request.resp( self.scheduler ) }

class SSession:
  """Handles a LURK session beetween the LURK client and CS

  A session is defined by the LURK messages  exchanges between
  the LURK client and the CS for setting a given TLS exchange.
  These LURK Messages may share a specific context and at least
  follows a deterministic order. 
  This object guarantee that specific order is respected and 
  that the appropriated context is shared between the messages.  

  SSession handles LURK sessions between in the TLS server

  Attributes:
    conf: a dictionnary characterizing the configuration of the CS
    next_mtype: the designation of teh next LURK message 
    scheduler: the object implementing the sheduler of the ongoing
      TLS session
    handshake: the object that characterizes the ongoing TLS
      handshake 
    session_id: the identifier of the LURK session between the
      LURK client and the CS  
    freshness: the algorithm from which randoms are generated.
    ephemeral: the ephemeral object provided by the LURK client.
    last_exchange: determine if the curent exchange between 
      the LURK client and teh CS is the last one - in which case
      the context will be removed, or if further exchanges
      are expected.
    ticket_counter: the number of ticket that have been sent
    session_ticket: the current session ticket object
    session_db: the database that contains all sessions. This
      is where that session context will be stored / retrieved.
    ticket_db: the database that contains the ticket information.
    debug: a boolean value that indicates information needs to 
      be output or not.
  """
  def __init__( self, tls13_conf:dict, session_db=None, ticket_db=None, debug=None ): # type Conf
    """ handles the various requests associated to a given session """
    self.conf = tls13_conf
    self.next_mtype = None
    self.scheduler = None
    self.handshake = None
    self.session_id = None
    self.freshness = None
    self.ephemeral = None
#    self.next_mtype = None
    self.last_exchange = None
    self.ticket_counter = 0
    self.session_ticket = None
    self.session_db = session_db
    self.ticket_db = ticket_db
    self.debug=debug

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
    self.next_mtype = req.next_mtype
    return req.resp



class CInitClientFinishedReq:

  def __init__(self, req, tls13_conf, debug=None ):
    """ computes the signature for the client

    If post handshake authentication is not enabled,
    than, the c_init_client_finished exchange is not
    followed by other exchange and ther eis only the
    need to perform the signature over the ClientHello
    ... later of server Finished/EndOfEarlyData.

    However, if post handshake authentication, is enabled,
    there is a need to generate the client Finished
    message, to be ready for the post authentication.
    This client Finished message requires h_c to be
    computed and so a key schedule to be initiated.
    This key schedule requires the shared secret and psk
    as input.
    """
    self.conf = tls13_conf
    self.debug = debug
    self.mtype = 'c_init_client_finished'
    self.next_mtype = 'c_post_hand_auth'


    psk = req[ 'psk' ]
    self.handshake = TlsHandshake( 'client', self.conf, debug=self.debug )
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
    self.session_id = SessionID( req[ 'session_id' ], tag=self.tag )
    ephemeral = Ephemeral( req[ 'ephemeral' ], self.mtype, self.conf, self.handshake )
    self.scheduler = KeyScheduler( self.handshake.get_tls_hash(), \
                                   shared_secret=ephemeral.shared_secret, psk=psk, debug=debug )
    self.scheduler.process( [ 'h_c', 'h_s' ], self.handshake )
    pylurk.debug.print_bin( 'h_c', self.scheduler.secrets[ 'h_c' ] )
    pylurk.debug.print_bin( 'h_s', self.scheduler.secrets[ 'h_s' ] )
    self.client_cert  = LurkCert( req[ 'client_certificate' ], \
                                  self.mtype, self.conf, server=False, \
                                  handshake=self.handshake )

    self.handshake.update_certificate( self.client_cert, server=False )
    self.handshake.update_certificate_verify( )
    ## get sig from freshly generated certificate_verify
    sig = self.handshake.msg_list[ 0 ][ 'data' ]['signature' ]
    ## generating Finished message and generating the transcript of the full handshake
    if self.tag.last_exchange is False:
##      self.handshake.update_server_finished( self.scheduler )
      self.handshake.update_finished( self.scheduler )
      self.scheduler.process( [ 'r' ], self.handshake )
    self.resp = { 'tag' : self.tag.resp,
                  'session_id' : self.session_id.cs,
                  'signature' : sig }


class CPostHandAuthReq:

  def __init__(self, req, tls13_conf, handshake, scheduler,\
               session_id, post_hand_auth_counter, debug=None ):
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
    sig = self.handshake.msg_list[ 0 ][ 'data' ]['signature' ]
    del self.handshake.msg_list[ : ]

    self.tag = Tag( req[ 'tag' ], self.mtype, self.conf, ctx=self.post_hand_auth_counter )
    self.resp =  { 'tag' : self.tag.resp,
                   'session_id' : session_id.e,
                   'signature' : sig }

class CInitClientHelloReq:

  def __init__(self, req, tls13_conf, ticket_db, debug=None ):
    self.conf = tls13_conf
    self.debug = debug
    self.mtype = 'c_init_client_hello'
    self.next_mtype = [ 'c_server_hello', 'c_client_finished' ]

    self.handshake = TlsHandshake( 'client', self.conf, debug=self.debug )
    self.handshake.msg_list.extend( req[ 'handshake' ] )
    self.handshake.update_random( Freshness( req[ 'freshness' ] ) )
    ## keyshare
    self.ephemeral = Ephemeral( { 'method' : 'cs_generated' }, self.mtype, \
      self.conf, self.handshake, debug=debug )

    self.handshake.update_key_share( [ k.ks_entry() for k in self.ephemeral.client_ecdhe_key_list ])
    ## pre-shared-key extension
    secret_list = []
    binder_key_list = []
    ## the dictionaries are only filled when PSK are proposed and
    ## hosted by the CS.
    self.scheduler_list = []
    psk_metadata_list = req[ 'psk_metadata_list' ]
    self.handshake.is_post_hand_auth_proposed( )
    if self.handshake.is_psk_proposed( ) is True:
      ticket_info_list = self.handshake.psk_info_list_from_identities( \
              psk_metadata_list, ticket_db )
      self.scheduler_list = self.handshake.binder_scheduler_key_list( \
              ticket_info_list )
      binder_key_list = [ ks.secrets[ 'b' ] for ks in self.scheduler_list  ]
      binder_finished_key_list = [ ks.finished_key( role='binder' ) for ks in self.scheduler_list  ]
      self.handshake.update_binders( ticket_info_list, binder_finished_key_list )
#      secret_request = SecretReq( req[ 'secret_request' ] , self.mtype, self.conf, \
#                       handshake=self.handshake )
      secret_request = SecretReq( req[ 'secret_request' ] ,\
                                  self.mtype, self.conf )
      ## we need to provide the hash function because handshake
      ## define the hash fcuntion from the ciphersuite. The ciphersuite
      ## is in the serverHello
      ks = self.scheduler_list[ 0 ]
      self.handshake.transcript = Hash( ks.tls_hash )
      ks.process( secret_request.of( [ 'e_s', 'e_x' ] ), self.handshake )
      secret_list = secret_request.resp( ks )
      ## avoiding redundant binder_key
      if len( binder_key_list ) != 0:
        for secret in secret_list:
          if secret[ 'secret_type' ] == 'b':
            secret[ 'secret_data' ] = b''
            break

    self.session_id = SessionID( req[ 'session_id' ] )
    self.resp = { \
      'session_id' : self.session_id.cs,
      'ephemeral_list' : self.ephemeral.resp,
      'binder_key_list' : [ \
        { 'secret_type' : 'b', 'secret_data' : b } for b in binder_key_list  ],
      'secret_list' : secret_list }

### self has been forgotten
## is the function called somewhere ?
#  def update_binders( self, psk_metadata_list ):
#    ticket_info_list = self.tls_handshake.psk_info_list_from_identities( \
#            psk_metadata_list, self.ticket_db )
#    scheduler_list = self.tls_handshake.binder_sheduler_key_list( ticket_info_list )
#    binder_finished_key_list = [ks.finished_key( role='binder' ) for ks in scheduler_list ]
#    truncated_client_hello = self.tls_handshake.truncated_client_hello( ticket_info_list )
#    self.tls_handshake.update_binders( ticket_info_list, binder_finished_key_list )
#    return scheduler_list


class CServerHelloReq:

  def __init__(self, req, tls13_conf, handshake, client_hello_ephemeral,\
               scheduler_list, session_id, debug=None ):
    self.conf = tls13_conf
    self.mtype = 'c_server_hello'
    self.next_mtype = 'c_client_finished'

    self.handshake = handshake
    self.handshake.msg_list.extend( req[ 'handshake' ] )
    self.handshake.sanity_check( self.mtype )
    secret_req = { 'h_s' : True, 'h_c' : True }
    for k in [ 'b', 'e_s', 'e_x', 'a_c', 'a_s', 'x', 'r' ]:
      secret_req[ k ] = False
#    secret_request = SecretReq( secret_req, self.mtype, self.conf, \
#                                handshake=self.handshake )
    secret_request = SecretReq( secret_req, self.mtype, self.conf )
    ephemeral = Ephemeral( req[ 'ephemeral' ], self.mtype, \
                                self.conf, self.handshake )
    ephemeral.client_shared_secret( client_hello_ephemeral )
    if debug is not None:
      debug.handle_bin( 'ecdhe_shared_secret', ephemeral.shared_secret )
    if self.handshake.is_psk_agreed( ):
      selected_identity = self.handshake.server_hello_ext_data( 'pre_shared_key' )
      self.scheduler = scheduler_list[ selected_identity ]
      self.scheduler.shared_secret = ephemeral.shared_secret
    else:
      self.scheduler = KeyScheduler( self.handshake.get_tls_hash(), \
                                     shared_secret=ephemeral.shared_secret, debug=debug )
    self.scheduler.process( [ 'h_c', 'h_s' ], self.handshake )
    self.session_id = session_id
    self.resp = { 'session_id' : session_id.e,
                  'secret_list' : secret_request.resp( self.scheduler ) }


class CClientFinishedReq:

  def __init__(self, req, tls13_conf, handshake, scheduler, session_id, debug=None ):
    self.conf = tls13_conf
    self.mtype = 'c_client_finished'
    self.next_mtype = [ 'c_post_hand_auth', 'c_register_ticket' ]
    ## scheduler is None when not being selected during the c_server_hello
    ## This means that only the certificate verify (signature) is generated
    self.scheduler = scheduler
    self.handshake = handshake
    self.handshake.msg_list.extend( req[ 'handshake' ] )
    self.handshake.sanity_check( self.mtype )
    is_cert_req = self.handshake.is_certificate_request()

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
      self.handshake.transcript = Hash( self.handshake.get_tls_hash() )
    else:
      self.scheduler.process( [ 'a_c', 'a_s' ], self.handshake )
    if is_cert_req:
      self.handshake.update_certificate( client_cert, server=False )
      self.handshake.update_certificate_verify( )
      ## get sig from freshly generated certificate_verify
      sig = self.handshake.msg_list[ 0 ][ 'data' ]['signature' ]
    else:
      sig = b''
    ## generating Finished message and generating the transcript of the full handshake
    if self.tag.last_exchange is False:
      self.handshake.update_finished( self.scheduler )
      self.scheduler.process( [ 'r' ], self.handshake )
    secret_request = SecretReq(req[ 'secret_request' ], self.mtype, self.conf )
    self.resp = { 'tag' : self.tag.resp,
                  'session_id' : session_id.cs,
                  'signature' : sig,
                  'secret_list' : secret_request.resp( self.scheduler ) }


class CRegisterTicketsReq:

  def __init__( self, req, tls13_conf, ticket_db, scheduler,\
                handshake, ticket_counter, session_id, debug=None ):
    self.conf = tls13_conf
    self.mtype = 'c_register_tickets'
    self.next_mtype = [ 'c_post_hand_auth', 'c_register_ticket' ]

    self.ticket_counter = ticket_counter
    self.tag = Tag( req[ 'tag' ], self.mtype, self.conf, ctx=self.ticket_counter )
    for new_session_ticket in req[ 'ticket_list' ]:
      self.ticket_counter += 1
      if self.ticket_counter > self.conf[ 'max_tickets' ]:
        raise LURKError( 'max_tickets_reached' )
      ticket_db.register( new_session_ticket, scheduler, handshake )


    self.resp = { 'tag' : self.tag.resp,
                  'session_id' : session_id.cs }

class CSession(SSession) :

  def __init__( self, tls13_conf:dict, session_db=None,\
                ticket_db=None, debug=None ):
    super().__init__( tls13_conf=tls13_conf, session_db=session_db, \
                      ticket_db=ticket_db, debug=debug )
    self.post_hand_auth_counter = None
    self.scheduler_list = None
    self.transcript_r = None
    self.cipher_suite = None
    self.tls_hash = None

  def serve( self, payload, mtype, status ):
    ## check request and next_
    self.is_expected_message( mtype, status )
    if mtype == 'c_init_client_finished':
      req = CInitClientFinishedReq( payload, self.conf, debug=self.debug )
      self.scheduler = req.scheduler
      self.handshake = req.handshake
      self.session_id = req.session_id
      self.last_exchange = req.tag.last_exchange
      self.post_hand_auth_counter = 0
    elif mtype == 'c_post_hand_auth':
      req = CPostHandAuthReq( payload, self.conf, self.handshake, self.scheduler,\
                           self.session_id, self.post_hand_auth_counter, debug=self.debug )
      self.last_exchange = req.tag.last_exchange
      self.post_hand_auth_counter = req.post_hand_auth_counter
    elif mtype == 'c_init_client_hello':
      req = CInitClientHelloReq( payload, self.conf, self.ticket_db, debug=self.debug )
      self.scheduler_list = req.scheduler_list
      self.handshake = req.handshake
      self.session_id = req.session_id
      self.ephemeral = req.ephemeral
      self.scheduler_list = req.scheduler_list
    elif mtype == 'c_server_hello' :
      req = CServerHelloReq( payload, self.conf, self.handshake, self.ephemeral,\
                             self.scheduler_list, self.session_id, debug=self.debug )
      ## maybe we can remove these two lines
      self.handshake = req.handshake
      self.scheduler = req.scheduler
    elif mtype == 'c_client_finished' :
      req = CClientFinishedReq( payload, self.conf, self.handshake, self.scheduler,\
                             self.session_id, debug=self.debug )
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
              self.scheduler, self.handshake,\
              self.ticket_counter, self.session_id, debug=self.debug )
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

  def __init__( self, debug=None ):
    self.db = {}
    self.debug=debug

  def key( self, new_session_ticket ):
    return new_session_ticket[ 'ticket' ]

  def register( self, new_session_ticket, ks, tls_handshake ):
    key = self.key( new_session_ticket )
    self.db[ key ] = { 'new_session_ticket' : new_session_ticket,
                    'psk_bytes' : ks.compute_psk( new_session_ticket[ 'ticket_nonce' ] ),
                    'tls_hash' : tls_handshake.get_tls_hash(),
                    'psk_type' : 'resumption',
                    'cipher_suite' : tls_handshake.cipher_suite,
                    'registration_time' : time.time() }
    if self.debug is not None:
      self.debug.trace_val( "Registering in CS Tickert DB", self.db[ key ] )

  def update_ticket_info( self, ticket_info ):
    """ update ticket_info with obfuscated_ticket_age

    This function updates the information so all information is
    available to generate a TLS ticket
    """
    if ticket_info[ 'psk_type' ] == 'external':
      obfuscated_ticket_age = 0
    else :
      obfuscated_ticket_age = int( ( time.time( ) - \
              ticket_info[ 'registration_time' ] ) * 1000 +\
              ticket_info[ 'new_session_ticket' ][ 'ticket_age_add' ] ) % 2**32
    ticket_info[ 'obfuscated_ticket_age' ] = obfuscated_ticket_age
    del ticket_info[ 'registration_time' ]
    return  ticket_info

  def get_ticket_info( self, ticket ):
    """ returns the ticket_info associated to ticket

    The intent of the function is to correlate the structure of
    the ticket DB and the key being used to retrieve the ticket_info.
    """
    try:
      return self.update_ticket_info( self.db[ ticket ] )
    except KeyError:
      return None

class Tls13Ext:
  def __init__(self, conf, ticket_db=None, session_db=None, debug=None ):
    self.conf = conf
    self.debug = debug
    if session_db is None:
      self.session_db = SessionDB()
    else:
      self.session_db = session_db
    if ticket_db is None:
      self.ticket_db = TicketDB( debug=self.debug)
    else:
      self.ticket_db = ticket_db

  def payload_resp( self, req:dict ) -> dict :
    req_type = req[ 'type' ]
    req_payload = req[ 'payload' ]
    if 'init' in req_type : #in [ 's_init_early_secret', 's_init_cert_verify' ]:
      if req_type[ :7 ] == 's_init_':
        session = SSession( self.conf, session_db=self.session_db,\
                            ticket_db=self.ticket_db, \
                            debug=self.debug )
      elif req_type[ :7 ] == 'c_init_' :
        session = CSession( self.conf, session_db=self.session_db,\
                            ticket_db=self.ticket_db,\
                            debug=self.debug )
      else:
        raise LURKError( 'invalid_type', f"{req_type}" )
      payload  = session.serve( req_payload, req_type, 'request')
      if session.session_id is not None :
        self.session_db.store( session )
    else :
      try:
        session = self.session_db.unstore( req_payload[ 'session_id' ] )
      except KeyError:
        raise LURKError( 'invalid_session_id', f"{req} session_id not found in DB" )
      payload = session.serve( req_payload, req_type, 'request' )
    if session.last_exchange is True:
      self.session_db.delete( session )
    return payload

