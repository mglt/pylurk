#from secrets import randbits, token_bytes
#from  os.path import join
#from copy import deepcopy
#import datetime
#import hashlib



from typing import  NoReturn
#Union, TypeVar, List

from cryptography.hazmat.primitives.asymmetric import utils
#from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
#from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey

#from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
#from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
#from cryptography.hazmat.primitives.asymmetric import rsa
#from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
#from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
#SECP256R1, SECP384R1, SECP521R1,
#EllipticCurvePublicNumbers, ECDH, EllipticCurvePrivateKey, EllipticCurvePublicKey

from cryptography.hazmat.primitives.hashes import Hash
#, SHA256, SHA384, SHA512
#from cryptography.hazmat.primitives.serialization import load_der_private_key,
#load_pem_private_key, NoEncryption, Encoding, PrivateFormat, PublicFormat
#from cryptography import x509
#from cryptography.x509.oid import NameOID

#from cryptography.hazmat.primitives.asymmetric import padding
#from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.hmac import HMAC

#from construct.core import *
#from construct.lib import *


import pytls13.struct_tls13 as tls
import pylurk.debug
from pylurk.debug import get_struct
#, get_struct_index
from pylurk.tls13.crypto_suites import SigScheme, CipherSuite
from pylurk.lurk.lurk_lurk import LURKError, ImplementationError
import pylurk.tls13.key_scheduler


class TlsHandshake:

  def __init__( self, role, tls13_conf=None, debug=None ) -> None:
    self.role = role #tls13_conf[ 'role' ]  ## list of role
    ## mostly makes sense for the server side
    self.conf = tls13_conf
    if self.conf is not None :
      self.finger_print_dict = self.conf[ '_finger_print_dict' ]
      self.private_key = self.conf[ '_private_key' ]
    self.debug = debug
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
    return [ msg[ 'msg_type' ] for msg in self.msg_list ]

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

  def client_hello_ext_data( self, extension_type ):
    ch_index = self.latest_client_hello_index()
    for ext in self.msg_list[ ch_index ][ 'data' ][ 'extensions' ] :
      if ext[ 'extension_type' ] == extension_type:
        return ext[ 'extension_data' ]
    return None

  def server_hello_ext_data( self, extension_type):
    ch_index = self.server_hello_index()
    for ext in self.msg_list[ ch_index ][ 'data' ][ 'extensions' ] :
      if ext[ 'extension_type' ] == extension_type:
        return ext[ 'extension_data' ]
    return None


  def is_psk_proposed( self )->bool :
    """ return True if self.msg_list has proposed PSK, False otherwise """
    if self.psk_proposed is not None:
      return self.psk_proposed

    ext_list = self.client_hello_extension_list( )
    if 'pre_shared_key' in ext_list  and  'psk_key_exchange_modes' in ext_list :
      self.psk_proposed = True
    else:
      self.psk_proposed = False
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

    if self.ks_proposed is not None:
      return self.ks_proposed

    ext_list = self.client_hello_extension_list( )
    if 'key_share' in ext_list :
      self.ks_proposed = True
    else:
      self.ks_proposed = False
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
#    error_txt = ""
    if mtype == 's_init_cert_verify':
      ## determine is a client Certificate
      ## is expected in the s_new_ticket
      self.is_certificate_request( )
      if self.is_psk_agreed() is True or self.is_ks_proposed is False or\
         self.is_ks_agreed is False:
        raise LURKError('invalid_handshake', \
                f"expecting ks_agreed and non psk_aghreed {self.msg_list}" )
## We foudn erros in the coditions checked with pylint but I cannot see how to
## updat ethe code.
#    elif mtype == 's_new_ticket' :
#      if self.is_certificate_agreed !=  self.is_certificate_request( ) is False :
#        raise LURKError('invalid_handshake', f"incompatible client "\
#                        f"Certificate / CertificateRequest" )
#      if self.resumption_master_secret is None and self.msg_list == []:
#        raise LURKError('invalid_handshake', f"expecting non empty handshake" )
    elif mtype == 's_init_early_secret':
      if self.is_psk_proposed() is False :
        raise LURKError('invalid_handshake', f"expecting psk_proposed {self.msg_list}" )
    elif mtype == 's_hand_and_app_secret':
      if self.is_psk_agreed() is False :
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
                f"suite {self.cipher_suite} and ticket cipher suites "\
                f"are not compatible {session_ticket.cipher}" )
    elif mtype == 'c_init_client_finished':
      if self.is_certificate_request is False and self.is_post_hand_auth_proposed() is False :
        raise LURKError( 'invalid_handshake', "Expecting server certificate authentication" )
    elif mtype in [ 'c_init_post_hand_auth', 'c_post_hand_auth' ]:
      if self.is_post_hand_auth_proposed() is False:
        raise LURKError( 'invalid_handshake', "Post handshake authentication no enabled" )
    elif mtype == 'c_init_client_hello':
      if self.is_psk_proposed() is False and self.is_ks_proposed() is False:
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

  def key_share_index( self, side ):
    """ return necessary arguments to point to the key_share_index

    pointers are returned (instead of simply the value) as we
    also want to update the key_share value.
    """
    if side == 'server':
      # update occurs in the server_hello
      if self.msg_list[ 0 ][ 'msg_type' ] == 'client_hello' :
        ch_index = self.latest_client_hello_index( )
        msg_index = ch_index + 1
      elif self.msg_list[ 0 ][ 'msg_type' ] == 'server_hello' :
        msg_index = 0
      else:
        raise ImplementationError( f"unexpected message type. Expecting "\
                f"client_hello or server_hello as first message "\
                f"{self.msg_list[ 0 ] [ 'msg_type' ]}" )
      ks_designation = 'server_share'
    elif side == 'client':
      # update the 'client_hello'
      msg_index = self.latest_client_hello_index( )
      ks_designation = 'client_shares'
    else:
      raise ImplementationError( f"unknown role {self.role}" )

    exts = self.msg_list[ msg_index ][ 'data' ][ 'extensions' ]
    if 'key_share' in [ e[ 'extension_type' ] for e in exts ] :
      key_share = get_struct( exts, 'extension_type', 'key_share' )
      key_share_index = exts.index( key_share )
    else:
      key_share_index = None

    return ks_designation, msg_index, key_share_index

  def get_key_share( self, side ):
    ks_designation, msg_index, ks_index = self.key_share_index( side )
    return self.msg_list[ msg_index ][ 'data' ]\
        [ 'extensions' ][ ks_index ][ 'extension_data' ]\
        [ ks_designation ]


  def update_key_share( self, key_share_entry ) -> NoReturn:
    """ update key_exchange value of the CLientHello or ServerHello

    On the server side, the key_share is the server key_share entry.
    On the client side, the key_share is a list of key_share entries (client_shares)
    """

    ks_designation, msg_index, ks_index = self.key_share_index( self.role )
    if msg_index is not None and ks_index is not None:
      self.msg_list[ msg_index ][ 'data' ]\
        [ 'extensions' ][ ks_index ][ 'extension_data' ]\
        [ ks_designation ] = key_share_entry

  def psk_info_list_from_identities( self, psk_metadata_list, ticket_db ):
    """ builds psk_info associated to each identities

    identities are always provided, psk_information are either
    retrieved from the PSKIdentityMetadata being provided or retrived from the TicketDB.

    binders are never provided to the server. This function is only to be used by the TLS server.
    """
    offered_psk = self.client_hello_ext_data( 'pre_shared_key' )
    ticket_info_list = []
    for psk_identity in offered_psk[ 'identities' ] :
      ticket_info = ticket_db.get_ticket_info( psk_identity[ 'identity' ] )
      if ticket_info is None:
        psk_identity_index = offered_psk[ 'identities' ].index( psk_identity )
        try:
          psk_metadata = psk_metadata_list.pop( 0 )
          while psk_metadata[ 'identity_index' ] < psk_identity_index:
            psk_metadata = psk_metadata_list.pop( 0 )
          if psk_metadata[ 'identity_index' ] == psk_identity_index:
            ticket_info = psk_metadata
            del ticket_info[ 'identity_index' ]
        except IndexError:
          raise LURKError( 'invalid_psk', f"Cannot retrive psk_infop for {psk_identity}" )
      ticket_info_list.append( ticket_info  )
    return ticket_info_list


  def truncated_client_hello( self, ticket_info_list ) -> bytes :
    """ returns  the necessary handshake context to generate the binders.

    The handshake context is returned in bytes which corresponds to
    Truncate(ClientHello1) or ClientHello1, HelloRetryRequest,
    Truncate(ClientHello2)

    This basically consists in removing the binders of the latest ClientHello
    """
    ## binder list is just generated to be able to built the ClientHello
    ## binders are set to zero bytes and will be removed during the truncation
    binder_list = []
    binder_list_len = 0
    for ticket_info in ticket_info_list:
      binder_len = pylurk.tls13.crypto_suites.hash_sanity_check( \
                     ticket_info[ 'tls_hash' ] ).digest_size
      binder_list.append( { 'binder' : b"\x00" * binder_len } )
      binder_list_len += 1 + binder_len ## considering binder + its size
    ## adding the binders to the latest extension which is supposed to be pre_shared_key
    ch_index = self.latest_client_hello_index( )
    self.msg_list[ ch_index ][ 'data' ][ 'extensions' ][ -1 ]\
                 [  'extension_data'] [ 'binders' ] = binder_list
    truncated_client_hello_bytes = b''
    for msg in self.msg_list[ : ch_index + 1]:
      truncated_client_hello_bytes += tls.Handshake.build( msg )
    truncated_client_hello_bytes = \
      truncated_client_hello_bytes[ : -binder_list_len - 2 ] ## removing list length
    if self.debug is not None:
      self.debug.handle_bin( 'truncated_client_hello', truncated_client_hello_bytes )
    return truncated_client_hello_bytes

  def compute_binder( self, tls_hash, binder_finished_key, \
                      truncated_client_hello_bytes, binder_index='' ) -> bytes:
    """ compute the binder associated to the binder_key

    The computation is performed similalrly to the finished message except
    that the TLS context only consists in the truncated ClientHello.

    We could have re-used the get_verify_data function that is used to
    generate the finished message. However, currently, we prefer to have
    the running hash of the handshake being decorelated from the one used
    to generate the binders.
    This function may appear as a bit redundant to get_verify_data.

    args:
      - tls_hash : the hash function used to generate the HMAC
      - binder_finished_key: the key (secret) used to generate the HMAC
      - truncated_client_hello
    """
    tls_hash = pylurk.tls13.crypto_suites.hash_sanity_check( tls_hash )
    transcript = Hash( tls_hash )
    transcript.update( truncated_client_hello_bytes )
    transcript_hash = transcript.finalize( )

    hmac = HMAC( binder_finished_key, tls_hash )
    hmac.update( transcript_hash )
    binder = hmac.finalize()
    if self.debug is not None:
      if binder_index != '':
        binder_index = f"({binder_index})"
      self.debug.handle_bin( f"compute_binder: {binder_index} "\
                             f"binder_finished_key" , binder_finished_key )
      self.debug.handle_bin( f"Transcript( truncated_client_hello ) "\
                             f"{binder_index}" , transcript_hash )
      self.debug.handle_bin( f"binder {binder_index}" , binder )

    return binder


  def binder_scheduler_key_list( self, ticket_info_list ):
    """ generates key_scheduler and binder_keys associated to tickets """
    ks_list = []
    for ticket_info in ticket_info_list :
      tls_hash = ticket_info[ 'tls_hash' ]
      psk = ticket_info[ 'psk_bytes' ]
      if ticket_info[ 'psk_type' ] == 'resumption':
        is_ext = False
      else:
        is_ext = True
      ks = pylurk.tls13.key_scheduler.KeyScheduler( tls_hash, psk=psk,\
             is_ext=is_ext, debug=self.debug )
      ks.process( [ 'b' ] , None )
      ks_list.append( ks )
    if self.debug is not None:
      for ticket_info in ticket_info_list :
        index = ticket_info_list.index( ticket_info )
        self.debug.trace_val( f"ticket ({index})", ticket_info )
        ks = ks_list[ index ]
        self.debug.handle_bin( f"binder_key ({index})", ks.secrets[ 'b' ] )
        self.debug.handle_bin( f"binder_finished_key ({index})", ks.finished_key( role='binder') )
    return ks_list

  def update_binders( self, ticket_info_list, binder_finished_key_list )-> None :
    """ generates binders to the ClientHello """
    offered_psks = self.client_hello_ext_data( 'pre_shared_key' )
    if len( offered_psks[ 'identities' ] ) != len( ticket_info_list ) or\
       len( offered_psks[ 'identities' ] ) != len( binder_finished_key_list ) :
      raise LURKError( 'invalid_psk', f"Mistmatching list lenggth: \n"\
        f"   - identitities (len: {len( offered_psks[ 'identities' ] )})\n"\
        f"   - psk_info_list  (len: {len( ticket_info_list )})\n"\
        f"   - binder_key_list  (len: {len( binder_finished_key_list )})" )

    ## generates the truncated client hello
    truncated_client_hello = self.truncated_client_hello( ticket_info_list )
    ## adding the binders
    binder_list = []
    for ticket_info in ticket_info_list :
      tls_hash = ticket_info[ 'tls_hash' ]
      binder_finished_key = binder_finished_key_list[ ticket_info_list.index( ticket_info ) ]
      binder = self.compute_binder( tls_hash, binder_finished_key, \
                       truncated_client_hello, \
                       binder_index=ticket_info_list.index( ticket_info ) )
      binder_list.append( { 'binder' : binder } )
    ch_index = self.latest_client_hello_index( )
    self.msg_list[ ch_index ][ 'data' ][ 'extensions' ][ -1 ]\
                 [  'extension_data'] [ 'binders' ] = binder_list


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
    if self.role == 'server' and server is True or\
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

  def certificate_verify_content( self, role=None ) :
    """ update the handshake with the CertificateVerify """
    if role is None:
      role = self.role
    if role == 'server':
      ctx_string = b'TLS 1.3, server CertificateVerify'
      transcript_h = self.transcript_hash( 'sig' )
    elif role == 'client':
      ctx_string = b'TLS 1.3, client CertificateVerify'
      if self.transcript_r is None:
        transcript_h = self.transcript_hash( 'sig' )
      else:
        transcript_h = self.transcript_hash( 'post_hand_auth_sig' )
    else:
      raise ImplementationError( f"unknown role {self.role}" )
    content = b'\x20' * 64 + ctx_string + b'\x00' + transcript_h
    if self.debug is not None:
      self.debug.trace_val( 'ctx_string', ctx_string )
      self.debug.handle_bin( 'ctx_string', ctx_string )
      self.debug.handle_bin( 'content to be signed', content )
    return content

  def update_certificate_verify( self ) :
    content = self.certificate_verify_content( )
    sig_scheme = SigScheme( self.conf[ 'sig_scheme' ][ 0 ] )
    if sig_scheme.algo in [ 'ed25519', 'ed448' ]:
      signature = self.private_key.sign( content )
    ## ecdsa
    elif sig_scheme.algo == 'ecdsa':
      signature = self.private_key.sign( content, \
                    ECDSA( sig_scheme.hash ) )
    ## rsa
    elif 'rsa' in sig_scheme.algo:
      print( f"--- update_certificate_verify: pad: {sig_scheme.pad}, h: {sig_scheme.hash}" )
      # signature = self.private_key.sign( content, sig_scheme.pad, sig_scheme.hash )
      hasher = Hash( sig_scheme.hash )
      hasher.update( content )
      digest = hasher.finalize( )
      signature = self.private_key.sign( digest, sig_scheme.pad, utils.Prehashed(sig_scheme.hash) )
    else:
      raise LURKError( 'invalid_signature_scheme', f"unknown {sig_scheme.algo}" )

    self.msg_list.append( { 'msg_type' : 'certificate_verify',
                            'data' : { 'algorithm' : sig_scheme.name,
                                       'signature' : signature } } )

  def get_verify_data( self, scheduler, role, transcript_mode ):
    finished_key = scheduler.finished_key( role )
    hmac = HMAC( finished_key, scheduler.tls_hash )
    hmac.update( self.transcript_hash( transcript_mode ) )
    return hmac.finalize()

  def update_finished( self, scheduler ):
    """ updates the finished message

    Only the self.role Finished message is generated.
    More specifically only the TLS client generates the client Finished
    and only the TLS server generates the server Finished.

    get_verify_data is used directly to perform the verification of
    the other Finished message.
    """
    verify_data = self.get_verify_data( scheduler, \
                    role=self.role, transcript_mode=f"{self.role} finished" )
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
    msg_bytes = bytearray()
    for msg in msg_list :
      msg_bytes.extend( tls.Handshake.build( msg, **ctx_struct ) )

    self.transcript.update( msg_bytes )
    transcript = self.transcript.copy()
    h = transcript.finalize()
    return h

  def post_hand_auth_transcript( self ):
    """ post handshake authentication transcript is derived from the transcript
        of the full handshake.
        This is a bit different from append transcript where messages are appened to
        a given transcript.
    """
    if self.transcript_r is None:
      raise ImplementationError( "handshake transcript for the handshake" +\
                                 "has not been finalized - expected to be " +\
                                 "finalized for post hand authentication" )

    transcript = self.transcript.copy()
    msg_bytes = bytearray()
    for msg in self.msg_list :
      msg_bytes.extend( tls.Handshake.build( msg ) )
    transcript.update( msg_bytes )
    del self.msg_list[ : ]
    return transcript.finalize()


  def transcript_hash( self, transcript_type ) -> bytes:
    """ return the Transcript-Hash output for the key schedule

    Performing the hash in the handshake class prevent the
    handshake class to keep all exchanges.
    """

    if self.transcript is None:
      self.transcript = Hash( self.get_tls_hash() )
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
##    elif transcript_type == 'finished' :
    elif transcript_type in [ 'client finished', 'server finished' ] :
      if self.msg_type_list( ) not in [ \
        ## 's_init_cert_verify', c_init_client_finished, c_client_finised
        ## without TLS client authentication, the client finished
        ## may be generated with the remaining server Finished
        ## This is a handshake list to consider by the CS for computing
        ## the finished hash.
        [ 'finished' ],\
        ## without TLS client authentication, the client finished
        ## may be generated without additional message after the a_c, a_h
        ## in fact as soon as a_c, a_h are generated by the client
        ## the finished message is not present.
        ## This case happens when the TLS client computes the finished hash
        ## after it has checked the server Finished
        [ ],\
        ## with TLS client authentication. Such list is processed by the CS.
        [ 'finished', 'certificate', 'certificate_verify' ], \
        ## when the TLS client proceeds to the client Finished message,
        ## the server Finished message has been removed to check the
        ## server Finished.
        [ 'certificate', 'certificate_verify' ], \
        ## with certificate authentication (client or server)
        [ 'certificate_verify' ], \
        ## 's_hand_and_app_secret'
        [ 'encrypted_extensions' ], \
        [ 'encrypted_extensions', 'certificate_request' ] ] :
        raise LURKError( 'invalid_handshake', f"unexpected handshake {self.msg_type_list()}" )
    elif transcript_type == 'a' :
      if self.msg_type_list( ) not in [ \
        ## 's_init_cert_verify'
        ## 's_hand_and_app_secret'
        [ 'finished' ], \
        ## c_client_finished
        [ 'server_hello', 'encrypted_extensions', 'certificate_request',\
          'certificate', 'certificate_verify', 'finished' ], \
        [ 'server_hello', 'encrypted_extensions', 'certificate', \
          'certificate_verify', 'finished' ], \
        [ 'server_hello', 'encrypted_extensions', 'finished' ], \
        [ 'encrypted_extensions', 'certificate_request', 'certificate',\
          'certificate_verify', 'finished' ], \
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
    if transcript_type == 'r' and self.transcript_r is not None:
      transcript = self.transcript_r
    elif transcript_type == 'post_hand_auth_sig' :
      transcript = self.post_hand_auth_transcript( )
    else :
      transcript = self.append_transcript( upper_msg_index )
      if transcript_type == 'r' :
        self.transcript_r = transcript

    if self.debug is not None:
      self.debug.handle_bin( f"Transcript Hash [mode {transcript_type}]", transcript )
    return transcript

  def get_ticket( self, selected_identity:int=None ):
    try:
      ch_index = self.latest_client_hello_index( )
      client_hello_exts = self.msg_list[ ch_index ][ 'data' ][ 'extensions' ]
      pre_shared_key = get_struct(client_hello_exts, 'extension_type', 'pre_shared_key' )
      identities = pre_shared_key[ 'extension_data' ][ 'identities' ]

      if selected_identity is None:
        return identities
      else:
        return identities[ selected_identity ]
    except:
      raise LURKError('invalid_handshake', f"unable to get psk_identity from {identities}" )
