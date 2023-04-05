#from secrets import randbits, token_bytes
#from  os.path import join
#from copy import deepcopy
from typing import TypeVar
#Union, NoReturn, List
from cryptography.hazmat.primitives.hashes import Hash
#, SHA256, SHA384, SHA512
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
#from cryptography.hazmat.primitives.hmac import HMAC
#from construct.core import *
#from construct.lib import *

import pylurk.debug
import pylurk.tls13.struct_tls13 as lurk
from pylurk.lurk.lurk_lurk import ImplementationError
#import pylurk.debug
#from pylurk.debug import get_struct, get_struct_index
#from pylurk.tls13.crypto_suites import SigScheme, CipherSuite

TlsHandshake = TypeVar( 'TlsHandshake' )

class KeyScheduler:

  def __init__( self, tls_hash, shared_secret:bytes=None, 
                psk:bytes=None, is_ext=False, debug=None ):
    self.secrets = { 'b' : None, 'e_s' : None, 'e_x' : None,\
                    'h_c' : None, 'h_s' : None, 'a_c' : None,\
                    'a_s' : None, 'x' : None, 'r' : None }
    self.tickets = []
    self.psk = psk
    self.is_ext = is_ext
    self.tls_hash = pylurk.tls13.crypto_suites.hash_sanity_check( tls_hash )

    self.shared_secret = shared_secret
    self.debug = debug

    ## initializaton of secret
    self.early_secret = None
    self.handshake_secret = None
    self.master_secret = None

  def hkdf_expand_label( self, secret,\
                         label, \
                         context, \
                         length ):
    hkdf_label = lurk.HkdfLabel.build( \
      { 'length' : length,
        'label' : b"tls13 " + label, \
        'context' : context } )
    return HKDFExpand( algorithm=self.tls_hash,\
                       length=length,\
                       info=hkdf_label ).derive( secret )

  def derive_secret( self, secret, label, transcript_h ):
    """ derive secret function

    Args:
      secret: the secret
      label: the label
      transcript_h : the transcript hash associated to the messages.
        Note that this is a main difference with Derive-Secret as
        described in RFC4664. Derive-Secret takes the messages and
        performs the Transcript-Hash of the messages.
    """
    return self.hkdf_expand_label( secret=secret, \
                                   label=label, \
                                   context=transcript_h, \
                                   length=self.tls_hash.digest_size )
#                                   algorithm=self.tls_hash )

  def process_early_secret( self ):

    if self.psk is None:
      self.psk = b"\x00" * self.tls_hash.digest_size

    self.early_secret = HKDF(
            algorithm=self.tls_hash,
            length=self.tls_hash.digest_size,
            info=None, # None or \x00 zero length string
            salt=b"\x00",
        )._extract( self.psk )

    if self.debug is not None:
      self.debug.handle_bin( "psk", self.psk )
      self.debug.handle_bin( "early_secret",  self.early_secret )


  def empty_transcript_h( self ):
    h = Hash( self.tls_hash )
    h.update( b'' )
    return h.finalize()


  def process_handshake_and_master_secret( self, shared_secret=None ):

    if shared_secret is not None:
      self.shared_secret = shared_secret
    empty_transcript = self.empty_transcript_h( )

    if self.shared_secret is None:
      self.shared_secret = b"\x00" * self.tls_hash.digest_size

    handshake_secret_salt = self.derive_secret(\
      self.early_secret,\
      b'derived',\
      empty_transcript )

    self.handshake_secret = HKDF(
      algorithm=self.tls_hash,
      salt=handshake_secret_salt,
      info=None,
#      backend=backend,
      length=self.tls_hash.digest_size )._extract( self.shared_secret )

    master_secret_salt = self.derive_secret(\
      self.handshake_secret,\
      b'derived',\
      empty_transcript )

    self.master_secret = HKDF(
      algorithm=self.tls_hash,
      salt=master_secret_salt,
      info=None,
      length=self.tls_hash.digest_size )._extract( b"\x00" * self.tls_hash.digest_size )
    if self.debug is not None:
      self.debug.handle_bin( "empty_transcript", empty_transcript )
      self.debug.handle_bin( "handshake_secret", self.handshake_secret )
      self.debug.handle_bin( "master_secret", self.master_secret )


  def process( self, secret_list:list, handshake:TlsHandshake ) -> None:

    ## early secrets
    if 'b' in secret_list or 'e_s' in secret_list or  'e_x' in secret_list:
      if self.early_secret is None :
        self.process_early_secret( )
      s = self.early_secret
      ## generating traffic secrets are derived
      if 'b' in secret_list :
        t = self.empty_transcript_h()
        if self.is_ext is True:
          label = b'ext binder'
        else:
          label = b'res binder'
        self.secrets[ 'b' ] = self.derive_secret( s, label, t )
        if self.debug is not None:
          self.debug.handle_bin( "transcript h ['b']", t )
          self.debug.handle_bin( "binder_key", self.secrets[ 'b' ] )
      if 'e_s' in secret_list or 'e_x' in secret_list:
        t = handshake.transcript_hash( 'e' )
        if self.debug is not None:
          self.debug.handle_bin( "transcript h ['e_s', 'e_x']", t )
        if 'e_s' in secret_list:
          self.secrets[ 'e_s' ] = self.derive_secret( s, b'c e traffic', t )
          if self.debug is not None:
            self.debug.handle_bin( "client_early_traffic_secret", self.secrets[ 'e_s' ] )
        if 'e_x' in secret_list:
          self.secrets[ 'e_x' ] = self.derive_secret( s, b'e exp master', t )
          if self.debug is not None:
            self.debug.handle_bin( "early_exporter_master_secret", self.secrets[ 'e_x' ] )
    # handshake and other secrets
    if 'h_c' in secret_list or  'h_s' in secret_list or \
       'a_c' in secret_list or  'a_s' in secret_list or \
       'r' in secret_list:
      if self.early_secret is None :
        self.process_early_secret( )
      if self.handshake_secret is None:
        self.process_handshake_and_master_secret( )

      if 'h_c' in secret_list or  'h_s' in secret_list:
        t = handshake.transcript_hash( 'h' )
        s = self.handshake_secret
        self.secrets[ 'h_c' ] = self.derive_secret( s, b'c hs traffic', t )
        self.secrets[ 'h_s' ] = self.derive_secret( s, b's hs traffic', t )
        if self.debug is not None:
          self.debug.handle_bin( "transcript h ['h_c', 'h_s']", t )
          self.debug.handle_bin( "client_handshake_traffic_secret", self.secrets[ 'h_c' ] )
          self.debug.handle_bin( "server_handshake_traffic_secret", self.secrets[ 'h_s' ] )

      if 'a_c' in secret_list or  'a_s' in secret_list or 'x' in secret_list:
        t = handshake.transcript_hash( 'a' )
        s = self.master_secret
        self.secrets[ 'a_c' ] = self.derive_secret( s, b'c ap traffic', t )
        self.secrets[ 'a_s' ] = self.derive_secret( s, b's ap traffic', t )
        if self.debug is not None:
          self.debug.handle_bin( "transcript h ['a_c', 'a_s']", t )
          self.debug.handle_bin( "client_application_traffic_secret_0", self.secrets[ 'a_c' ] )
          self.debug.handle_bin( "server_application_traffic_secret_0", self.secrets[ 'a_s' ] )
        if 'x' in secret_list:
          self.secrets[ 'x' ] = self.derive_secret( s, b'exp master', t )
          if self.debug is not None:
            self.debug.handle_bin( "exporter_master_secret", self.secrets[ 'x' ] )

      if 'r' in secret_list:
        t = handshake.transcript_hash( 'r' )
        s = self.master_secret
        self.secrets[ 'r' ] = self.derive_secret( s, b'res master', t )
        if self.debug is not None:
          self.debug.handle_bin( "transcript h ['r']", t )
          self.debug.handle_bin( "resumption_master_secret", self.secrets[ 'r' ] )

  def finished_key( self, role ):
    if role == 'server' :
      secret = self.secrets[ 'h_s' ]
    elif role == 'client' :
      secret = self.secrets[ 'h_c' ]
    elif role == 'binder' :
      secret = self.secrets[ 'b' ]
    else:
      raise ImplementationError( f"unknown role {role}" )

    return self.hkdf_expand_label( secret=secret,
                     label=b'finished', context=b'',\
                     length=self.tls_hash.digest_size )

  def compute_psk( self, ticket_nonce ) -> bytes: ## or None
    return self.hkdf_expand_label( secret=self.secrets[ 'r' ],\
                         label=b"resumption", \
                         context=ticket_nonce, \
                         length=self.tls_hash.digest_size )
#                         backend=default_backend() ) #, \

  def next_generation_application_traffic_secret( self, secret ):
    return self.hkdf_expand_label( secret=secret, label=b'traffic upd', \
             context=b'', length=self.tls_hash.digest_size )
