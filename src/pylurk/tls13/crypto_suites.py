#import binascii

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
#, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
#, Ed448PublicKey
#from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
#, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import \
  SECP256R1, SECP384R1, SECP521R1, ECDSA, \
  EllipticCurvePublicNumbers, ECDH, EllipticCurvePrivateKey
#, EllipticCurvePublicKey
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
#Hash,
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
# load_der_private_key, load_pem_private_key, NoEncryption, \
#PrivateFormat,
#from cryptography import x509
#from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
#from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM, AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
#HKDF,

from pylurk.lurk.lurk_lurk import LURKError, ImplementationError
#, ConfigurationError
import pylurk.tls13.struct_tls13 as lurk
import pylurk.debug
import pytls13.struct_tls13 as tls

def hash_sanity_check( tls_hash ):
  """ enables to provide tls_hash as a string

  This is especially useful when psk_metadata structure or tickets
  are carried as structure as opposed to objects.
  """
  if isinstance( tls_hash, ( SHA256, SHA384, SHA512 ) ): # or \
#     isinstance( tls_hash, SHA384() ) or \
#     isinstance( tls_hash, SHA512() ):
    return tls_hash

  if isinstance( tls_hash, str ) :
    if tls_hash == 'sha256' :
      tls_hash = SHA256()
    elif tls_hash == 'sha384' :
      tls_hash = SHA384()
    elif tls_hash == 'sha384' :
      tls_hash = SHA512()
    else :
      raise ImplementationError( f"unknown tls_hash {tls_hash}" )
  else :
    raise ImplementationError( f"unknown tls_hash {tls_hash}" )
  return tls_hash


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
    try:
      return hash_sanity_check( hash_algo )
    except :
##    if hash_algo == 'sha256':
##      h = SHA256()
###      h = hashlib.sha256
##    elif hash_algo == 'sha384':
##      h = SHA384()
###      h = hashlib.sha384
##    elif hash_algo == 'sha512':
##      h = SHA512()
###      h = hashlib.sha512
##    else:
      raise LURKError( 'invalid_signature_scheme', f"{hash_algo} is not implemented" )
##    return h

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
#      pad = padding.PSS(
#        mgf=padding.MGF1(self.hash),
#       salt_length=padding.PSS.MAX_LENGTH)
      pad = padding.PSS(
        mgf=padding.MGF1(self.hash),
       salt_length=self.hash.digest_size )
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
              f"{self.name}, {type(key)} ,"\
              f"incompatible private key and signature algorithm" )
    if isinstance( key, EllipticCurvePrivateKey ):
      if isinstance( key.curve, type( self.curve ) ) is False:
        raise LURKError( 'invalid_signature_scheme', \
              f"{self.name}, {self.curve}, {key.curve} ,"\
              f"incompatible curve and signature algorithm" )



class CipherSuite:
  def __init__( self, name:str, secret=None ) :
    """ Handle the cipher suite string
    """
    self.name = name
    self.hash = self.get_hash()
    self.tag_len = self.tag_length( )
    self.key_len = self.key_length( )
    self.nonce_len = self.nonce_length( )

    if secret is not None:
      self.traffic_key( secret )


  def get_hash( self ):
    return SigScheme( self.name ).get_hash( )

  def nonce_length( self ):
    return 12

  def tag_length( self ):
    if self.name == 'TLS_CHACHA20_POLY1305_SHA256':
      tag_length = 16
    elif self.name == 'TLS_AES_128_GCM_SHA256':
      tag_length = 16
    elif self.name == 'TLS_AES_256_GCM_SHA384':
      tag_length = 16
    elif self.name == 'TLS_AES_128_CCM_SHA256':
      tag_length = 16
    elif self.name == 'TLS_AES_128_CCM_8_SHA256':
      tag_length = 8
    else:
      raise LURKError( 'invalid_cipher_suite', f"{self.name} is not implemented" )
    return tag_length

  def key_length( self ):
    if self.name == 'TLS_CHACHA20_POLY1305_SHA256':
      key_length = 32
    elif self.name == 'TLS_AES_128_GCM_SHA256':
      key_length = 16
    elif self.name == 'TLS_AES_256_GCM_SHA384':
      key_length = 32
    elif self.name == 'TLS_AES_128_CCM_SHA256':
      key_length = 16
    elif self.name == 'TLS_AES_128_CCM_8_SHA256':
      key_length = 16
    else:
      raise LURKError( 'invalid_cipher_suite', f"{self.name} is not implemented" )
    return key_length

  def compute_nonce( self, sequence_number, iv ):
    sn = (b'\x00' * 4) + int(sequence_number).to_bytes( 8, byteorder='big' )
    xor = bytearray()
    for sn, iv in zip( sn, iv ):
      xor.append( sn ^ iv )
    return xor
#      nonce = b''
#      for i in range( self.nonce_len ):
#        nonce += sn[ i ] ^ iv[ i ]
#      return nonce
#      formatted_num = (b"\x00" * 4) + struct.pack(">q", num)
#    return bytes([i ^ j for i, j in zip(iv, formatted_num)])

  def hkdf_expand_label( self, secret,\
                       label, \
                       context, \
                       length, \
                       backend=default_backend() ): #, \
    hkdf_label = lurk.HkdfLabel.build( \
      { 'length' : length,
        'label' : b"tls13 " + label, \
        'context' : context } )
    return HKDFExpand( algorithm=self.hash,\
                         length=length,\
                         info=hkdf_label,\
                         backend=backend ).derive( secret )

  def traffic_key( self, secret ):
#    ks = pylurk.tls13.lurk_tls13.KeyScheduler( tls_hash=self.hash )
    self.write_key = self.hkdf_expand_label( secret=secret, label=b'key', \
            context=b'', length=self.key_len )
    self.write_iv = self.hkdf_expand_label( secret=secret, label=b'iv', \
            context=b'', length=self.nonce_len )
    self.sequence_number = 0


  def next_generation_application_traffic_secret( self, secret ):
    return self.hkdf_expand_label( secret=secret, label=b'traffic upd', \
             context=b'', length=self.hash.digest_size )

  def decrypt_old( self, msg, debug=False ):
    """ decrypt msg and return a plain text structure (equivalent)

    """
    additional_data = b'\x17\x03\x03' + len( msg ).to_bytes( 2, byteorder='big' )
    nonce = self.compute_nonce( self.sequence_number, self.write_iv )
    pylurk.debug.print_bin( "fragment (encrypted)",  msg  )
    pylurk.debug.print_bin( "write_key", self.write_key )
    pylurk.debug.print_bin( "write_iv", self.write_iv )
    pylurk.debug.print_bin( "nonce", nonce )
    pylurk.debug.print_bin( "additional_data", additional_data )
    pylurk.debug.print_val( 'sequence_number', self.sequence_number )
    if 'GCM' in self.name:
      cipher = AESGCM( self.write_key )
    elif 'CCM' in self.name :
      cipher = AESCCM( self.write_key, tag_length=self.tag_len )
    elif self.name == 'TLS_CHACHA20_POLY1305_SHA256':
      cipher = ChaCha20Poly1305( self.write_key )
    else:
      raise LURKError( 'invalid_cipher_suite', f"{self.name} is not implemented" )
    clear_text = cipher.decrypt( nonce, msg, additional_data )
    ## this probably can be handled by construct itself
    length_of_padding = 0
    for i in range( len( clear_text ) ):
      if clear_text[ -1 - i ] != b'\x00':
        break
      else:
        length_of_padding += 1
    type_byte = ( clear_text[ -1 - length_of_padding ]).to_bytes( 1, byteorder='big' )
    ct_type = tls.ContentType.parse( type_byte )
    pylurk.debug.print_bin( f"fragment (decrypted) [type {ct_type}]",  clear_text )
    if ct_type in [ 'application_data', 'handshake' ] :
      clear_text_msg_len = len( clear_text ) - 1 - length_of_padding
      clear_text_struct = tls.TLSInnerPlaintext.parse( clear_text, \
              type=ct_type, length_of_padding=length_of_padding, \
              clear_text_msg_len=clear_text_msg_len )
    else:
      clear_text_struct = tls.TLSInnerPlaintext.parse( clear_text, \
              type=ct_type, length_of_padding=length_of_padding )
    self.sequence_number += 1
    if debug is True:
      return clear_text_struct, clear_text
    return  { 'type' : ct_type, 'content' : clear_text_struct[ 'content' ] }


  def decrypt( self, msg:bytes, debug=None ) -> dict:
    """ decrypt msg and return a plain text structure (equivalent)

    """
    additional_data = b'\x17\x03\x03' + len( msg ).to_bytes( 2, byteorder='big' )
    nonce = self.compute_nonce( self.sequence_number, self.write_iv )
    if debug is not None :
      pylurk.debug.print_bin( "fragment (encrypted)",  msg  )
      pylurk.debug.print_bin( "write_key", self.write_key )
      pylurk.debug.print_bin( "write_iv", self.write_iv )
      pylurk.debug.print_bin( "nonce", nonce )
      pylurk.debug.print_bin( "additional_data", additional_data )
      pylurk.debug.print_val( 'sequence_number', self.sequence_number )
    if 'GCM' in self.name:
      cipher = AESGCM( self.write_key )
    elif 'CCM' in self.name :
      cipher = AESCCM( self.write_key, tag_length=self.tag_len )
    elif self.name == 'TLS_CHACHA20_POLY1305_SHA256':
      cipher = ChaCha20Poly1305( self.write_key )
    else:
      raise LURKError( 'invalid_cipher_suite', f"{self.name} is not implemented" )
    clear_text = cipher.decrypt( nonce, msg, additional_data )
    ## this probably can be handled by construct itself
    length_of_padding = 0
    for i in range( len( clear_text ) ):
      if clear_text[ -1 - i ] != b'\x00':
        break
      else:
        length_of_padding += 1
    type_byte = ( clear_text[ -1 - length_of_padding ]).to_bytes( 1, byteorder='big' )
    ct_type = tls.ContentType.parse( type_byte )
    if ct_type in [ 'application_data', 'handshake' ] :
      clear_text_msg_len = len( clear_text ) - 1 - length_of_padding
      clear_text_struct = tls.FragmentTLSInnerPlaintext.parse( \
              clear_text, type=ct_type, \
              length_of_padding=length_of_padding, \
              clear_text_msg_len=clear_text_msg_len )
    else:
      clear_text_struct = tls.TLSInnerPlaintext.parse( \
              clear_text, type=ct_type, \
              length_of_padding=length_of_padding )
    self.sequence_number += 1
    return  { 'type' : ct_type, \
              'content' : clear_text_struct[ 'content' ],\
              'zeros' : b'\x00' * length_of_padding }


  def encrypt( self, clear_text_msg, content_type,\
               length_of_padding=0, debug=None ):
    """ builds and encrypts the clear_text_msg as inner_text message """

    ## building the inner message
    zeros = b'\x00' * length_of_padding
    inner_plain_text = { \
      'content' : clear_text_msg,
      'type' : content_type,
      'zeros' : zeros }
    if content_type == 'application_data' :
      clear_text_record_bytes = tls.TLSInnerPlaintext.build( \
              inner_plain_text, type=content_type, \
              length_of_padding=length_of_padding, \
              clear_text_msg_len=len(clear_text_msg) )
    else: # handshake
      clear_text_record_bytes = tls.TLSInnerPlaintext.build( \
              inner_plain_text, type=content_type, \
              length_of_padding=length_of_padding)

    additional_data = b'\x17\x03\x03' + \
            int( len( clear_text_record_bytes ) +\
            self.tag_len ).to_bytes( 2, byteorder='big' )
    nonce = self.compute_nonce( self.sequence_number, self.write_iv )
    if 'GCM' in self.name:
      cipher = AESGCM( self.write_key )
    elif 'CCM' in self.name :
      cipher = AESCCM( self.write_key, tag_length=self.tag_len )
    elif self.name == 'TLS_CHACHA20_POLY1305_SHA256':
      cipher = ChaCha20Poly1305( self.write_key )
    else:
      raise LURKError( 'invalid_cipher_suite', f"{self.name} is not implemented" )
    encrypted_reccord =  cipher.encrypt( nonce, clear_text_record_bytes, additional_data )
    if debug is True :
      pylurk.debug.print_bin( "write_key", self.write_key )
      pylurk.debug.print_bin( "write_iv", self.write_iv )
      print( f"  - sequence_number : {self.sequence_number}" )
      pylurk.debug.print_bin( "nonce", nonce )
      pylurk.debug.print_bin( "additional_data", additional_data )

    self.sequence_number += 1
    return encrypted_reccord

  def debug( self, debug, description="" ):
    debug.handle_bin( f"{description}_write_key", self.write_key )
    debug.handle_bin( f"{description}_write_iv", self.write_iv )


class ECDHEKey():

  def __init__( self ):
    self.group = None
    self.private = None
    self.public = None

  def generate( self, group ):
    """ generates a brand ne ECDHE key pair for a given group """
    self.group = group
    if group in [ 'secp256r1', 'secp384r1', 'secp521r1' ]:
      if group ==  'secp256r1':
        curve =  SECP256R1()
      elif group ==  'secp384r1':
        curve = SECP384R1()
      elif group ==  'secp521r1':
        curve = SECP521R1()
#      private_key = ec.generate_private_key( curve, default_backend())
      private_key = ec.generate_private_key( curve )
#      public_key = private_key.public_key()
    elif group  in [ 'x25519', 'x448' ]:
      if group == 'x25519':
        private_key = X25519PrivateKey.generate()
      elif group == 'x448':
        private_key = X448PrivateKey.generate()
    self.private = private_key
    self.public = private_key.public_key()

  def ks_entry( self ) -> dict:
    """ returns the ks_entry (TLS) associated to the ECDHE key

    Note that only the public part is in the ks entry
    """
    if self.group in [ 'secp256r1', 'secp384r1', 'secp521r1' ]:
      public_numbers = self.public.public_numbers()
      key_exchange = { 'legacy_form' : 4,
                       'x' : public_numbers.x,
                       'y' : public_numbers.y }
    elif self.group  in [ 'x25519', 'x448' ]:
      key_exchange = self.public.public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw)
    return { 'group' : self.group,
             'key_exchange' : key_exchange }

  def generate_from_pem( self, pem_bytes:bytes ):
## private_key = serialization.load_pem_private_key(\
## b'-----BEGIN PRIVATE KEY-----\n\
## MC4CAQAwBQYDK2VuBCIEICAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/\n\
## -----END PRIVATE KEY-----', None)
    self.private = serialization.load_pem_private_key( pem_bytes, None)
    self.public = self.private.public_key()

  def pkcs8( self ):
    if self.private is not None:
      private_bytes = self.private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption() )
    else:
      private_bytes = b''
    return private_bytes

  def generate_from_ks_entry( self, ks_entry:dict ):
    """ generates the ECHDE key from a ks_entry structure

    Note that only the public part is in the ks entry.

    .. code-block:: python

       ks_entry is a dictionary { 'group' : 'x25519', 
                                  'key_exchange' : kx_bytes }

    """

    self.group = ks_entry[ 'group' ]
    key_exchange = ks_entry[ 'key_exchange' ]
##    if group not in self.conf[ 'authorized_ecdhe_group' ]:
##      raise LURKError( 'invalid_ephemeral', f"unsupported {self.group}" )
    if self.group in [ 'secp256r1', 'secp384r1', 'secp521r1' ]:
      if self.group ==  'secp256r1':
        curve =  SECP256R1()
      elif self.group ==  'secp384r1':
        curve = SECP384R1()
      elif self.group ==  'secp521r1':
        curve = SECP521R1()
      else:
        raise LURKError( 'invalid_ephemeral', f"unknown group {self.group}" )

      public_number = EllipticCurvePublicNumbers( key_exchange[ 'x' ],\
                     key_exchange[ 'y' ], curve )
      self.public = public_number.public_key()
    elif self.group  in [ 'x25519', 'x448' ]:
      if self.group == 'x25519':
        self.public = X25519PublicKey.from_public_bytes( key_exchange )
      elif self.group == 'x448':
        self.public = X448PublicKey.from_public_bytes( key_exchange )
    else:
      raise LURKError( 'invalid_ephemeral', f"unknown group {self.group}" )

  def shared_secret( self, ecdhe_key ):
    if self.private is None:
      private_key = ecdhe_key.private
      public_key = self.public
    else:
      private_key = self.private
      public_key = ecdhe_key.public
    if self.group in [ 'secp256r1', 'secp384r1', 'secp521r1' ]:
      print( f"private key {type(private_key)}" )
      print( f"public key {type(public_key)}" )
      print( f"ECDHE {type(ECDH())}" )
      shared_secret = private_key.exchange( ECDH(), public_key )
    elif self.group  in [ 'x25519', 'x448' ]:
      shared_secret = private_key.exchange( public_key )
    else:
      raise LURKError( 'invalid_ephemeral', f"Unexpected group {self.group}" )
    return shared_secret



