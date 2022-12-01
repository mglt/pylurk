import os.path
import binascii
import json 
from pylurk.struct_lurk import LURKMessage

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

def str_to_bytes( hexlify_string:str ):
  hexlify_string = str( hexlify_string )
  bytes_output = b''
#  print(  f" {type(hexlify_string)} {hexlify_string}" )
  for hex_str in hexlify_string.split( " " ):
#    print( hex_str )
    bytes_output += binascii.unhexlify( hex_str )
  return bytes_output

def bytes_to_str( bit_string ):
  return binascii.hexlify(bit_string, sep=' ').decode()

def bytes_to_human( description:str, bit_string:bytes ):
    output_string = f"  - {description} [{len(bit_string)} bytes]:\n"
    sep=0
    for char in bytes_to_str( bit_string ):
      if char == ' ':
        sep += 1
        if sep % 16 == 0:
          output_string += '\n'
        else:
          output_string += char
      else:
        output_string += char
    return output_string
#    return f"  - {description} [{len(bit_string)} bytes]: {bytes_to_str(bit_string)}"

def print_bin( description:str, bit_string:bytes ):
    print( bytes_to_human( description, bit_string ) )
#    print( f"  - {description} [{len(bit_string)} bytes]: {bytes_to_str(bit_string)}" )

class TestVector:

  def __init__( self, debug_conf ):

    self.file = debug_conf[ 'test_vector_file' ]
    self.mode = debug_conf[ 'test_vector_mode' ] ## check, write

    if os.path.isfile( self.file ):
      with open( self.file, 'rt', encoding='utf8' ) as f:
        self.db = json.load( f )
    else:
      self.db = {}

    self.check = False
    if debug_conf[ 'test_vector' ] is True:
      if debug_conf[ 'test_vector_mode' ] == 'check':
        self.check = True

    self.record = False
    if debug_conf[ 'test_vector' ] is True:
      if debug_conf[ 'test_vector_mode' ] == 'record':
        self.record = True

    self.trace = debug_conf[ 'trace' ]

  def read_bin( self, key ) -> bytes :
    """ returns the value in a binary format """
    if key in self.db.keys() :
      return str_to_bytes( self.db[ key ] )

  def read_str( self ) -> str :
    """ returns the value in a string representation"""
    if key in self.db.keys() :
      return self.db[ key ] 

  def check_bin( self, key:str, value:bytes ):
    """ raises an error when the key, value mismatches those of the test_vector """
    
    if key in self.db.keys() :
##      print( f"DB: {type( self.db[ key ] )} - {self.db[ key ]}" )
      ref_value = str_to_bytes( self.db[ key ] )
##      print( f"ref_value {type( ref_value )} - {ref_value}" )
      if ref_value != b'' :
        if value != ref_value :
#          i = 0
#          for b in value:
#            print( f" {i}: {ref_value[ i ]} - {value[ i ]} {ref_value[ i ] == value[ i ] }" )
#            i += 1
          raise ValueError(
            f"TestVector {key} check fails:\n"\
            f"{bytes_to_human( 'expected', ref_value)}\n"\
            f"{bytes_to_human( 'provided', value)}\n" )

  def value_to_json( self, struct:dict ):
    if isinstance( struct, dict ) is True:
     for k in struct.keys():
       v = struct[ k ]
       if isinstance( v, bytes ) or isinstance( v, bytearray ):
         struct[ k ] = bytes_to_str( v )
       elif isinstance( v, dict ):
         struct[ k ] = self.value_to_json( v )
    elif isinstance( struct, list ) is True:
      for i in range( len ( struct ) ):
        struct[ i ] = value_to_json( struct[ i ] ) 
#    else: 
#      return struct
    return struct

  def record_bin( self, key:str, value:bytes ):
    value = bytes_to_str( value ) 
    self.db[ key ] = value
    self.record_val( key, value )
#    self.db[ key ] = self.value_to_json( value )
#    with open( self.file, 'w', encoding='utf8' ) as f:
#      json.dump( self.db, f, indent=2 )

  def record_val( self, key:str, value ):
    with open( self.file, 'rt', encoding='utf8' ) as f:
      tmp_db = json.load( f )
      tmp_db[  key ] = self.db[ key ]
    with open( self.file, 'w', encoding='utf8' ) as f:
      json.dump( tmp_db, f, indent=2 )

  def trace_bin( self, key:str, value:bytes ):
    print( bytes_to_human( key, value ) )

  def trace_val( self, key:str, value:bytes ):
    if isinstance( value , bytes ) or isinstance( value, bytearray ):
      print( f"  - {key} [{len(value)} bytes]: {value}" )
    else: 
      print( f"  - {key}: {value}" )

  def handle_bin( self, key:str, value:bytes ):
    if self.check is True:
      self.check_bin( key, value )
    if self.record is True:
      self.record_bin( key, value )
    if self.trace is True:
      self.trace_bin( key, value )


class Tls13TestVector( TestVector ):

  
  def check_client_ephemeral( self, ephemeral ):
    for k in ephemeral.client_ecdhe_key_list:
      if k.private != None:
        self.check_bin( f"client_{k.group}_ecdhe_private", k.pkcs8() ) 

  def trace_client_ephemeral( self, ephemeral ):
    for k in ephemeral.client_ecdhe_key_list:
      if k.private != None:
        pkcs8_bytes = k.pkcs8( )
        key = f"client_{k.group}_ecdhe_private"
        self.trace_bin( key, pkcs8_bytes )   
        self.trace_val( key, pkcs8_bytes )
#        print( f"  - {key} [{len(pkcs8_bytes)} bytes]: {pkcs8_bytes}" )
      self.trace_val( f"client_{k.group}_ecdhe_public", k.ks_entry( ) )   

  def record_client_ephemeral( self, ephemeral ):
    for k in ephemeral.client_ecdhe_key_list:
      if k.private != None:
        self.record_bin( f"client_{k.group}_ecdhe_private", k.pkcs8() )

  def handle_client_ephemeral( self, ephemeral ):
    if self.check is True:
      self.check_client_ephemeral( ephemeral )
    if self.record is True:
      self.record_client_ephemeral( ephemeral )
    if self.trace is True:
      self.trace_client_ephemeral( ephemeral )

  def lurk_msg_key( self, struct:dict ):
    return f"{struct[ 'type' ]}_{struct[ 'status' ]}"

  def check_lurk_msg( self, msg:dict ):
    pass
###    msg_bytes = LURKMessage.build( msg )
###    self.check_bin( f"{self.lurk_msg_key( msg )}_bytes", msg_bytes )

  def trace_lurk_msg( self, msg:dict ):
    key = self.lurk_msg_key( msg )
    msg_bytes = LURKMessage.build( msg )
    self.trace_val( f"{key}", LURKMessage.parse( msg_bytes ) )
    self.trace_bin( f"{key}_bytes", msg_bytes )

  def record_lurk_msg( self, msg ):
    key = self.lurk_msg_key( msg )
    msg_bytes = LURKMessage.build( msg )
    self.record_bin( f"{key}_bytes", msg_bytes )
##    self.record_val( f"{key}", dict( msg ) )

  def handle_lurk_msg( self, msg ):
    if self.check is True:
      self.check_lurk_msg( msg )
    if self.record is True:
      self.record_lurk_msg( msg )
    if self.trace is True:
      self.trace_lurk_msg( msg )

