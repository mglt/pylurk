import os.path
import binascii
import json
import pprint
from pylurk.struct_lurk import LURKMessage
from pylurk.lurk.lurk_lurk import ConfigurationError

def get_struct(struct_list: list, key:str, value) -> dict :
  """ return the first element of the list that contains  key:value """
  for e in struct_list:
    if e[ key ] == value:
      return e
  return None

def get_struct_index(struct_list: list, key:str, value) -> dict :
  """ return the first element of the list that contains  key:value """
  for e in struct_list:
    if e[ key ] == value:
      return struct_list.index(e)
  return None

def str_to_bytes( hexlify_string:str ):
  """ converts string to bytes 

  This could be useful for example when bytes needs to be 
  stored into a json file. JSON does not store bytes, so 
  these needs to be stored as bytes.  

  The reverse function is bytes_to_str.

  Args:
    hexlify_string: the string that represents bytes - 
      it has a specific format

  Returns:
    bytes_output: the represented bytes (by the string).
  """
  hexlify_string = str( hexlify_string )
  bytes_output = b''
  for hex_str in hexlify_string.split( " " ):
    bytes_output += binascii.unhexlify( hex_str )
  return bytes_output

def bytes_to_str( bit_string ):
  """ converts bytes to string 

  Args:
    bit_string: th ebytes stream

  Returns:
    the string representaing the bytes
  """
  return binascii.hexlify(bit_string, sep=' ').decode()

def bytes_to_human( description:str, bit_string:bytes ):
  """ display bytes stream into a human readable format

  Args: 
    description: a string that describes the coming bytes
    bit_string: the byte stream to display

  Returns:
    a string
  """

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

def check_file( file_path ):
  """ checks a file can be open """
  if file_path is None :
    raise ConfigurationError( "file_path is None. Expecting file path." )
  if os.path.exists( file_path ) is False:
    raise ConfigurationError( f"{file_path} does not exist." )
  if os.path.isfile( file_path ) is False:
    raise ConfigurationError( f"{file_path} is not a file but a directory" )
  if os.stat( file_path ).st_size == 0 :
    raise ConfigurationError( f"{file_path} is empty" )

def print_bin( description:str, bit_string:bytes ):
  """ prints human readable bytes to the stdout 

  Args: 
    description: a string that describes the coming bytes
    bit_string: the byte stream to display
  """

  print( bytes_to_human( description, bit_string ) )

def print_val( key:str, value ):
  """ pretty print values

  We should probably replace print_bin by print val
  """

  if isinstance( value , ( bytes, bytearray ) ):
    ##    print( f"  - {key} [{len(value)} bytes]: {value}" )
    print_bin( key, value )
  else:
    pprint.pprint( f"  - {key}: {value}", width=80, sort_dicts=False )

class Debug:

  def __init__( self, debug_conf ):
    self.conf = debug_conf
    self.test_vector = False
    self.test_vector_file = None
    test_vector_mode = None
    self.check = False
    self.record = False
    self.db = {}
    self.trace = False
    if 'trace' in debug_conf.keys( ):
      self.trace = debug_conf[ 'trace' ]
      if isinstance( self.trace, bool ) is False:
        raise ConfigurationError( f"Unexpected value for trace."\
          f" Expecting boolean value. {debug_conf}" )

    ## handling test_vector when present test_vector MUST have a file
    ## and a mode.
    if 'test_vector' in debug_conf.keys( ):
      key_list = debug_conf[ 'test_vector' ]
      if 'file' in key_list and 'mode' in key_list :
        self.test_vector_file = debug_conf[ 'test_vector' ][ 'file' ]
        test_vector_mode = debug_conf[ 'test_vector' ][ 'mode' ]
        self.test_vector = True
        if test_vector_mode == 'check':
          self.check = True
        elif test_vector_mode == 'record':
          self.record = True
        elif test_vector_mode is None :
          pass
        else:
          raise ConfigurationError( f"Unexpected mode. Acceptable values "\
            f"are: 'check', 'record' or None. Provided mode is {debug_conf}" )

        if os.path.exists( self.test_vector_file ) and\
           os.path.isfile( self.test_vector_file ) and\
           os.stat( self.test_vector_file ).st_size > 0:
          with open( self.test_vector_file, 'rt', encoding='utf8' ) as f:
            self.db = json.load( f )

  def read_bin( self, key ) -> bytes :
    """ returns the value in a binary format """
    if key in self.db.keys() :
      return str_to_bytes( self.db[ key ] )
    return None

  def read_str( self, key ) -> str :
    """ returns the value in a string representation"""
    if key in self.db.keys() :
      return self.db[ key ]
    return None

  def check_bin( self, key:str, value:bytes ):
    """ raises an error when the key, value mismatches those of the test_vector """
    if key in self.db.keys() :
      ref_value = str_to_bytes( self.db[ key ] )
      if ref_value != b'' :
        if value != ref_value :
          raise ValueError(
            f"Debug {key} check fails:\n"\
            f"{bytes_to_human( 'expected', ref_value)}\n"\
            f"{bytes_to_human( 'provided', value)}\n" )

  def value_to_json( self, struct:dict ):
    """ stores a given value into a compatible json format

    JSON files are very restrictive regarding the type of data
    they can store. More specifically, they cannot store bytes,
    so we have to convert these bytes into strings. 
    This fonction is able to convert any structure into a JSON
    compatible structure, that is to say, it is able to look 
    for the bytes stream into that structure.

    Args:
      struct: a dictionnary or list that can conatin a bytesstream. 
        In general dictionnary are expected to represent complex
        structures.

    Returns:
      a JSON compatible structure, that can be stored into a JSON file.
    """
    if isinstance( struct, dict ) is True:
      for k in struct.keys():
        v = struct[ k ]
        if isinstance( v, ( bytes, bytearray ) ):
          struct[ k ] = bytes_to_str( v )
        elif isinstance( v, dict ):
          struct[ k ] = self.value_to_json( v )
    elif isinstance( struct, list ) is True:
      for i in range( len ( struct ) ):
        struct[ i ] = self.value_to_json( struct[ i ] )
    return struct

  def record_bin( self, key:str, value:bytes ):
    value = bytes_to_str( value )
    self.record_val( key, value )

  def record_val( self, key:str, value ):
    """ record key value to the test_vector file

    The value is simultaneously added to the db as well as to the
    test_vector file.
    The reason to do so is to allow a common test_vector file being
    shared by the multiple modules as well as to avoid synchronizing
    the various db.
    """
    ## updating the local db
    self.db[ key ] = self.value_to_json( value )

    ## updating the test_vector file
    ## opens only when the file exists to read the existing records.
    if os.path.exists( self.test_vector_file ) and os.path.isfile( self.test_vector_file )\
       and os.stat( self.test_vector_file ).st_size > 0:
      with open( self.test_vector_file, 'rt', encoding='utf8' ) as f:
        tmp_db = json.load( f )
#        tmp_db[  key ] = self.db[ key ]
    else:
      tmp_db = {}
    tmp_db[ key ] = self.value_to_json( value )
    with open( self.test_vector_file, 'wt', encoding='utf8' ) as f:
      json.dump( tmp_db, f, indent=2 )

  def trace_bin( self, key:str, value:bytes ):
    print( bytes_to_human( key, value ) )

  def trace_val( self, key:str, value:bytes ):
    if isinstance( value , ( bytes, bytearray ) ):
      print( f"  - {key} [{len(value)} bytes]: {value}" )
    else:
#      pprint.pprint( f"  - {key}: {value}", width=80, sort_dicts=False )
      print( f"  - {key}: {value}" )

  def handle_bin( self, key:str, value:bytes ):
    if self.check is True:
      self.check_bin( key, value )
    if self.record is True:
      self.record_bin( key, value )
    if self.trace is True:
      self.trace_bin( key, value )


class Tls13Debug( Debug ):


  def check_client_ephemeral( self, ephemeral ):
    for k in ephemeral.client_ecdhe_key_list:
      if k.private is not None:
        self.check_bin( f"client_{k.group}_ecdhe_private", k.pkcs8() )

  def trace_client_ephemeral( self, ephemeral ):
    for k in ephemeral.client_ecdhe_key_list:
      if k.private is not None:
        pkcs8_bytes = k.pkcs8( )
        key = f"client_{k.group}_ecdhe_private"
        self.trace_bin( key, pkcs8_bytes )
        self.trace_val( key, pkcs8_bytes )
      self.trace_val( f"client_{k.group}_ecdhe_public", k.ks_entry( ) )

  def record_client_ephemeral( self, ephemeral ):
    for k in ephemeral.client_ecdhe_key_list:
      if k.private is not None:
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

