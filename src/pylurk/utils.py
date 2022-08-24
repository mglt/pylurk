import binascii

MODE_TRACE = True

def print_bin( description:str, bit_string:bytes ):
  if MODE_TRACE is True:
    print( f"  - {description} [{len(bit_string)} bytes]: {binascii.hexlify(bit_string, sep=' ')}" )


def str_to_bytes( hexlify_string:str ):
  bytes_output = b''
  for hex_str in hexlify_string.split( " " ):
    bytes_output += binascii.unhexlify( hex_str )
  return bytes_output

