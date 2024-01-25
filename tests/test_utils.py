from _io import BytesIO
import traceback
from copy import deepcopy
from construct.core import *
from construct.lib import *
import json

def title(title):
    """ print title in a square box

    To enhance the readability of the tests, this function prints in the
    terminal teh string title in a square box.

    Args:
        title (str): the string
    """
    space = "    "
    title = space + title + space
    h_line = '+'
    for character in title:
        h_line += '-'
    h_line += '+\n'
    print('\n' + h_line + '|' + title + '|\n' + h_line )


def compare( data_struct1, data_struct2):
  """ compares two data structures """
  if isinstance( data_struct1, (dict, Container) ) and\
     isinstance( data_struct2, (dict, Container) ) :
    ## removing unsignificant variable for container, i.e. used for teh
    ## purpose of data processing
    data_keys = []
    for data_struct in [ data_struct1, data_struct2]:
      keys = list(data_struct.keys())
      if isinstance(data_struct, Container):
        for k in keys[:]:
          if k[0] == '_' or k == 'reserved':
            keys.remove(k)
      data_keys.append(set(keys))
    ## comparing keys
    if not data_keys[0] == data_keys[1]:
      k1 = data_keys[0]
      k2 = data_keys[1]
      raise Exception(\
        "\n    - k1: %s"%k1 + "\n    - k2: %s"%k2 +\
        "\n    - keys in k1 not in k2: %s"%k1.difference(k2) +\
        "\n    - keys in k2 not in k1 :%s"%k2.difference(k1) +\
        "\n    - data_struct1: %s"%data_struct1 +\
        "\n    - data_struct2: %s"%data_struct2 )
    for k in data_keys[1] :
      compare(data_struct1[k], data_struct2[k])
  elif isinstance( data_struct1, (list, set, ListContainer)) and\
     isinstance( data_struct2, (list, set, ListContainer)) :
    for i in range(len(data_struct1)):
      if ( None in data_struct1 and None not in data_struct2):
        data_struct1.remove(None)
      if ( None in data_struct2 and None not in data_struct1):
        data_struct2.remove(None)

    if len(data_struct1) == len(data_struct2):
      for i in range(len(data_struct1)):
         compare(data_struct1[i], data_struct2[i])
    else:
      raise Exception( f"lenght do not match" \
        f"\n    - data_struct1 [{type(data_struct1)}] [len: {len(data_struct1)}]: {data_struct1}"\
        f"\n    - data_struct1 [{type(data_struct2)}] [len: {len(data_struct2)}]: {data_struct2}" )
  elif isinstance( data_struct1, (str, EnumIntegerString)) and\
     isinstance( data_struct2, (str, EnumIntegerString)) :
    if str(data_struct1) != (data_struct2):
      raise Exception( \
        "\n    - data_struct1 [%s] : %s"%(type(data_struct1), data_struct1) +\
        "\n    - data_struct2 [%s] : %s"%(type(data_struct2), data_struct2) )
  else:
    if data_struct1 != data_struct2:
      if data_struct1 in  [ None, b'' ] and data_struct2 in [ None, b'' ]:
        pass
      else:
         raise Exception( \
           "\n    - data_struct1 [%s] : %s"%(type(data_struct1), data_struct1) +\
           "\n    - data_struct2 [%s] : %s"%(type(data_struct2), data_struct2) )


def obj2json( data:dict ) -> dict:
  """ converts a bytes or bytearray value to string """
  json_data = deepcopy( data )
  if isinstance( json_data, BytesIO ) :
    json_data = json_data.read()
#  if isinstance( json_data, bytes ) or\
  if type( json_data ) is bytes or\
     isinstance( json_data, bytearray ) : #or\
#     isinstance( json_data, BytesIO) :
    json_data = json_data.hex( '-' )
  elif isinstance( json_data, dict ):
    for k in json_data.keys():
##      if isinstance( json_data[ k ], BytesIO ):
##        del json_data[ k ]
##      else:
        json_data[ k ] = obj2json( json_data[ k ] )
  elif isinstance( json_data, list ):
    for i in range( len( json_data ) ):
      json_data[ i ] = obj2json( json_data[ i ] )
  else:
    c = json_data.__class__.__name__
##    if c == 'BytesIO':
##      print( "class: %s, object: %s, type: %s"%(c, json_data.read(), type( json_data ) ) )

  return json_data


def test_struct( struct, data_struct, ctx_struct={}, \
                 ext_title='', no_title=False, \
                 io_check=True, print_data_struct=False, \
                 print_binary=False, print_data=True ):
  """ compares a data structure ( i.e. a dictionary to the structure itself  """
#  print( f" --- input : {struct} - {data_struct}" )
  binary = struct.build(data_struct, **ctx_struct)
#  print( f" --- binary  : {binary}" )
  data = struct.parse(binary, **ctx_struct)
#  print( f" --- data  : {data}" )

  if not no_title:
    try:
      name = data._name
    except(AttributeError):
      name = ''
    title("%s [%s]  structure"%(name, ext_title))

  if print_data_struct == True:
    print("struct: %s"%json.dumps( obj2json( data_struct ), indent=2) )
  if print_binary == True:
    print("bytes: %s"%binary.hex( '-' ) )
  if print_data == True:
    print("struct: %s"%data)
  if io_check:
    try:
      #print( f"{data_struct} - {data}" )
      compare( data_struct, data )
    except AssertionError as e:
      _, _, tb = sys.exc_info()
      traceback.print_tb(tb) # Fixed format
      tb_info = traceback.extract_tb(tb)
      filename, line, func, text = tb_info[-1]
      print('An error occurred on line {} in statement {}'.format(line, text))
      print(e)
      exit(1)
  return binary, data


def match( req, resp ):
  """ tests if the re and resp match """
  if req[ 'designation' ] != resp[ 'designation' ]:
    raise ValueError( f"designation does not match {req} / {resp}" )
  if req[ 'version' ] != resp[ 'version' ]:
    raise ValueError( f"version does not match {req} / {resp}" )
  if req[ 'id' ] != resp[ 'id' ]:
    raise ValueError( f"id does not match {req} / {resp}" )


