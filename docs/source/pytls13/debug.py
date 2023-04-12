import json
import os.path
import pprint
import typing 
import pylurk.debug
import pytls13.tls_client_handler
import pytls13.struct_tls13 as tls

#typing.NewType( 'TLSMsg', pytls13.tls_client_handler.TLSMsg )

class Debug( pylurk.debug.Debug ):

  def __init__( self, debug_conf ):
    super().__init__( debug_conf )
    self.client_tls_record_counter = 1
    self.server_tls_record_counter = 1
    self.client_tls_msg_counter = 1
    self.server_tls_msg_counter = 1

  def tls_record_byte( self, tls_msg ):
    """ returns the tls_Reccord bytes 

    For received TLS record, these are stored in record_layer_bytes
    so this value is prefered.
    For sent TLS record, the bytes are formed using to_record_layer_bytes.
    """   
    if tls_msg.record_layer_bytes != b'':
      return tls_msg.record_layer_bytes    
    return tls_msg.to_record_layer_bytes() 

  def tls_record_struct( self, tls_msg ):
    if tls_msg.content_type == 'handshake' and isinstance( tls_msg.content, bytes ): 
      struct = tls.FragmentTLSPlaintext.parse( tls_msg.record_layer_bytes )
    else:
      struct = tls.TLSPlaintext.parse( tls_msg.to_record_layer_bytes() )

    return struct

  def content_byte( self, tls_msg ):
      """fragment / content of a TLS record / inner message
      """
      return tls_msg.to_record_layer_bytes()[ 5 : ] 

  def content_struct( self, tls_msg ):
    return self.tls_record_struct( tls_msg ) [ 'fragment' ]    
      

  def inner_content_bytes( self, tls_msg ):
    return tls_msg.to_inner_msg_bytes( ) 

  def inner_content_struct( self, tls_msg ):
    inner_msg = tls_msg.to_inner_msg_bytes( )  
    if tls_msg.content_type in [ 'handshake', 'application_data' ] and\
       isinstance( tls_msg.content, bytes ):
      struct = tls.FragmentTLSInnerPlaintext.parse( inner_msg, \
              type=tls_msg.content_type, 
              clear_text_msg_len=len( tls_msg.content ),\
              length_of_padding=len( tls_msg.zeros ) )
    else:
      struct = tls.TLSInnerPlaintext.parse( inner_msg, \
             type=tls_msg.content_type,
             length_of_padding=len( tls_msg.zeros ) )
    return struct


  def record_counter( self, tls_msg ):
    """ select appropriated TLS record counter to tls_msg """  
    if tls_msg.sender == 'client':
      msg_counter = self.client_tls_record_counter
    elif tls_msg.sender == 'server' :
      msg_counter = self.server_tls_record_counter
    else:
      raise ValueError( f"Invalid tls_msg.sender {tls_msg.sender}"\
              f"MUST be set to 'client' or 'server' " )   
    return msg_counter

  def msg_counter( self, tls_msg ):
    """ select appropriated TLS message counter to tls_msg """  
    if tls_msg.sender == 'client':
      msg_counter = self.client_tls_msg_counter
    elif tls_msg.sender == 'server' :
      msg_counter = self.server_tls_msg_counter
    else:
      raise ValueError( f"Invalid tls_msg.sender {tls_msg.sender}"\
              f"MUST be set to 'client' or 'server' ")   
    return msg_counter


  def handle_tls_record( self, tls_msg, label="" ):
    counter = self.record_counter( tls_msg )  
    description = f"TLS record {counter} {tls_msg.descriptor( label=label )}"
    tls_msg_bytes = self.tls_record_byte( tls_msg ) 
    tls_msg_struct = self.tls_record_struct( tls_msg ) 
    self.handle_bin( description, tls_msg_bytes )
    if self.trace is True:
      self.trace_val( description, self.tls_record_struct( tls_msg ) )
    self.client_tls_record_counter += 1

  def handle_tls_msg( self, tls_msg, label="" ):
    """ handles tls message

    """
    counter = self.msg_counter( tls_msg )  
    description = f"TLS message {counter} {tls_msg.descriptor( label=label )}" 
    tls_msg_bytes = self.content_byte( tls_msg ) 
    tls_msg_struct = self.content_struct( tls_msg ) 
    self.handle_bin( description, tls_msg_bytes )
    if self.trace is True:
      self.trace_val( description, self.content_struct( tls_msg ) )

  def handle_inner_tls_msg( self, tls_msg, label="" ):
    """ handles tls message

    """
    msg_nbr = self.record_counter( tls_msg )
    description = f"Inner TLS message {msg_nbr} {tls_msg.descriptor( label=label )}" 
    tls_msg_bytes = self.inner_content_bytes( tls_msg ) 
    tls_msg_struct = self.inner_content_struct( tls_msg ) 
    self.handle_bin( description, tls_msg_bytes )
    if self.trace is True:
      self.trace_val( description, self.inner_content_struct( tls_msg ) )


  def dump( self ):
    with open( self.file, 'rw', encoding='utf8' ) as f:
      json.dump( self.db, f, indent=2 )

  
  def handle( key, value ):
    if self.mode == 'check':
      self.check( key, value )
    elif self.mode == 'write':
      self.add_value( key, value )
    else: 
      raise ValueError( f"Unknown mode {self.mode}" )
