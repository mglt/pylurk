from construct.core import *
from construct.lib import *
from pylurk.extensions.tls12_struct import FreshnessFunct, KeyPairId
from pylurk.extensions.tls13_tls13_struct import PskIdentity, Certificate,\
                                                  SignatureScheme

class Error(Exception):
    """ Generic Error class
    """
    def __init__(self, expression, message, status):
        self.expression = expression
        self.message = message
        self.status = status


class KeyReq:

  def __init__(self, ):
    self.struct = _KeyRequest
    self.struct_name = "KeyRequest"  
    self.available_secrets = ['b', 'e_s', 'e_x', 'h_c', 'h_s', 'a_c', 'a_s', 'x', 'r']
    self.rules = {\
      ('server', 'early_secret') : ['b','e_c*', 'e_x*'],\
      ('server', 'init_certificate_verify') : [ 'h_c', 'h_s', 'a_c*', 'a_s*', 'x*'],\
      ('server', 'handshake_and_app_secret') : ['h_c', 'h_s', 'a_c*', 'a_s*', 'x*'],\
      ('server', 'new_session_ticket') : ['r*'],\
      ('client', 'binder_key') : ['b'],\
      ('client', 'early_secret') : ['e_c*', 'e_x*'],\
      ('client', 'init_handshake_secret'): ['h_c', 'h_s'],\
      ('client', 'handshake_secret') : ['h_c', 'h_s'],\
      ('client', 'app_secret') : ['a_c*', 'a_s*', 'x*'],\
      ('client', 'certificate_verify') : ['a_c*', 'a_s*', 'x*'],\
      ('client', 'register_session_ticket') : ['r*'], \
      ('client', 'post_handshake') : [], }
    

  def check(self, role, exchange_type, key_req):
    """ checks requested secrets match the rules """
 
    rule = self.rules[(role, exchange_type)]
    for key in key_req.keys():
       if key not in self.available_secrets
         raise Error((role, exchange_type, key_req),\
                     "key not in available keys %s"%self.available_secrets,\
                     'invalid_key_request') 
       if key in rule and key_req[key] = True: ## mandatory keys
         continue
       else:                  ## optional (key*) or not mentioned in rule
         if key_req[key] == False:  ## not mentionned or optional set to False
           continue
         else:                      ## optional set to True
           if key+'*' in rule:      
             continue
       raise Error( (role, exchange_type, key_req),\
                    "key_req does not match the rules %s"%rule,\
                    'invalid_key_request') 

