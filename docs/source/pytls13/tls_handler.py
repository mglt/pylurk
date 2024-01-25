
class TLSAlert(Exception):
  def __init__(self, level:str,  description:str, message="" ):
    """ TLS Alert 
     
    Args:
      level the level of the alert (warning / fatal)
      description: the description of the alerte
      message (optional): additional description
    """
    self.level = level
    self.description = description
    self.message = message

class ServerTLSAlert( TLSAlert ):
  pass

class ClientTLSAlert( TLSAlert ):
  pass

