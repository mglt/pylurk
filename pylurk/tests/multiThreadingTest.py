from  os.path import join
import multiprocessing as mp
from time import sleep
import threading
import pkg_resources
data_dir = pkg_resources.resource_filename( __name__, '../data/')
from copy import deepcopy
from pylurk.core.conf import default_conf

from pylurk.core.lurk import LurkConf, LurkUDPClient, LurkUDPServer, \
                                       LurkTCPClient, LurkTCPServer, \
                                       LurkHTTPClient, LurkHTTPServer
                 ## PoolMixIn, \
from pylurk.extensions.tls12 import Tls12RsaMasterConf,  Tls12EcdheConf, \
                       Tls12RsaMasterRequestPayload,\
                       Tls12ExtRsaMasterRequestPayload,\
                       Tls12EcdheRequestPayload

from pylurk.utils.utils import message_exchange, resolve_exchange, bytes_error_testing


def print_title(title):
    """ print title in a square box

    To enhance the readability of the tests, this function prints in the
    terminal teh string title in a square box.  

    Args:
        title (str): the string 
    """
    h_line = '+'
    for c in range(len(title) + 8):
        h_line += '-'
    h_line += '+\n'
    print(h_line + '|    ' + title + '    |\n' + h_line + '\n\n')

def set_lurk( role, **kwargs):
    """ set lurk client or server

    Set a LURK client or LURK server with specific connectivity
    parameters.

    Args:
        type (str): the type of connectivity. Acceptable values are 'udp',
            'tcp', 'tcp+tls', 'http', 'https'. The default value is 'udp.
        ip_address (str): the ip address of the LURK server. The default
            value is 127.0.0.1.
        port (int): the port value of the LURK server. Default value is 6789
        background (bool): starts the LURK server in a daemon process
            when set to True. 
        thread (bool): enables multithreading of the LURK server when
            set to True.  
        
    """

    try:
        type = kwargs['type']
    except KeyError:
        type='udp'
    try:
        ip_address = kwargs['ip_address']
    except KeyError:
        ip_address = '127.0.0.1'
    try:
        port=kwargs['port']
    except KeyError:
        port = 6789
    try:
        background = kwargs['background']
    except KeyError:
        background = True
    try:
        thread = kwargs['thread']
    except KeyError:
        thread = True

    conf = LurkConf(deepcopy(default_conf))
    conf.set_role(role)
    conf.set_connectivity( type=type, ip_address=ip_address, port=port)

    if role == 'client':
        print("Setting client %s"%type)
        if type in ['udp', 'udp+dtls']:
            return LurkUDPClient(conf=conf.get_conf())
        elif type in ['tcp', 'tcp+tls']:
            return LurkTCPClient(conf=conf.get_conf())
        elif type in ['http', 'https']:
            return LurkHTTPClient(conf=conf.get_conf())
        else: 
            print("UNKNOWN type: %s for client"%type)
    elif role == 'server':
        print("Setting server %s"%type)
        if type in ['udp', 'udp+dtls']:
            if background == True: 
                p = mp.Process(target=LurkUDPServer, args=(conf.get_conf(),),\
                   kwargs={'thread' : thread}, name="%s server"%type, daemon=True )
                p.start()
                return p
            else: #background == False: 
                LurkUDPServer(conf.get_conf(), thread=thread) 
        elif type in ['tcp', 'tcp+tls']: 
            if background == True:
                p = mp.Process(target=LurkTCPServer, args=(conf.get_conf(),),\
                   kwargs={'thread' : thread}, name="%s server"%type, daemon=True )
                p.start()
                return p
            else: # background == False: 
                LurkTCPServer(conf.get_conf(), thread=thread) 
        elif type in ['http', 'https']:
            if background == True:
                p = mp.Process(target=LurkHTTPServer, args=(conf.get_conf(),),\
                   kwargs={'thread' : thread}, name="%s server"%type, daemon=True )
                p.start()
                return p
            else: #background == False:
                LurkHTTPServer(conf.get_conf(), thread=thread)

        else: 
            print("UNKNOWN type: %s for server"%type)


def test_basic_exchanges(type, background=True, thread=True):
    """ Testing basic exchanges between LURK client / Server

    Tests basic exchanges with a basic LURK client / LURK server
    configuration. It takes the default values for ip_address and port 

    Args:
        type (str): the type of connectivity. Acceptable values are 'udp',
            'tcp', 'tcp+tls', 'http', 'https'. The default value is 'udp.
        background (bool): starts the LURK server in a daemon process
            when set to True. 
        thread (bool): enables multithreading of the LURK server when
            set to True.  
        
    """

    print_title( type.upper() + " LURK CLIENT / SERVER - MULTI-Threads TESTS" +\
                 " - background: %s, thread: %s"%(background, thread)) 
    if background == True:
        server = set_lurk('server', type=type, background=background, thread=thread)
        sleep(3)
    client = set_lurk('client', type=type)
    
    designation = 'tls12'
    version = 'v1'
    
    for mtype in [ 'rsa_master', 'ecdhe', 'ping', 'rsa_extended_master', \
                   'capabilities']:
        if mtype in [ 'ping', 'capabilities' ]:
            resolve_exchange( client, designation, version, mtype,\
                              payload={}, silent=True )
            continue
        for freshness_funct in [ "null", "sha256" ]:
            print("---- %s, %s"%(mtype, freshness_funct))
            resolve_exchange(client, designation, version, mtype,
                   payload={ 'freshness_funct' :freshness_funct}, silent=False)
    if background == True:
        server.terminate()
    client.closing()

def str2bool(v):
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Test basic client / server exchanges.')
    parser.add_argument('--type', dest='type', nargs='?', type=str, metavar='type', \
                    default=None, help='comm. type udp, tcp, tcp+tls, http, https')
    parser.add_argument('--background', dest='background', nargs='?', \
                    type=str2bool, metavar='background',  default=True, \
                    help="server started as background process")
    parser.add_argument('--thread', dest='thread', nargs='?', type=str2bool,\
                    metavar='thread', default=True, help="server is multithreaded")
    parser.print_help()
    print("""Typical usage:
             - Test all configurations ('udp', 'tcp', 'tcp+tls', 'http', 'https'. 
               Default sets server in a background process and multithreading is 
               enabled on the server : 
       
               $ python3 multiThreadingTest or  
               $ python3 -m pylurk.tests.multiThreadingTest

             - Test a specific configuration: 

              $ python3 multiThreadingTest --type tcp --thread True 
                                           --background False
              $ python3 -m pylurk.tests.multiThreadingTest --type tcp 
                                           --thread True 
                                            --background False """)
    
    args = parser.parse_args() 
    print(args)
    background = args.background
    thread = args.thread
    if args.type == None:
        for type in [ 'udp', 'tcp', 'tcp+tls', 'http', 'https']:
            test_basic_exchanges(type, background=background, \
                                 thread=thread)
            sleep(5)
    else: 
        test_basic_exchanges(args.type, background=background,\
                             thread=thread)


    
###    print( "+--------------------------------------------------------+" )
###    print( "|    HTTPS  LURK CLIENT / SERVER  - MULTI-Threads TESTS  |" )
###    print( "+--------------------------------------------------------+" )
###    
###    
###    print("-- Starting LURK HTTPS Clients")
###    clt_conf = LurkConf( )
###    clt_conf.set_role( 'client' )
###    clt_conf.set_connectivity( type='tcp', ip_address="127.0.0.1", port=6789 ) #keep to tcp?
###    client = LurkHTTPClient( conf = clt_conf.conf, secureTLS_connection=True )
###    
###    print("-- Starting LURK HTTPS Server")
###    srv_conf = LurkConf()
###    srv_conf.set_role( 'server' )
###    srv_conf.set_connectivity( type='tcp', ip_address="127.0.0.1", port=6789 )#keep to tcp?
###    
###    lurkHttpsServer = ThreadedLurkHTTPserver(srv_conf.conf, max_workers=7 , secureTLS_connection=True)
###    t = threading.Thread( target=lurkHttpsServer.serve_forever)
###    
###    t.daemon = True
###    t.start()
###    
###    designation = 'tls12'
###    version = 'v1'
###    
###    for mtype in [ 'rsa_master', 'ecdhe', 'ping', 'rsa_extended_master', \
###                    'capabilities']:
###        if mtype in [ 'ping', 'capabilities' ]:
###            resolve_exchange( client, designation, version, mtype, \
###                              payload={} )
###            continue
###        for freshness_funct in [ "null", "sha256" ]:
###            resolve_exchange( client, designation, version, mtype, \
###                              payload={ 'freshness_funct' : freshness_funct } )
###    
###    lurkHttpsServer.shutdown()
###    lurkHttpsServer.server_close()
