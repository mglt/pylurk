import sys
import os
import signal
import binascii
import multiprocessing as mp
import pkg_resources
data_dir = pkg_resources.resource_filename(__name__, '../data/')

##sys.path.append(os.path.abspath("../"))

from os.path import isfile
from copy import deepcopy
from time import sleep
from Cryptodome.PublicKey import RSA, DSA, ECC
from Cryptodome.Hash import HMAC, SHA256, SHA512
from Cryptodome.Signature import pkcs1_15, DSS
from Cryptodome.Cipher import PKCS1_v1_5
from fabric import Connection


from time import time

#from pylurk.core.lurk import *
from pylurk.core.conf import default_conf
from pylurk.core.lurk import LurkConf, ConfError, ImplementationError, \
                             LurkMessage, LurkServer, \
                             LurkUDPClient, LurkUDPServer, \
                             LurkTCPClient, LurkTCPServer, \
                             LurkHTTPClient, LurkHTTPServer
from pylurk.extensions.tls12 import Tls12EcdheConf

## client server high level testing


def check_request_response( request, response, designation, \
                            version, mtype ):
    """Checks request/response match expected exchange

    Checks if the request and response match a given type of exchange
    defined by (designation, type, version). In addition, response is 
    checks against the request.

    Args:
        request (dict): the request expressed as a dictionary
        response (dict): the response expressed as a dictionary
        designation (str): the extension of the exchange. Typical values
            may be 'lurk' or 'tls12'
        version (int): the version of the designation
        mtype (str): the type of request within the extension
            (designation, version)

    Raises:
        ImplementationError when an unexpected value is found.
    
    """
    if request[ 'designation' ] != designation : 
        raise ImplementationError( request, \
            "Expected designation : %s."%designation )
    if request[ 'version' ] != version : 
        raise ImplementationError( request, \
            "Expected version : %s."%version )
    if request[ 'status' ] != 'request' :\
        raise ImplementationError( request, \
            "Expected status : 'request'")
    if request[ 'type' ] != mtype :\
        raise ImplementationError( request, \
            "Expected type : %s"%mtype)
    if response[ 'designation' ] != designation : 
        raise ImplementationError( response, \
            "Expected designation : %s."%designation )
    if response[ 'version' ] != version : 
        raise ImplementationError( response, \
            "Expected version : %s."%version )
    if response[ 'status' ] != 'success' :\
        raise ImplementationError( response, \
            "Expected status : 'success'")
    if request[ 'type' ] != mtype :\
        raise ImplementationError( response, \
            "Expected type : %s"%mtype)
    #converting id to int
    for message in [ request, response ]:
        if type( message[ 'id' ] ) == bytes:
            message[ 'id' ] = int.from_bytes( message[ 'id' ], 'big' )

    if request[ 'id' ] != response[ 'id' ] :
        raise ImplementationError( (request[ 'id'], response[ 'id' ] ),\
            "Expected matching id" )

def message_exchange( designation, version, mtype,  \
                 payload={}, silent=False ):
    """ generates an prints a valid query / response using LurkMessage  

    This function is useful to test the development of a Lurk Extension. 
    By using the LurkMessage, there is no client / server communication using 
    transport layer such as tcp, udp nor the handling of such communication 
    protocols. 

    Args:
        designation (str): the extension of the exchange. Typical values
            may be 'lurk' or 'tls12'
        version (int): the version of the designation
        mtype (str): the type of request within the extension
            (designation, version)
        payload (dict): the dictionary that represent the Lurk payload
            parameters. These parameters do not include the parameters of the 
            Lurk Header. 
        
    """
    print("\n-- testing: desig.: %s, vers.: %s "%(designation, version) +\
          "mtype: %s"%(mtype))
    print( ">> Request")
    msg = LurkMessage()
    header = {'designation':designation, 'version': version, \
              'type':mtype, 'status':"request" }
    request_bytes = msg.build( **header, payload=payload   ) 
    msg.show( request_bytes )
    request = msg.parse( request_bytes )
    
    print("<< Response")
    response = msg.serve( request )
    response_bytes = msg.build( **response )
    msg.show( response_bytes)

    if silent == False:
        pass 
    check_request_response( request, response, designation, \
                            version, mtype )

def resolve_exchange( client, designation, version, mtype,  \
                 payload={}, silent=False):
    """ generates an prints a valid query / response using resolve  

    This function tests a request/response exchange performed by a Lurk
    Client and a Lurk Server.

    Args:
        client (obj): instance of a Client object. The object needs to
            have a resolve function.  
        designation (str): the extension of the exchange. Typical values
            may be 'lurk' or 'tls12'
        version (int): the version of the designation
        mtype (str): the type of request within the extension
            (designation, version)
        payload (dict): the dictionary that represent the Lurk payload
            parameters. These parameters do not include the parameters of the 
            Lurk Header. 
        silent (bool): indicates if request/response needs to be
            displayed or not. By default, silent is set to False and request /
            responses are displayed. 

    """
    time_start = time()
    resolutions, errors = client.resolve( [{'designation' : designation, \
                      'version' : version,'status'  : "request", \
                      'type' : mtype, 'payload' : payload}] )
    time_stop = time()
    print("    -- type: %s -> %s sec"%(mtype, time_stop - time_start))
    try:
        request = resolutions[0][0]
        response = resolutions[0][1]
    except IndexError:
        print("resolutions: %s"%resolutions)
        print("errors: %s"%errors)
        raise ImplementationError(resolutions, "No response received")   

    if silent == False:
        msg = LurkMessage()
        print( ">> Request")
        msg.show( request )
        print( "<< Response")
        msg.show( response )
        print( "\n" )

    check_request_response( request, response, designation, \
                            version, mtype )

def set_title(title):
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
    return h_line + '|' + title + '|\n' + h_line + '\n\n'

def default_param(role, **kwargs):
    """ Returns necessary parameters to tests client server

    Enables default settings for testing various testing configuration.
    When the parameters are not provided, it takes various default
    values. This parameters are usually used to start a LURK Client and a
    LURK Server.  
   
    Arg:
        connectivity (dict): a connectivity object, that is a
            dictionary with all connectivity parameters. {'type': , 
            'ip_address': , 'port', 'key': , 'cert': , 'key_peer': , 
            'cert_peer': }. Deafult values are those provided by
            default_conf 
        background (bool): indicates the server is started in background 
            thread. Default value is set to True
        thread (bool): indicates whether the server is multithreaded or
            not. The default value is True.

    Returns:
        conf (obj): a LurkConf object, that contains the appropriated
            configuration file
        background (bool): indication whether is put in a background
            process or not
        thread (bool): indication whether the serve ris mutlithreaded or
            not 
    """
    conn = {}
    for k in ['type', 'ip_address', 'port', 'key', 'cert', \
              'key_peer', 'cert_peer']:
        try:
            conn[k]=kwargs['connectivity'][k]
        except KeyError:
            conn[k] = deepcopy(default_conf['connectivity'][k])
    conf = LurkConf(conf=deepcopy(default_conf))
    conf.set_role(role)
    conf.set_connectivity(**conn)
    try:
        background = kwargs['background']
    except KeyError:
        background = True
    try:
        thread = kwargs['thread']
    except KeyError:
        thread = True

    return conf, background, thread 


def set_lurk(role, **kwargs):
    """ set lurk client or server

    Set a LURK client or LURK server with specific connectivity
    parameters.

    Args:
        connectivity: dictionary containing the connectivity information as follows:
         connectivity = {
              'type' : "udp",  # "local", "tcp", "tcp+tls", http, https
              'ip_address' : "127.0.0.1", #can be the remote_host if remote connection is desired
              'port' : 6789,
              'key' : join( data_dir, 'key_tls12_rsa_server.key'),
              'cert' : join( data_dir, 'cert_tls12_rsa_server.crt'),
              'key_peer' : join( data_dir, 'key_tls12_rsa_client.key'),
              'cert_peer' : join( data_dir, 'cert_tls12_rsa_client.crt'),

    }
        background (bool): starts the LURK server in a daemon process
            when set to True.
        thread (bool): enables multithreading of the LURK server when
            set to True.

    """
    try:
        resolver_mode = kwargs['resolver_mode']
    except KeyError:
        resolver_mode = 'stub'

    conf, background, thread = default_param(role, **kwargs)
    connection_type = conf.get_conf()['connectivity']['type']

    if role == 'client':
        print("Setting client %s"%connection_type)
        if connection_type in ['udp', 'udp+dtls']:
            client = LurkUDPClient(conf=conf.get_conf(), \
                                   resolver_mode=resolver_mode)
        elif connection_type in ['tcp', 'tcp+tls']:
            client = LurkTCPClient(conf=conf.get_conf(), \
                                   resolver_mode=resolver_mode)
        elif connection_type in ['http', 'https']:
            client = LurkHTTPClient(conf=conf.get_conf(), \
                                    resolver_mode=resolver_mode)
        return client
    elif role == 'server':
        print("Setting server %s"%connection_type)

        #initialize server
        server=None

        if connection_type in ['udp', 'udp+dtls']:
            if background is True:
                server = mp.Process(target=LurkUDPServer, args=(conf.get_conf(),),\
                   kwargs={'thread' : thread}, name="%s server"%connection_type, daemon=True)
            else: #background == False:
                server = LurkUDPServer(conf.get_conf(), thread=thread)
        elif connection_type in ['tcp', 'tcp+tls']:
            if background is True:
                server = mp.Process(target=LurkTCPServer, args=(conf.get_conf(),),\
                   kwargs={'thread' : thread}, name="%s server"%connection_type, daemon=True)
            else: # background == False:
                server = LurkTCPServer(conf.get_conf(), thread=thread)
        elif connection_type in ['http', 'https']:
            if background is True:
                server = mp.Process(target=LurkHTTPServer, args=(conf.get_conf(),),\
                   kwargs={'thread' : thread}, name="%s server"%connection_type, daemon=True)
            else: #background == False:
                server = LurkHTTPServer(conf.get_conf(), thread=thread)
        if background is True:
            server.start()
            return server 



def lurk_serve_payloads(silent=True):
    """ Tests lurk classes build and serve methods 

    While all classes are tested individually, the classes are called
    via the LURK Extension module. This mimique the way classes of an
    extension are called by the server.
    
    """
    from pylurk.extensions.lurk import LurkExt
    lurk_ext = LurkExt()
    designation = 'lurk'
    version = 'v1'
    for mtype in ['ping', 'capabilities']:
        req = lurk_ext.ext_class[('request', mtype)]
        resp = lurk_ext.ext_class[('success', mtype)]
        try:
            payload={}
            req_payload = req.build_payload(**payload)
            if silent is False:
                 req.show(req_payload)
            time_start = time()
            res_payload = resp.serve(req_payload)
            time_stop = time()
            print("    -- type: %s -> %s sec"%(mtype, time_stop - time_start))
            if silent is False:
                resp.show(res_payload)
        except Exception as err:
            raise ImplementationError((mtype, payload), err)





def lurk_client_server_exchange(connection_type, background=True, thread=True):
    """ Testings basic exchanges between LURK CLient and LURK Server
  
    The function instantiates a client and a server, connects them with
    the defined connectivity, and tests teh various payloads. 
  
    LURK client / LURK server takes the default values for ip_address 
    and port
  
    Args:
     connection_type (str): the connection_type of connectivity.
         Acceptable values are 'udp','tcp', 'tcp+tls', 'http', 
         'https'. The default value is 'udp.
     background (bool): starts the LURK server in a daemon process
         when set to True.
     thread (bool): enables multithreading of the LURK server when
         set to True.
    """
  
    print(set_title(connection_type.upper() + \
                 " LURK CLIENT / SERVER - MULTI-Threads TESTS" +\
                 " - background: %s, thread: %s"%(background, thread)))
    connectivity = {'type': connection_type}
    if background is True:
        server = set_lurk('server', connectivity=connectivity,
                          background=background, thread=thread)
        sleep(3)
    resolution_mode = 'stub'
    client = set_lurk('client', connectivity=connectivity, \
                      resolution_mode=resolution_mode)
  
    designation = 'lurk'
    version = 'v1'
  
    try:
        for mtype in ['ping', 'capabilities']:
            print("-- %s, %s, %s "%(designation, version, mtype))
            resolve_exchange(client, designation, version, mtype,\
                                 payload={}, silent=True)
        if background is True:
            server.terminate()
        client.closing()
    except Exception as err:
        header = {'designation':designation, 'version': version, \
                  'type':mtype, 'status':"request" }
        raise ImplementationError(header, err)





def tls12_conf_ecdhe_payloads():
    """ returns payloads associated to various configuration parameters

    The returned payloads test all configuration parameters associated
    to ecdhe authentication.

    Returns:
        payloads (lst): list of payloads

    Todo:
        read parameters values from default_conf
    """

    payloads = []
    for freshness_funct in ["null", "sha256"]:
        for ecdhe_curve in ['secp256r1', 'secp384r1', 'secp521r1' ]:
            ecdhe_private = Tls12EcdheConf().default_ecdhe_private(\
                                        ecdhe_curve=ecdhe_curve)
            for h, sig in [('sha256', 'rsa'), ('sha512', 'rsa'),\
                                 ('sha256', 'ecdsa'), ('sha512', 'ecdsa')]:
                sig_and_hash = {'sig':sig, 'hash':h}
                for poo_prf in [ "null", "sha256_128", "sha256_256" ]:
                    payloads.append({'freshness_funct':freshness_funct, \
                                     'ecdhe_private':ecdhe_private,\
                                     'poo_prf':poo_prf,\
                                     'sig_and_hash':sig_and_hash})
    return payloads

def tls12_conf_rsa_payloads():
    """ returns payloads associated to various configuration parameters

    The returned payloads test all configuration parameters associated
    to rsa authentication methods.

    Returns:
        payloads (lst): list of payloads

    Todo:
        read parameters values from default_conf
    """

    payloads = []
    for freshness_funct in ["null", "sha256"]:
        for prf_hash in [ "sha256", "sha384", "sha512" ]:
            payloads.append({'freshness_funct':freshness_funct,\
                             'prf_hash':prf_hash})
    return payloads


def tls12_serve_payloads(silent=False):
    """ Tests tls12 classes build and serve methods

    """
    from pylurk.extensions.tls12 import LurkExt
    lurk_ext = LurkExt('server')
    designation = 'tls12'
    version = 'v1'
    for mtype in [\
                  'rsa_master', 'rsa_master_with_poh',  \
                  'rsa_extended_master', 'rsa_extended_master_with_poh', \
                  'ecdhe', \
                  'ping', 'capabilities']:
        print("-- %s, %s, %s "%(designation, version, mtype))
        req = lurk_ext.ext_class[('request', mtype)]
        resp = lurk_ext.ext_class[('success', mtype)]
        try:

            if mtype in ['ping', 'capabilities']:
                payloads =[{}]
            elif 'rsa' in mtype:
                payloads = tls12_conf_ecdhe_payloads()
            elif mtype == 'ecdhe':
                payloads = tls12_conf_ecdhe_payloads()

            for payload in payloads:
                req_payload = req.build_payload(**payload)
                if silent is False:
                    req.show(req_payload)
                time_start = time()
                res_payload = resp.serve(req_payload)
                time_stop = time()
                print("    -- type: %s -> %s sec"%(mtype, time_stop - time_start))
                if silent is False:
                    resp.show(res_payload)
        except Exception as err:
            raise ImplementationError((mtype, payload), err)


def tls12_client_server_exchanges(connection_type, background=True, thread=True):
    """ Testing basic exchanges between LURK client / Server

    The function instantiates a client and a server, connects them with
    the defined connectivity, and tests the various payloads. 

    LURK client / LURK server takes the default values for ip_address and port

    Note that with ecdhe, the ecdhe_private key is generated outside th3
    payload generation as the private key is needed to generates the
    ecdhe_params as well as the poo (with prf_poo different from
    'null'). Providing 'ecdhe_private' in the payload insures the same
    key is used to generate ecdhe_params as well as the poo. If not
    provided poo cannot be generated and an error is raised.   

    Args:
        connection_type (str): the connection_type of connectivity.
            Acceptable values are 'udp','tcp', 'tcp+tls', 'http', 
            'https'. The default value is 'udp.
        background (bool): starts the LURK server in a daemon process
            when set to True.
        thread (bool): enables multithreading of the LURK server when
            set to True.

    """

    print(set_title(connection_type.upper() + " LURK CLIENT / SERVER - MULTI-Threads TESTS" +\
                 " - background: %s, thread: %s"%(background, thread)))
    connectivity = {'type': connection_type}
    if background is True:
        server = set_lurk('server', connectivity=connectivity,\
                          background=background, thread=thread)
        sleep(3)
    resolution_mode = 'stub'
    client = set_lurk('client', connectivity=connectivity, \
                      resolution_mode=resolution_mode)

    designation = 'tls12'
    version = 'v1'

    try:
        for mtype in [\
                      'rsa_master', 'rsa_master_with_poh',  \
                      'rsa_extended_master', 'rsa_extended_master_with_poh', \
                      'ecdhe', \
                      'ping', 'capabilities']:
            print("-- %s, %s, %s "%(designation, version, mtype))

            if mtype in ['ping', 'capabilities']:
                payloads =[{}]
            elif 'rsa' in mtype:
                payloads = tls12_conf_rsa_payloads()
            elif mtype == 'ecdhe':
                payloads = tls12_conf_ecdhe_payloads()
            for payload in payloads:
                resolve_exchange(client, designation, version, mtype,\
                                 payload=payload, silent=True)
        if background is True:
            server.terminate()
        client.closing()
    except Exception as err:
        header = {'designation':designation, 'version': version, \
                  'type':mtype, 'status':"request" }
        raise ImplementationError((header, payload), err)

def str2bool(value):
    """ Interpret output as Booleann value

    Boolean value can be expressed through various ways. This function
    get the inputs and deduce the corresponding boolean value.

    Args:
        value (str): input value that represent a boolean. Considered values
            are: 'yes'/'no', 'y'/'n', 'true'/'false', 't'/'f', '1'/'0

    Returns:
        bool (bool): corresponding boolean value
    """

    if value.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    if value.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    raise argparse.ArgumentTypeError('Boolean value expected.')

def set_ssh(remote_host, remote_user, password):
    if remote_user is None or remote_host is None:
        raise ImplementationError("", "remote_user expected")
    return Connection(host=remote_host, user=remote_user,  connect_kwargs={
        "password": password, })


def start_server(connectivity, background=True, thread=True, \
                 remote_connection=False):

    """ This method start a local or remote server using ssh of any type
        (udp, udp+dtls, tcp, tcp+tls, hhtp, https)

    Args:
        - connectivity (dict) containing the connectivity information 
              as follows:
              connectivity = {
                 'type' : 'udp', # lurk server connectivity. Default value is
                      'udp'. Possible other values can be 'local, 'tcp', 
                      'tcp+tls', 'http', 'https'
                 'ip_address' : '127.0.0.1' # lurk server IP address. Default 
                      value is '127.0.0.1'. This parameter will be used 
                      by the lurk client as well as the by the ssh client 
                      to identify the host on which the lurk server is started. 
                 'port' : 6789, # lurk_server port. Default value is 6789
                 'key' : join( data_dir, 'key_tls12_rsa_server.key'), # the 
                      private key used for the TLS cryptographic
                      operations. As well as the key used for TLS session 
                      with the server (we shoudl have two different keys)
                 'cert' : join( data_dir, 'cert_tls12_rsa_server.crt'),
                 'key_peer' : join( data_dir, 'key_tls12_rsa_client.key'),
                 'cert_peer' : join( data_dir, 'cert_tls12_rsa_client.crt'),
                 'remote_user': 'xubuntu_server', #needed for ssh connection
                 'password:'123'#password to the remote server
                 'path_to_erilurk': 'Desktop/HyameServer/projects/erilurk' 
                      #path to erilurk project on remote server. Should be
                      remove when installation is performed with pip3 or
                      any package installation. 
              }
        - background: if set to true will start the server in the background 
              as a process. Doe not change much. WE SHOUDL REMOVE THIS PARAMETER
        - thread (bool): if set to true enables multi-threading on the server side
        - remote_connection (bool) : if set to true start the lurk
             server on a remote host via ssh. 
    Returns:
        - server: the object identifying the lurk server process. When
            executed remotely, server is the PID when executed local
            server is a process. Note that when executed remotely, the
            server is started as daemon. When executed locally, it is
            the responsibility of the function to maintain server
            running. Exiting the function kills the child processes even 
            when tagged as daemon. As a result the function is expected
            to do a server.join() to avoid killing the server.   
    """
    if remote_connection is False:
        server = set_lurk('server', connectivity=connectivity, \
                             background=background, thread=thread)
        sleep(5)
        return server.pid

    # default values to any missing parameters from the configuration to prevent error when running start server on the remote host
    updated_conf = {}
    for k in ['type', 'ip_address', 'port', 'key', 'cert', 'key_peer', 'cert_peer', 'remote_user', 'password',
              'path_to_erilurk']:
        try:
            updated_conf[k] = connectivity[k]
        except KeyError:
            try:
                if k in ['remote_user', 'password', 'ip_address', 'path_to_erilurk']:
                    print("Missing argument remote_host and/or remote_user and/or password and/or path_to_erilurk")
                    return
                else:
                    updated_conf[k]
            except KeyError:
                updated_conf[k] = deepcopy(default_conf['connectivity'][k])

    # connect to remote server
    remote_session = set_ssh(updated_conf['ip_address'], updated_conf['remote_user'], updated_conf['password'])

    with remote_session.cd(updated_conf['path_to_erilurk']):
        # use screen -d -m to keep the process running on remote server and continue to run the remaining code
        # todo check connection reset by peer issue when trying to set the keys
        # remote_session.run("screen -d -m python3 -m pylurk.utils.start_server --key type --value %s --key ip_address --value %s --key port --value %d --key key --value %s --key cert --value %s --key key_peer --value %s --key cert_peer --value %s --background False --thread %s" %(updated_conf['type'], updated_conf['ip_address'], updated_conf['port'], updated_conf['key'], updated_conf['cert'], updated_conf['key_peer'], updated_conf['cert_peer'], thread))#& echo $!

        remote_session.run(
            "screen -d -m python3 -m pylurk.utils.start_server --key type --value %s --key ip_address --value %s --key port --value %d  --background False --thread %s" % (
            updated_conf['type'], updated_conf['ip_address'], updated_conf['port'], thread))  # & echo $!

    # wait till server gets started
    sleep(10)

    # get the process of the launched server which will be of the for ip_address:port
    processes = remote_session.run(
        "lsof -i -P -n | grep %s" % updated_conf['ip_address'] + ":" + str(updated_conf['port']))

    # return the process id of the launched server
    return int((str(processes.stdout).split())[1])



def stop_server(server, remote_host=None, remote_user=None, password = None):
    
    if isinstance(server, mp.context.Process) :
        server_pid = server.pid
    else:
        server_pid = int(server) 
    if remote_host is None:
        os.kill(server_pid, signal.SIGTERM)
        sleep(5)
        return
    elif remote_user is None:
        raise ImplementationError( "", "remote_user expected")
    remote_session = set_ssh(remote_host, remote_user, password)
    remote_session.run("kill -15 %s" %server_pid)







## server byte level testing


def bytes_error( bytes_ref, error_index, error_value='\xf0'):
   last_index = len( bytes_ref )
   if error_index == last_index:
        return bytes_ref[: last_index ] + value
   elif error_index >= 0 and error_index < last_index:
        return bytes_ref[: error_index] + value + bytes_ref[ error_index + 1 : ] 



def bytes_error_testing( server,  bytes_query_ref, error_table):
    msg = LurkMessage()
    for e in error_table:
        print("--- %s Error Testing"%e[0])
        for byte_index in  range(e[1] - e[2] ):
            response_bytes = server.byte_serve( bytes_error( bytes_query_ref,\
                                           byte_index ) ) 
            response = msg.parse( response_bytes ) 
            if response[ 'status' ] != error_status:
                raise ImplementationError( msg.show( response_bytes ), "expected %s"%e[3] )
               

def get_key_files( key_type, key_scope, key_format='der' ):
    """ check parameters for generate_keys and generate_x509 and returns
        key file names public, private """

    key_types  = [ 'rsa', 'dsa', 'ecc' ]
    if key_type not in [ 'rsa', 'dsa', 'ecc' ]:
        raise ConfError( key_type, "Expecting %s"%key_types )
    key_formats = [ 'der', 'pem' ]
    if key_format not in key_formats:
        raise ConfError( key_format, "Expecting %s"%key_formats )
    key_scopes = [ 'sig', 'enc' ]
    if key_scope not in key_scopes:
        raise ConfError( key_scope, "Expecting %s"%key_scope )
    file_pbl = "key-%s-%s-asn1.%s"%( key_type, key_scope, key_format)
    file_prv = "key-%s-%s-pkcs8.%s"%( key_type, key_scope, key_format)
    return file_pbl, file_prv

def generate_keys( key_type, key_scope, key_format='der' ):
    """ generates private and public keys:
        - key_type designates the type of the key: 'rsa', 'dsa', 'ecc'
        - key_format designates the key representation 'der' or 'pem'
        - key_scope designates the scope of the key: 'sig', 'enc' -- this is
          mostly for naming convention
        output files are:
            key-<key_type>-<key_scope>-{pkcs8,asn1}.<key_format>
    """
    pbl, prv = get_key_files( key_type, key_scope, key_format=key_format )

    if key_format == 'der':
        key_format = 'DER' 
    if key_format == 'pem':
        key_format = 'PEM'

    if key_type == 'rsa':
        key = RSA.generate(2048)
        bytes_prv = key.exportKey( key_format, pkcs=8)
        bytes_pbl = key.publickey().exportKey( key_format )
    elif key_type == 'dsa':
        key = DSA.generate(2048)
        bytes_prv = key.exportKey( key_format, pkcs8=True)
        bytes_pbl = key.publickey().exportKey( key_format)
    elif key_type == 'ecc':
        key = ECC.generate(curve='P-256')
        bytes_prv = key.export_key( format=key_format, use_pkcs8=True ) 
        bytes_pbl = key.public_key().export_key( format=key_format )
    else:
        raise ImplementationError( key_type, "Unknown key type" )

    with open( prv, 'wb' )  as f:
        f.write( bytes_prv )
    with open( pbl, 'wb' )  as f:
        f.write( bytes_pbl )

def get_keys(  key_type, key_scope, key_format='der' ):

    from cryptography.hazmat.primitives.serialization import \
        load_der_private_key, load_der_public_key, load_pem_private_key,\
        load_pem_public_key
    from cryptography.hazmat.backends import default_backend
    pbl, prv = get_key_files( key_type, key_scope, key_format=key_format )

    for file_name in [ pbl, prv ]:
        if isfile( file_name ) == False:
            generate_keys( key_type, key_scope, key_format=key_format )

    if key_format == 'der' :
        with open( prv, 'rb' )  as f:
            private_key = load_der_private_key( f.read(), \
                          password=None, backend=default_backend() )
        with open( pbl, 'rb' )  as f:
            public_key = load_der_public_key( f.read(), \
                          backend=default_backend() )
    elif key_format == 'pem' :
        with open( prv, 'rb' )  as f:
            privet_key = load_pem_private_key( f.read(), \
                          password=None, backend=default_backend() )
        with open( pbl, 'rb' )  as f:
            public_key = load_pem_public_key( f.read(), \
                          backend=default_backend() )
    
    return public_key, private_key


def generate_x509( key_type, key_scope, key_format='der' ):

    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime
    from cryptography.hazmat.primitives import serialization


    public_key, private_key = get_keys( key_type, key_scope, \
                                        key_format=key_format )

    subject = x509.Name([\
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CA"),\
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"QC"),\
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Montreal"),\
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),\
        x509.NameAttribute(NameOID.COMMON_NAME, u"www.example.com"),\
      ])

    issuer = subject
    builder = x509.CertificateBuilder()
    builder = builder.subject_name( subject )
    builder = builder.issuer_name( issuer )
    #builder.public_key( public_key.public_key() )
    builder = builder.public_key( public_key )
    builder = builder.serial_number( x509.random_serial_number() )
    builder = builder.not_valid_before( datetime.datetime.utcnow() )
    builder = builder.not_valid_after( 
            # Our certificate will be valid for 10 days
            datetime.datetime.utcnow() + datetime.timedelta(days=365 * 100 ) )
    builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"www.example.com")]),
            critical=False )
    # Sign our certificate with our private key
    cert = builder.sign( private_key, hashes.SHA256(), default_backend())
    # Write our certificate out to disk.
    cert_file = "cert-%s-%s.%s"%( key_type, key_scope, key_format)

    with open(cert_file, "wb") as f:
        if key_format == 'pem' :
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        if key_format == 'der' :
            f.write(cert.public_bytes(serialization.Encoding.DER))


## we are missing the edge_server
def vector_rsa_master( _cert, _premaster, _encrypted_premaster,\
                       _client_random, _server_random, _master,  \
                        key, lurk_rsa_conf ):
    """ test vector for rsa_master. "_" designates the measured
        informations by for example an ngnix / apache implementation. 
            - _cert:  public key or certificate used by the TLS Client
            - _premaster generated by the TLS client
            - _encrypted_premaster encrypted premaster provided by the 
              TLS Client
            - {_client, _server}_random : random used
            - key : private key used by the TLS Server
            - lurk_rsa_conf : 
    """

    print("\n --- checking compatibility between key / _cert" )
    lurk_rsa_conf.cert = [ _cert ]
    lurk_rsa_conf.key = [ key ]
    conf = Tls12RSAMasterConf( conf=lurk_rsa_conf)
    public_key = conf.read_key( _cert )
    private_key = conf.read_key( key )
    
    print("\n --- RSA Public / Private Keys" )
    for k in [ public_key, private_key ]:
        if k.has_private() == False:
           print( "    Public Key: %s"%{'n': k.n, 'e': k.e} )
        else:
           print("    Private Key: %s"%\
               {'n' : k.n, 'e' : k.e, 'd' : k.d, 'p' : k.p, 'q' : k.q} )

    print("\n --- checking encrypted premaster / premaster" )
    rsa_cipher = PKCS1_v1_5.new(public_key) 
    encrypted_premaster = rsa_cipher.encrypt( _premaster_secret ) 
    if encrypted_premaster != _encrytped_premaster:
        raise ImplementationError( (encrypted_premaster,_encrytped_premaster), \
            "Encrypting premaster with key does not result in measured " + \
            "_encrypted_premaster")

    rsa_cipher = PKCS1_v1_5.new(private_key)
    premaster = rsa_cipher.decrypt(_encrypted_premaster, b'\x00')
    if premaster != _premaster:
        raise ImplementationError( (premaster,_premaster), \
            "Decrypting _encrypted_premaster with key does not result " +\
            "in measured _premaster")

    
    print("\n --- parameters")
    premaster = Premaster.parse(_premaster )
    print("\n    - Premaster : %s"%binascii.hexlify(_premaster) )
    print("\n    - Premaster : %s"%premaster )
    print("\n    - EncryptedPremaster : %s"%binascii.hexlify(_encrypted_premaster) )
    client_random = Random.parse( _client_random )
    server_random = Random.parse( _server_random )
    print("\v    - Client Random: %s"%binascii.hexlify(_client_random ) )
    print("\v    - Client Random: %s"%client_random )
    print("\v    - Server Random: %s"%binascii.hexlify(_server_random ) )
    print("\v    - Server Random: %s"%server_random )

    ## would be good to also test with edge server... 
    payload_args = { 'cert' : _cert,\
                     'client_random' : client_random, \
                     'server_random' : server_random, \
                     'tls_version' : tls_version, \
                     'prf' : "sha256_null",
                     'encrypted_premaster' : encrypted_premaster }
    query, response = client.resolve( designation='tls12', \
                                  version='v1', \
                                  type='rsa_master', \
                                  payload=payload_args )

    master = binascii.hexlify( response[ 'master' ] )

    if master != _master:
        raise ImplementationError( (master,_master), \
            "ERROR: _master and master do not match!")
    print("\v    - Master: %s"%binascii.hexlify(_server_random ) )
    print("\v    - Server Random: %s"%server_random )


    print("LURK Query >>>>")
    msg.show( query )
    print("LURK Response <<<<")
    msg.show( response )




