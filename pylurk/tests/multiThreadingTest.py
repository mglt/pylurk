"""
Test client / server communication with basic exchanges.

"""
from copy import deepcopy
from time import sleep
import multiprocessing as mp
import pkg_resources

from pylurk.core.conf import default_conf
from pylurk.core.lurk import LurkConf, ConfError, \
                             LurkUDPClient, LurkUDPServer, \
                             LurkTCPClient, LurkTCPServer, \
                             LurkHTTPClient, LurkHTTPServer
from pylurk.utils.utils import resolve_exchange


data_dir = pkg_resources.resource_filename(__name__, '../data/')

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

def set_lurk(role, **kwargs):
    """ set lurk client or server

    Set a LURK client or LURK server with specific connectivity
    parameters.

    Args:
        connection_type (str): the type of connectivity. Acceptable values are 'udp',
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
        connection_type = kwargs['connection_type']
    except KeyError:
        connection_type = 'udp'
    try:
        ip_address = kwargs['ip_address']
    except KeyError:
        ip_address = '127.0.0.1'
    try:
        port = kwargs['port']
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
    conf.set_connectivity(type=connection_type, ip_address=ip_address, port=port)

    role_list = ['client', 'server']
    connection_type_list = ['udp', 'udp+dtls', 'tcp', 'tcp+tls', 'http', 'https']
    if role not in role_list:
        ConfError(role, "UNKNOWN. Expecting value in %s"%role_list)
    if connection_type not in connection_type_list:
        ConfError(connection_type, "UNKNOWN connection_type. Expecting value " +\
                  "in %s"%connection_type_list)

    if role == 'client':
        print("Setting client %s"%connection_type)
        if connection_type in ['udp', 'udp+dtls']:
            client = LurkUDPClient(conf=conf.get_conf())
        elif connection_type in ['tcp', 'tcp+tls']:
            client = LurkTCPClient(conf=conf.get_conf())
        elif connection_type in ['http', 'https']:
            client = LurkHTTPClient(conf=conf.get_conf())
        return client

    elif role == 'server':
        print("Setting server %s"%connection_type)
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

def test_basic_exchanges(connection_type, background=True, thread=True):
    """ Testing basic exchanges between LURK client / Server

    Tests basic exchanges with a basic LURK client / LURK server
    configuration. It takes the default values for ip_address and port

    Args:
        connection_type (str): the connection_type of connectivity. Acceptable values are 'udp',
            'tcp', 'tcp+tls', 'http', 'https'. The default value is 'udp.
        background (bool): starts the LURK server in a daemon process
            when set to True.
        thread (bool): enables multithreading of the LURK server when
            set to True.

    """

    print(set_title(connection_type.upper() + " LURK CLIENT / SERVER - MULTI-Threads TESTS" +\
                 " - background: %s, thread: %s"%(background, thread)))
    if background is True:
        server = set_lurk('server', connection_type=connection_type,
                          background=background, thread=thread)
        sleep(3)
    client = set_lurk('client', connection_type=connection_type)

    designation = 'tls12'
    version = 'v1'

    for mtype in ['rsa_master', 'ecdhe', 'ping', 'rsa_extended_master', \
                   'capabilities']:
        if mtype in ['ping', 'capabilities']:
            resolve_exchange(client, designation, version, mtype,\
                              payload={}, silent=True)
            continue
        for freshness_funct in ["null", "sha256"]:
            print("---- %s, %s"%(mtype, freshness_funct))
            resolve_exchange(client, designation, version, mtype,
                             payload={'freshness_funct' :freshness_funct}, silent=False)
    if background is True:
        server.terminate()
    client.closing()

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

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Test basic client / server exchanges.')
    parser.add_argument('--connection_type', dest='connection_type', nargs='?', \
                        type=str, metavar='connection_type', default=None, \
                        help='comm. type udp, tcp, tcp+tls, http, https')
    parser.add_argument('--background', dest='background', nargs='?', \
                        type=str2bool, metavar='background', default=True, \
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

              $ python3 multiThreadingTest --connection_type tcp --thread True
                                           --background False
              $ python3 -m pylurk.tests.multiThreadingTest --connection_type tcp
                                           --thread True
                                            --background False """)

    args = parser.parse_args()
    if args.connection_type is None:
        for connection_type in ['udp', 'tcp', 'tcp+tls', 'http', 'https']:
            test_basic_exchanges(connection_type, background=args.background, \
                                 thread=args.thread)
            sleep(5)
    else:
        test_basic_exchanges(args.connection_type, background=args.background,\
                             thread=args.thread)
