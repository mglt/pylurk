"""
Test client / server communication with basic exchanges.

"""
from time import sleep
from pylurk.utils.utils import str2bool, tls12_client_server_exchanges


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Test basic client / server exchanges.')
    parser.add_argument('--connection_type', dest='connection_type', nargs='?', \
                        type=str, metavar='connection_type', default=None, \
                        help="""Sets the server connection type. Available connection 
                             types are  udp, tcp, tcp+tls, http, https'.
                             Unless specified, all connection types are tested.""")
    parser.add_argument('--background', dest='background', nargs='?', \
                        type=str2bool, metavar='background', default=True, \
                        help="""Defines if the server is started as background 
                             process when set to True. By default, the server is started
                             as a background process and background is
                             set to True.""")
    parser.add_argument('--thread', dest='thread', nargs='?', type=str2bool,\
                        metavar='thread', default=True, \
                        help="""Defines if the server is multithreaded. By default 
                             the server is multithreaded and thread is set to True.""")
    parser.print_help()
    print("""Typical usage:
             - Test all configurations ('udp', 'tcp', 'tcp+tls', 'http', 'https'.
               Default sets server in a background process and multithreading is
               enabled on the server :

               $ python3 tls12_client_server or
               $ python3 -m pylurk.tests.tls12_client_server

             - Test a specific configuration:

              $ python3 tls12_client_server.py --connection_type tcp --thread True
                                            --background False
              $ python3 -m pylurk.tests.tls12_client_server --connection_type tcp
                                            --thread True
                                            --background False """)

    args = parser.parse_args()
    if args.connection_type is None:
        for connection_type in ['udp', 'tcp', 'tcp+tls', 'http', 'https']:
            tls12_client_server_exchanges(connection_type, \
                background=args.background, \
                thread=args.thread)
            sleep(5)
    else:
        tls12_client_server_exchanges(args.connection_type,\
            background=args.background,\
            thread=args.thread)
