"""
Starts LURK Server. The server can be set with a specific connectivity
('udp', 'tcp', 'tcp+tls', 'http', 'https') with multithreading enabled
or not.
"""
from pylurk.utils.utils import start_server, str2bool


if __name__ == "__main__":
    import argparse
    conf = {'type':'udp'}
    parser = argparse.ArgumentParser(description='Start and run Lurk Server')
    parser.add_argument('--key', action='append', help="""Defines the Key of the connectivity configuration. It can take one of the following values 
                        ['type', 'ip_address', 'port', 'key', 'cert', 'key_peer', 'cert_peer', 'remote_user', 'password', path_to_erilurk']""")
    parser.add_argument('--value', action='append', help="""Defines the actual values given to the key corresponding to the preceding key argument""")
    parser.add_argument('--background', dest='background', nargs='?', \
                        type=str2bool, metavar='background', default=True, \
                        help="""Defines if the server is started as background 
                             process when set to True. By default, the server is started
                             as a background process and background is set to True.""")
    parser.add_argument('--thread', dest='thread', nargs='?', type=str2bool,\
                        metavar='thread', default=True, \
                        help="""Defines if the server is multithreaded. By default,
                             the server is multithreaded and it is set to True.""")

    parser.add_argument('--remote_connection', dest='remote_connection', nargs='?', \
                        type=bool, metavar='remote_connection', default=False, \
                        help="""Determines if a remote connection is desired. Default is set to False""")

    parser.print_help()
    args = parser.parse_args()
    connectivity_conf = {k: v for k, v in zip(args.key, args.value)}

    try:
       connectivity_conf['port'] = int (connectivity_conf['port'])
    except KeyError:
        pass

    start_server(connectivity_conf=connectivity_conf, \
                 background=args.background,\
                 thread=args.thread, \
                 remote_connection=args.remote_connection)






