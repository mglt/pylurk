"""
Starts LURK Server. The server can be set with a specific connectivity
('udp', 'tcp', 'tcp+tls', 'http', 'https') with multithreading enabled
or not. 
"""
from pylurk.utils.utils import start_server, str2bool


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Start and run Lurk Server')
    parser.add_argument('--connection_type', dest='connection_type', nargs='?', \
                        type=str, metavar='connection_type', default='udp', \
                        help="""Sets the server connection type. Available connection 
                             types are  udp, tcp, tcp+tls, http, https'.
                             Unless specified, 'udp' is considered.""")
    parser.add_argument('--background', dest='background', nargs='?', \
                        type=str2bool, metavar='background', default=True, \
                        help="""Defines if the server is started as background 
                             process when set to True. By default, the server is started
                             as a background process and background is set to True.""")
    parser.add_argument('--thread', dest='thread', nargs='?', type=str2bool,\
                        metavar='thread', default=True, \
                        help="""Defines if the server is multithreaded. By default,
                             the server is multithreaded and it is set to True.""")

    parser.add_argument('--remote_host', dest='remote_host', nargs='?', \
                        type=str, metavar='remote_user', default=None, \
                        help="""Defines the remote host the server runs on. 
                             The host can be a FQDN, or an IP address. Unless specified, 
                             the server is started locally. This is the default behavior. 
                             When specified, the server is started on the remote host 
                             using SSH, so SSH must be enabled on the remote host.""")
    parser.add_argument('--remote_user', dest='remote_user', nargs='?', \
                        type=str, metavar='remote_user', default=None, \
                        help="""Defines the user of the remote host the server runs on. 
                             remote_user is only considered when
                             remote_host is specified.""")
    parser.print_help()

    args = parser.parse_args()
    start_server(connection_type=args.connection_type, \
                 background=args.background,\
                 thread=args.thread, \
                 remote_host=args.remote_host, \
                 remote_user=args.remote_user)



