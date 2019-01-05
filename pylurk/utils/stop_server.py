"""
Starts LURK Server. The server can be set with a specific connectivity
('udp', 'tcp', 'tcp+tls', 'http', 'https') with multithreading enabled
or not. 
"""
from pylurk.utils.utils import stop_server, str2bool


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Stop Lurk Server')

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

    parser.add_argument('server_pid', nargs=1,
                        type=int, metavar='server_pid', help='PID of the Lurk Server')


    parser.print_help()

    args = parser.parse_args()
    stop_server(args.server_pid[0], \
                 remote_host=args.remote_host, \
                 remote_user=args.remote_user)



