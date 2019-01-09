"""
Test building and serving payload. This is usefull to test the tls12
extension. Payloads only are tested and there is no lurk header.

"""
from time import sleep
from pylurk.utils.utils import str2bool, tls12_serve_payloads


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Test build and serve ' +\
                'methods of the tls12 lurk extensions. Only payloads ' +\
                'are tested.')
    parser.print_help()
    print("""Typical usage:
             - Test all configurations ('udp', 'tcp', 'tcp+tls', 'http', 'https'.
               Default sets server in a background process and multithreading is
               enabled on the server :

               $ python3 -m pylurk.tests.tls12_serve_payloads """)

    tls12_serve_payloads(silent=True)
