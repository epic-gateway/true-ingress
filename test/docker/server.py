#!/usr/bin/python3
'''
HTTP server to provide content of file requestd in RTL.
Started to listen on IP and PORT
'''

import string
import cgi
import time
import sys
from os import curdir, sep
from http.server import HTTPServer, BaseHTTPRequestHandler

def create_request_handler(home_dir):
    class MyHandler(BaseHTTPRequestHandler):

        def __init__(self, request, client_address, server):
            self.home_dir = home_dir
            super().__init__(request, client_address, server)

        def do_GET(self):
            try:
                print('requested: ' + self.path)
                path = "%s%s" % (self.home_dir, self.path)
                print('full path: ' + path)
                f = open(path, 'rb')
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(f.read())
                f.close()
                print('done')
                return

            except IOError:
                self.send_error(404,'File Not Found: %s' % self.path)

    return MyHandler


def main(argv):
    print(argv)
    print(len(argv))

    if (len(argv) < 4):
        print("Usage: %s <ip> <port> <home-dir>" % argv[0])
        print("    <ip>       - IP where HTTP server will be listening on")
        print("    <port>     - TCP port where HTTP server will be listening on")
        print("    <home-dir> - Where to find files")
        return 1

    try:
        print("Starting HTTP server on %s:%s, home '%s'" % (argv[1], argv[2], argv[3]))
#        server = HTTPServer((argv[1], int(argv[2])), MyHandler)
        server = HTTPServer((argv[1], int(argv[2])), create_request_handler(argv[3]))
        print('running...')
        print('press ^C to stop')
        server.serve_forever()
    except KeyboardInterrupt:
        print('^C received, shutting down server')
        server.socket.close()

if __name__ == '__main__':
    main(sys.argv)
