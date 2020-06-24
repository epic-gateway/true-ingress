'''
HTTP server to provide content of file requestd in RTL.
Started to listen on IP and PORT
'''

import string
import cgi
import time
import sys
from os import curdir, sep
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

class MyHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        try:
            print('requested: ' + self.path)
            f = open(self.path, 'rb')
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(f.read())
            f.close()
            print('done')
            return

        except IOError:
            self.send_error(404,'File Not Found: %s' % self.path)


def main(argv):
    print(argv)
    print(len(argv))

    if (len(argv) < 3):
        print("Usage: %s <ip> <port>" % argv[0])
        print("    <ip>   - IP where HTTP server will be listening on")
        print("    <port> - TCP port where HTTP server will be listening on")
        return 1

    try:
        print("Starting HTTP server on %s:%s" % (argv[1], argv[2]))
        server = HTTPServer((argv[1], int(argv[2])), MyHandler)
        print('running...')
        print('press ^C to stop')
        server.serve_forever()
    except KeyboardInterrupt:
        print('^C received, shutting down server')
        server.socket.close()

if __name__ == '__main__':
    main(sys.argv)
