#!/usr/bin/python3
'''
HTTP server to provide content of file requestd in RTL.
Started to listen on IP and PORT
'''

import sys
from socketserver import UDPServer, BaseRequestHandler

def create_request_handler(home_dir, chunk_size):
    class MyHandler(BaseRequestHandler):
        def __init__(self, request, client_address, server):
            self.home_dir = home_dir
            self.chunk_size = chunk_size
            super().__init__(request, client_address, server)

        def handle(self):
            message = self.request[0].strip()
            socket = self.request[1]

            try:
                # Sending a reply to client
                path = "%s/%s" % (self.home_dir, message.decode())
                f = open(path, 'rb')

                print("Sending '%s'" % (path))
                data = f.read()
                print(len(data))
                f.close()

                i = 0
                while(i < len(data)):
                    if (i + self.chunk_size <= len(data)):
                        sent = socket.sendto(data[i:i + self.chunk_size], self.client_address)
                        i += sent;
                        print(sent)
                    else:
                        sent = socket.sendto(data[i:], self.client_address)
                        i += sent;
                        print(sent)
                        break

                socket.sendto(b'', self.client_address)
                print('done')
            except FileNotFoundError:
                print("File '%s' not found" % (path))
                socket.sendto(b'', self.client_address)

    return MyHandler

def main(argv):
    print(argv)
    print(len(argv))

    if (len(argv) < 5):
        print("Usage: %s <ip> <port> <home-dir>" % argv[0])
        print("    <ip>       - IP where HTTP server will be listening on")
        print("    <port>     - TCP port where HTTP server will be listening on")
        print("    <home-dir> - Where to find files")
        print("    chunk_size - size of send buffer")
        return 1

    try:
        print("Starting UDP server on %s:%s, home '%s' (chunk size %s)" % (argv[1], argv[2], argv[3], argv[4]))
#        server = UDPServer((argv[1], int(argv[2])), MyHandler(argv[3]))
        server = UDPServer((argv[1], int(argv[2])), create_request_handler(argv[3], int(argv[4])))
        print('running...')
        print('press ^C to stop')
        server.serve_forever()
    except KeyboardInterrupt:
        print('^C received, shutting down server')
        server.socket.close()


if __name__ == '__main__':
    main(sys.argv)
