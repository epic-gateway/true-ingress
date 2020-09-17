#!/usr/bin/python3
'''
HTTP server to provide content of file requestd in RTL.
Started to listen on IP and PORT
'''

import sys
import socket

def main(argv):
    print(argv)
    print(len(argv))

    if (len(argv) < 4):
        print("Usage: %s <ip> <port> <home-dir>" % argv[0])
        print("    <ip>       - IP where HTTP server will be listening on")
        print("    <port>     - TCP port where HTTP server will be listening on")
        print("    <home-dir> - Where to find files")
        return 1

    print("Starting UDP server on %s:%s, home '%s'" % (argv[1], argv[2], argv[3]))

    # Create a datagram socket
    UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

    # Bind to address and ip
    UDPServerSocket.bind((argv[1], int(argv[2])))

    print('running...')
    print('press ^C to stop')

    # Listen for incoming datagrams
    while(True):
        try:
            message, address = UDPServerSocket.recvfrom(1024)

            # Sending a reply to client
            path = "%s/%s" % (argv[3], message.decode())
            print('full path: ' + path)
            f = open(path, 'rb')

            while(True):
                data = f.read(1520)
                print(len(data))
                if (len(data) > 0):
                    sent = UDPServerSocket.sendto(data, address)
                    print(sent)
                else:
                    break

            f.close()
            print('done')
            UDPServerSocket.sendto(b'', address)
        except FileNotFoundError:
            print("File '%s' not found" % (path))
            UDPServerSocket.sendto(b'', address)
        
        except KeyboardInterrupt:
            print('^C received, shutting down server')
            server.socket.close()
            return 0

if __name__ == '__main__':
    main(sys.argv)
