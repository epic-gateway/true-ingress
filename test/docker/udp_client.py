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
        print("    <filename> - Files to download")
        return 1

    print("Downloading '%s' from %s:%s" % (argv[3], argv[1], argv[2]))

    # Open socket
    UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    UDPClientSocket.settimeout(1.0)
    
    # Send request
    UDPClientSocket.sendto(str.encode(argv[3]), (argv[1], int(argv[2])))

    path = "/tmp/%s" % (argv[3])
    print('full path: ' + path)
    f = open(path, 'wb')

    # Listen for response
    while(True):
        try:
            data, address = UDPClientSocket.recvfrom(4096)
            if (len(data) == 0):
                f.close()
                print('done')
                return 0
            else:
                print(len(data))
                f.write(data)
        except socket.timeout:
            print('REQUEST TIMED OUT')
            return 1

if __name__ == '__main__':
    main(sys.argv)
