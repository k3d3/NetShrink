#!/usr/bin/env python2.7 

import os
import sys
import socket
from base64 import b64encode, b64decode
from binascii import hexlify
import ConfigParser as configparser
from hashlib import sha256

import nacl
import pyev

DEF_PORT=24414
IDENTITY_FILE = ".identity"
WHITELIST_FILE = ".whitelist"
PEER_FILE = ".peers"

ip_header_size = 20
udp_header_size = 8
count_bytes_in = 0
count_bytes_out = 0

def c_recvfrom(sock, length):
    global count_bytes_in
    data, addr = sock.recvfrom(length)
    count_bytes_in += ip_header_size + udp_header_size + len(data)
    return data, addr
    
def c_sendto(sock, data, addr):
    global count_bytes_out
    count_bytes_out += ip_header_size + udp_header_size + len(data)
    return sock.sendto(data, addr)

def load_identity():
    if not os.path.exists(IDENTITY_FILE):
        return None, None, None
    name, public_key, secret_key = open(IDENTITY_FILE).readlines()
    name = name[:-1] # Removing the \n from the end
    public_key = b64decode(public_key[:-1])
    private_key = b64decode(secret_key[:-1])
    return name, public_key, secret_key
    
def save_identity(name, public_key, secret_key):
    a=open(IDENTITY_FILE,"w")
    a.write(name+"\n")
    a.write(b64encode(public_key)+"\n")
    a.write(b64encode(secret_key)+"\n")
    a.close()

def get_fingerprint(public_key):
    fingerprint = ""
    pkh = sha256(public_key).hexdigest().upper()
    for i in xrange(0,32,2):
        fingerprint += pkh[i:i+2]+":"
    return fingerprint[:-1]
    
def new_key_interface():
    global fingerprint
    print("Key does not exist, creating new key...")
    name = raw_input("Enter a name for this key: ")
    public_key, secret_key = nacl.crypto_sign_keypair()
    print("Your identity is:")
    print(name + " " + get_fingerprint(public_key))
    print("Verify this fingerprint is valid when connecting")
    save_identity(name, public_key, secret_key)
    return name, public_key, secret_key
    
def peer_exists(peer_name, pfile=PEER_FILE):
    peers = configparser.RawConfigParser()
    if peers.read(PEER_FILE) == []:
        return False
    return peers.has_section(peer_name)

def get_peer_public_key(peer_name, pfile=PEER_FILE):
    peers = configparser.RawConfigParser()
    peers.read(PEER_FILE)
    return b64decode(peers.get(peer_name,"public_key"))

def save_peer(peer_name, peer_public_key, pfile=PEER_FILE):
    peers = configparser.RawConfigParser()
    peers.read(PEER_FILE)
    try:
        peers.add_section(peer_name)
    except configparser.DuplicateSectionError:
        pass
    peers.set(peer_name,"public_key",b64encode(peer_public_key))
    peers.set(peer_name,"fingerprint",get_fingerprint(peer_public_key))
    peers.write(open(PEER_FILE,"w"))

connection_map = {}
config = None
conn_sock = None

class Connection:
    def __init__(self, sock, addr, peer_name, peer_public_key, peer_dhpk):
        self.sock = sock
        self.addr = addr
        self.peer_name = peer_name
        self.peer_public_key = peer_public_key
        self.peer_dhpk = peer_dhpk
        self.name, self.public_key, self.secret_key = load_identity()
        self.dhpk, self.dhsk = crypto_box_keypair()
        authpkt = '\0'
        authpkt += self.name + '\0'
        authpkt += nacl.crypto_sign(self.dhpk, self.secret_key)
        c_sendto(self.sock, authpkt, self.addr)
        
    def raw_recv(self, data):
        pass ''' CONTINUE HERE '''
        
    def recv(self, data):
        pass

def serve_cb(watcher, revents):
    global connection_map
    data, addr = c_recvfrom(sock, 4096)
    if addr not in connection_map:
        if data[0] != '\0': # DH Key Exchange Packet
            print("Ignoring garbage data from %s" % addr[0])
            return # Ignore this connection
        name_end = data.find("\0", 1)
        name = data[1:name_end]
        kexpkt = data[name_end+1:]
        if not peer_exists(name, pfile=WHITELIST_FILE):
            print("Ignoring unknown peer \"%s\" from %s" % (name, addr[0]))
            return # Ignore this connection
        try:
            peer_public_key = get_peer_public_key(name, pfile=WHITELIST_FILE)
            result = nacl.crypto_sign_open(kexpkt, peer_public_key)
        except Exception:
            print("Invalid signature from peer \"%s\" from %s" % (name, addr[0]))
            return # Ignore this connection
        print("Accepted connection from peer \"%s\" from %s" % (name, addr[0]))
        connection_map[addr] = Connection(conn_sock, addr, name,
                                          peer_public_key, result)
    else:
        connection_map[addr].raw_recv(data)

# COMMANDS
    
def serve(address="0.0.0.0",port=24414):
    global config, conn_sock
    name, public_key, secret_key = load_identity()
    if name is not None:
        print("Your identity is:")
        print(name + " " + get_fingerprint(public_key))
        print("Verify this fingerprint is valid when connecting")
    else:
        name, public_key, secret_key = new_key_interface()
    config = configparser.SafeConfigParser()
    config.read("netshrink.cfg")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    conn_sock = sock
    sock.bind((address,port))
    loop = pyev.default_loop()
    pyev.Io(sock, pyev.EV_READ, loop, serve_cb)
    print("Listening for new connections")
    loop.start()

def connect():
    name, public_key, secret_key = load_identity()
    if name is not None:
        print("Your identity is:")
        print(name + " " + get_fingerprint(public_key))
        print("Verify this fingerprint is valid when connecting")
    else:
        name, public_key, secret_key = new_key_interface()

def addpeer(address, port=DEF_PORT):
    name, public_key, secret_key = load_identity()
    if name is not None:
        print("Your identity is:")
        print(name + " " + get_fingerprint(public_key))
        print("Verify this fingerprint is valid when connecting")
    else:
        name, public_key, secret_key = new_key_interface()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    data = '\x01' + public_key + name
    c_sendto(sock, data, (address, port))
    print("Sent packet, waiting for response...")
    while True:
        data, addr = c_recvfrom(sock, 4096)
        if data[0] != '\x02': # getpeer packet
            print("Garbage packet ignored from %s" % addr[0])
            continue
        print("Got identity from %s" % addr[0])
        peer_public_key = data[1:33]
        peer_name = data[33:]
        print("Peer identity is \"%s %s\"" % \
              (peer_name, get_fingerprint(peer_public_key)))
        if peer_exists(peer_name):
            print("WARNING: Peer already exists. Saving this peer will"
                  " overwrite the existing key!")
        choice = raw_input("Do you want to save this peer (yes/no)? ")
        while True:
            if choice == "yes":
                save_peer(peer_name, peer_public_key)
                print("Peer saved.")
                break
            elif choice == "no":
                print("Peer not saved.")
                break
            else:
                choice = raw_input("Do you want to save this peer (yes/no)? ")
        print("The addpeer command has completed successfully.")
        print("Total bytes in:  %d" % count_bytes_out)
        print("Total bytes out: %d" % count_bytes_out)
        sys.exit(0)

def getpeer(address="0.0.0.0",port=DEF_PORT):
    name, public_key, secret_key = load_identity()
    if name is not None:
        print("Your identity is:")
        print(name + " " + get_fingerprint(public_key))
        print("Verify this fingerprint is valid when connecting")
    else:
        name, public_key, secret_key = new_key_interface()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((address,port))
    print("Listening for peers on %s:%d..." % (address, port))
    while True:
        data, addr = c_recvfrom(sock, 4096)
        if data[0] != '\x01': # addpeer packet
            print "Garbage packet ignored from %s" % addr[0]
            continue
        print("Got identity from %s" % addr[0])
        outdata = "\x02" + public_key + name
        c_sendto(sock, outdata, addr)
        peer_public_key = data[1:33]
        peer_name = data[33:]
        print("Peer identity is \"%s %s\"" % \
              (peer_name, get_fingerprint(peer_public_key)))
        if peer_exists(peer_name, pfile=WHITELIST_FILE):
            print("WARNING: Peer already exists. Saving this peer will"
                  " overwrite the existing key!")
        choice = raw_input("Do you want to save this peer (yes/no)? ")
        while True:
            if choice == "yes":
                save_peer(peer_name, peer_public_key, pfile=WHITELIST_FILE)
                print("Peer saved.")
                break
            elif choice == "no":
                print("Peer not saved.")
                break
            else:
                choice = raw_input("Do you want to save this peer (yes/no)? ")
        print("Listening for peers on %s:%d..." % (address, port))

def help():
    print("%s help\nTo be created" % sys.argv[0])
    sys.exit(0)

if __name__ == '__main__':
    arg = sys.argv[1:]
    if len(arg) == 0:
        help()
    if arg[0].lower() == "serve":
        if len(arg) == 0:
            serve()
        elif len(arg) == 1:
            serve(port=arg[1])
        elif len(arg) == 2:
            serve(address=arg[1], port=int(arg[2]))
        else:
            help()
    elif arg[0].lower() == "connect":
        if len(arg) == 1:
            connect(address=arg[1])
        elif len(arg) == 2:
            connect(address=arg[1], port=int(arg[2]))
        else:
            help()
    elif arg[0].lower() == "addpeer":
        if len(arg) == 2:
            addpeer(arg[1])
        elif len(arg) == 3:
            addpeer(arg[1], arg[2])
        else:
            help()
    elif arg[0].lower() == "getpeer":
        try:
            if len(arg) == 1:
                getpeer()
            elif len(arg) == 2:
                getpeer(port=int(arg[1]))
            elif len(arg) == 3:
                getpeer(address=arg[1], port=int(arg[2]))
            else:
                help()
        except KeyboardInterrupt:
            print("Total bytes in:  %d" % count_bytes_in)
            print("Total bytes out: %d" % count_bytes_out)
            sys.exit(0)
    elif arg[0].lower() == "help":
        help()
    else: # Assume we want to connect to a server
        if len(arg) == 1:
            connect(address=arg[0])
        elif len(arg) == 2:
            connect(address=arg[0], port=int(arg[2]))
        else:
            help()