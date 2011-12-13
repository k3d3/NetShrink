#!/usr/bin/env python2.7 

import os
import sys
import socket
import struct
import atexit
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
    secret_key = b64decode(secret_key[:-1])
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
    if peers.read(pfile) == []:
        return False
    return peers.has_section(peer_name)

def get_peer_public_key(peer_name, pfile=PEER_FILE):
    peers = configparser.RawConfigParser()
    peers.read(pfile)
    return b64decode(peers.get(peer_name,"public_key"))

def save_peer(peer_name, peer_public_key, pfile=PEER_FILE):
    peers = configparser.RawConfigParser()
    peers.read(pfile)
    try:
        peers.add_section(peer_name)
    except configparser.DuplicateSectionError:
        pass
    peers.set(peer_name,"public_key",b64encode(peer_public_key))
    peers.set(peer_name,"fingerprint",get_fingerprint(peer_public_key))
    peers.write(open(pfile,"w"))

connection_map = {}
config = None
conn_sock = None

class ServeConnection:
    def __init__(self, sock, addr, peer_name, peer_public_key, peer_dhpk):
        global config
        self.sock = sock
        self.addr = addr
        self.peer_name = peer_name
        self.peer_public_key = peer_public_key
        self.name, self.public_key, self.secret_key = load_identity()
        dhpk, self.dhsk = nacl.crypto_box_keypair()
        self.kex_init = False
        self.key = nacl.crypto_scalarmult(self.dhsk, peer_dhpk)
        self.dhsk = None
        self.mac_bytes = config.getint("netshrink","mac_bytes")
        if self.mac_bytes > 32:
            self.mac_bytes = 32
        self.nonce_bytes = config.getint("netshrink","nonce_bytes")
        if self.nonce_bytes > 8:
            self.nonce_bytes = 8
        if self.nonce_bytes:
            self.nonce_prefix = nacl.crypto_auth(config.get("netshrink",
                                                            "nonce_prefix"),
                                             self.key)[:23-self.nonce_bytes]
        else:
            self.nonce_prefix = nacl.crypto_auth(config.get("netshrink",
                                                            "nonce_prefix"),
                                                 self.key)[:23]
        self.nonce = 0
        authpkt = '\0'
        authpkt += self.name + '\0'
        authpkt += nacl.crypto_sign(dhpk, self.secret_key)
        c_sendto(self.sock, authpkt, self.addr)
    
    def raw_recv(self, data):
        if self.mac_bytes > 0:
            mac = data[:self.mac_bytes]
            if not nacl.crypto_auth(data[self.mac_bytes:],
                                self.key)[:self.mac_bytes] == mac:
                print "Failed MAC verification"
                return
        if self.nonce_bytes:
            nonce_in = data[self.mac_bytes:self.mac_bytes+self.nonce_bytes]
        else:
            nonce_in = ''
        #if nonce_in == '\0' * self.nonce_bytes:   
            #print("Key re-exchange time! In")
            #self.key_get_exchange(data[self.mac_bytes+self.nonce_bytes:])
            # Disabled because I am incompetent at key re-exchanges
            #return
        nonce = '\x01' + self.nonce_prefix # 1 if client, 0 if server
        nonce += data[self.mac_bytes:self.mac_bytes+self.nonce_bytes]
        in_data = data[self.mac_bytes+self.nonce_bytes:]
        self.recv(nacl.crypto_stream_xor(in_data, nonce, self.key))
    
    def recv(self, data):
        print "Received data from %s: %s" % (self.peer_name, repr(data))

    def send(self, data):
        if self.nonce_bytes:
            self.nonce += 1
            nonce_out = struct.pack("!Q", self.nonce)[-self.nonce_bytes:]
        else:
            nonce_out = ''
        crypted_data = nonce_out + nacl.crypto_stream_xor(data,
                              '\x00' + self.nonce_prefix + nonce_out, self.key)
        mac = nacl.crypto_auth(crypted_data, self.key)[:self.mac_bytes]
        c_sendto(self.sock, mac + crypted_data, self.addr)
        if nonce_out == '\xff' * self.nonce_bytes: # wrap around
            self.nonce = 0 #nonce 0 should only be used for key exchanges
            #print("Key re-exchange time! Out")
            #self.key_exchange()
            # Disabled because I am incompetent at key re-exchanges

    def key_exchange(self):
        self.peer_nonce = 0
        self.kex_init = True
        nonce_out = '\0' * self.nonce_bytes
        dhpk, self.dhsk = nacl.crypto_box_keypair()
        authpkt = nacl.crypto_sign(dhpk, self.secret_key)
        crypted_data = nonce_out + nacl.crypto_stream_xor(authpkt,
                              '\0' + self.nonce_prefix + nonce_out, self.key)
        mac = nacl.crypto_auth(crypted_data, self.key)[:self.mac_bytes]
        c_sendto(self.sock, mac + crypted_data, self.addr)
        
    def key_get_exchange(self, data):
        nonce = '\0' * self.nonce_bytes
        authpkt = nacl.crypto_stream_xor(data,
                                         '\x01' + self.nonce_prefix + nonce,
                                         self.key)
        try:
            peer_dhpk = nacl.crypto_sign_open(authpkt, self.peer_public_key)
        except Exception:
            print("Invalid signature from peer \"%s\" from %s" % \
                                                               (name, addr[0]))
            sys.exit(0)
        if self.kex_init:
            self.key = nacl.crypto_scalarmult(self.dhsk, peer_dhpk)
            print("New key is %s"%repr(self.key))
            self.nonce_prefix = nacl.crypto_auth(config.get("netshrink",
                                                        "nonce_prefix"),
                                                self.key)[:23-self.nonce_bytes]
            self.dhsk = None
            self.kex_init = False
            return
        dhpk, dhsk = nacl.crypto_box_keypair()
        authpkt = nacl.crypto_sign(dhpk, self.secret_key)
        crypted_data = nonce + nacl.crypto_stream_xor(authpkt,
                                '\0' + self.nonce_prefix + nonce, self.key)
        mac = nacl.crypto_auth(crypted_data, self.key)[:self.mac_bytes]
        c_sendto(self.sock, mac + crypted_data, self.addr)
        self.key = nacl.crypto_scalarmult(dhsk, peer_dhpk)
        print("New key is %s"%repr(self.key))

class Connection:
    def __init__(self, sock, addr):
        self.sock = sock
        self.addr = addr
        self.name, self.public_key, self.secret_key = load_identity()
        dhpk, self.dhsk = nacl.crypto_box_keypair()
        self.mac_bytes = config.getint("netshrink","mac_bytes")
        if self.mac_bytes > 32:
            self.mac_bytes = 32
        self.nonce_bytes = config.getint("netshrink","nonce_bytes")
        if self.nonce_bytes > 8:
            self.nonce_bytes = 8
        self.nonce = 0
        self.peer_nonce = 0
        self.kex_init = False
        authpkt = '\0' + self.name + '\0'
        authpkt += nacl.crypto_sign(dhpk, self.secret_key)
        c_sendto(self.sock, authpkt, self.addr)
        while True:
            data, inaddr = c_recvfrom(self.sock, 4096)
            if data[0] != '\0':
                print("Ignoring garbage data from %s" % inaddr[0])
                continue
            name_end = data.find('\0', 1)
            self.peer_name = data[1:name_end]
            kexpkt = data[name_end+1:]
            if not peer_exists(self.name):
                print("Peer \"%s\" is unknown, but you are whitelisted." % \
                                                                self.peer_name)
                print("Please run addpeer/getpeer to authenticate.")
                sys.exit(0)
            self.peer_public_key = get_peer_public_key(self.peer_name)
            try:
                peer_dhpk = nacl.crypto_sign_open(kexpkt, self.peer_public_key)
            except Exception:
                print("Invalid signature from peer \"%s\" from %s" % \
                                                   (self.peer_name, inaddr[0]))
                sys.exit(0)
            break
        print("Accepted connection from peer \"%s\" from %s" % \
                                                     (self.peer_name, addr[0]))
        self.key = nacl.crypto_scalarmult(self.dhsk, peer_dhpk)
        self.dhsk = None
        if self.nonce_bytes:
            self.nonce_prefix = nacl.crypto_auth(config.get("netshrink",
                                                            "nonce_prefix"),
                                             self.key)[:23-self.nonce_bytes]
        else:
            self.nonce_prefix = nacl.crypto_auth(config.get("netshrink",
                                                            "nonce_prefix"),
                                                 self.key)[:23]
        print("len of nonce_prefix is %d"%len(self.nonce_prefix))
        for i in xrange(260):
            self.send("Hello there")

    def raw_recv(self, data):
        if self.mac_bytes > 0:
            mac = data[:self.mac_bytes]
            if not nacl.crypto_auth(data[self.mac_bytes:],
                                self.key)[:self.mac_bytes] == mac:
                print "Failed MAC verification"
                return
        if self.nonce_bytes:
            nonce_in = data[self.mac_bytes:self.mac_bytes+self.nonce_bytes]
        else:
            nonce_in = ''
        if nonce_in == '\0' * self.nonce_bytes:
            #print("Key re-exchange time! In")
            #self.key_get_exchange(data[self.mac_bytes+self.nonce_bytes:])
            # Disabled because I am incompetent at key re-exchanges
            return
        nonce = '\0' + self.nonce_prefix # 1 if client, 0 if server
        nonce += data[self.mac_bytes:self.mac_bytes+self.nonce_bytes]
        in_data = data[self.mac_bytes+self.nonce_bytes:]
        self.recv(nacl.crypto_stream_xor(in_data, nonce, self.key))

    def recv(self, data):
        print "Received data from %s: %s" % (self.peer_name, repr(data))
        
    def send(self, data):
        if self.nonce_bytes:
            self.nonce += 1
            nonce_out = struct.pack("!Q", self.nonce)[-self.nonce_bytes:]
        else:
            nonce_out = ''
        crypted_data = nonce_out + nacl.crypto_stream_xor(data,
                              '\x01' + self.nonce_prefix + nonce_out, self.key)
        mac = nacl.crypto_auth(crypted_data, self.key)[:self.mac_bytes]
        c_sendto(self.sock, mac + crypted_data, self.addr)
        if nonce_out == '\xff' * self.nonce_bytes: # about to wrap around
            self.nonce = 0 #nonce 0 should only be used for key exchanges
            #print("Key re-exchange time! Out")
            #self.key_exchange()
            # Disabled because I am incompetent at key re-exchanges

    def key_exchange(self):
        self.peer_nonce = 0
        self.kex_init = True
        print("asdf")
        nonce_out = '\0' * self.nonce_bytes
        dhpk, self.dhsk = nacl.crypto_box_keypair()
        authpkt = nacl.crypto_sign(dhpk, self.secret_key)
        crypted_data = nonce_out + nacl.crypto_stream_xor(authpkt,
                              '\x01' + self.nonce_prefix + nonce_out, self.key)
        mac = nacl.crypto_auth(crypted_data, self.key)[:self.mac_bytes]
        c_sendto(self.sock, mac + crypted_data, self.addr)

    def key_get_exchange(self):
        nonce = '\0' * self.nonce_bytes
        print("asdf2")
        authpkt = nacl.crypto_stream_xor(data, nonce, self.key)
        try:
            peer_dhpk = nacl.crypto_sign_open(authpkt, self.peer_public_key)
        except Exception:
            print("Invalid signature from peer \"%s\" from %s" % \
                                                               (name, addr[0]))
            sys.exit(0)
        if self.kex_init:
            self.key = nacl.crypto_scalarmult(self.dhsk, peer_dhpk)
            print("New key is %s"%repr(self.key))
            self.nonce_prefix = nacl.crypto_auth(config.get("netshrink",
                                                        "nonce_prefix"),
                                                self.key)[:23-self.nonce_bytes]
            self.dhsk = None
            self.kex_init = False
            return
        dhpk, dhsk = nacl.crypto_box_keypair()
        authpkt = nacl.crypto_sign(dhpk, self.secret_key)
        crypted_data = nonce_out + nacl.crypto_stream_xor(authpkt,
                                '\x01' + self.nonce_prefix + nonce, self.key)
        mac = nacl.crypto_auth(crypted_data, self.key)[:self.mac_bytes]
        c_sendto(self.sock, mac + crypted_data, self.addr)
        self.key = nacl.crypto_scalarmult(dhsk, peer_dhpk)
        print("New key is %s"%repr(self.key))
        

def sigint_cb(watcher, revents):
    global count_bytes_in, count_bytes_out
    print("")
    print("Total bytes in:  %d" % count_bytes_in)
    print("Total bytes out: %d" % count_bytes_out)
    watcher.loop.stop()
    os._exit(0)

def serve_cb(watcher, revents):
    global connection_map, conn_sock
    data, addr = c_recvfrom(conn_sock, 4096)
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
        peer_public_key = get_peer_public_key(name, pfile=WHITELIST_FILE)
        try:
            result = nacl.crypto_sign_open(kexpkt, peer_public_key)
        except Exception:
            print("Invalid signature from peer \"%s\" from %s" % \
                                                               (name, addr[0]))
            return # Ignore this connection
        print("Accepted connection from peer \"%s\" from %s" % (name, addr[0]))
        connection_map[addr] = ServeConnection(conn_sock, addr, name,
                                          peer_public_key, result)
    else:
        print "packet from %s" % addr[0]
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
    io = pyev.Io(sock, pyev.EV_READ, loop, serve_cb)
    io.start()
    sigint = pyev.Signal(2, loop, sigint_cb)
    sigint.start()
    print("Listening for new connections")
    loop.start()

def connect(address, port=24414):
    global config, connection_map
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
    loop = pyev.default_loop()
    connection_map[0] = Connection(sock, (address, port))
    
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

def atexit_cb():
    print("Total bytes in:  %d" % count_bytes_in)
    print("Total bytes out: %d" % count_bytes_out)

if __name__ == '__main__':
    atexit.register(atexit_cb)
    arg = sys.argv[1:]
    if len(arg) == 0:
        help()
    if arg[0].lower() == "serve":
        if len(arg) == 1:
            serve()
        elif len(arg) == 2:
            serve(port=arg[1])
        elif len(arg) == 3:
            serve(address=arg[1], port=int(arg[2]))
        else:
            help()
    elif arg[0].lower() == "connect":
        try:
            if len(arg) == 2:
                connect(address=arg[1])
            elif len(arg) == 3:
                connect(address=arg[1], port=int(arg[2]))
            else:
                help()
        except KeyboardInterrupt:
            print("Total bytes in:  %d" % count_bytes_in)
            print("Total bytes out: %d" % count_bytes_out)
            os._exit(0)
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
            os._exit(0)
    elif arg[0].lower() == "help":
        help()
    else: # Assume we want to connect to a server
        try:
            if len(arg) == 1:
                connect(address=arg[0])
            elif len(arg) == 2:
                connect(address=arg[0], port=int(arg[2]))
            else:
                help()
        except KeyboardInterrupt:
            print("Total bytes in:  %d" % count_bytes_in)
            print("Total bytes out: %d" % count_bytes_out)
            os._exit(0)