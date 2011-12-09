#!/usr/bin/env python2.7 

import os
import sys
import socket
from base64 import b64encode, b64decode
from binascii import hexlify
import ConfigParser as configparser
from hashlib import sha256

import nacl

DEF_PORT=24414
IDENTITY_FILE = ".identity"
PEER_FILE = ".peers"

def identity_exists():
    return 

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
    
def peer_exists(peer_name):
    peers = configparser.RawConfigParser()
    if peers.read(PEER_FILE) == []:
        return False
    return peers.has_section(peer_name)

def save_peer(peer_name, peer_public_key):
    peers = configparser.RawConfigParser()
    peers.read(PEER_FILE)
    try:
        peers.add_section(peer_name)
    except configparser.DuplicateSectionError:
        pass
    peers.set(peer_name,"public_key",b64encode(peer_public_key))
    peers.set(peer_name,"fingerprint",get_fingerprint(peer_public_key))
    peers.write(open(PEER_FILE,"w"))

# COMMANDS
    
def serve():
    print("will implement later.")
    sys.exit(1)

def connect():
    print("will implement later.")
    sys.exit(1)

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
    sock.sendto(data, (address, port))
    print("Sent packet, waiting for response...")
    while True:
        data, addr = sock.recvfrom(4096)
        if data[0] != '\x02': # getpeer packet
            print("Garbage packet ignored from %s" % addr[0])
            continue
        if addr != (address, port):
            print("Ignoring packet from %s" % addr[0])
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
        data, addr = sock.recvfrom(4096)
        if data[0] != '\x01': # addpeer packet
            print "Garbage packet ignored from %s" % addr[0]
            continue
        print("Got identity from %s" % addr[0])
        outdata = "\x02" + public_key + name
        sock.sendto(outdata, addr)
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
        print("Listening for peers on %s:%d..." % (address, port))
    sys.exit(1)

def help():
    print("%s help\nTo be created" % sys.argv[0])
    sys.exit(0)

if __name__ == '__main__':
    arg = sys.argv[1:]
    if len(arg) == 0:
        help()
    if arg[0].lower() == "serve":
        serve()
    elif arg[0].lower() == "connect":
        connect()
    elif arg[0].lower() == "addpeer":
        if len(arg) == 2:
            addpeer(arg[1])
        elif len(arg) == 3:
            addpeer(arg[1], arg[2])
        else:
            help()
    elif arg[0].lower() == "getpeer":
        if len(arg) == 1:
            getpeer()
        elif len(arg) == 2:
            getpeer(port=int(arg[1]))
        elif len(arg) == 3:
            getpeer(address=arg[1], port=int(arg[2]))
        else:
            help()
    elif arg[0].lower() == "help":
        help()
    else: #
        if peer_exists(arg[0].lower()):
            connect()
        else:
            help()