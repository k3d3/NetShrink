import struct

import bases

sample = \
'''GET / HTTP/1.1
User-Agent: Python/bananas
Content-Type: Postdata, bitches (9876)

this is a huge amount of data'''

chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890/$?&=-_.+!*\'(),%'

HTTP_TYPES = [
              'GET',
              'HEAD',
              'POST',
              'PUT',
              'DELETE',
              'CONNECT'
             ]

HTTP_VERSIONS = [
                 'HTTP/1.0',
                 'HTTP/1.1'
                ]

def shrink_reqline(line):
    global HTTP_TYPES, HTTP_VERSIONS
    reqtype, location, http = line.split()
    output = ''
    if reqtype.upper() in HTTP_TYPES:
        output += chr(HTTP_TYPES.index(reqtype.upper()))
    else:
        output += '\xff' + reqtype + '\x00'
    shorturl = bases.decode(location, chars)
    output += struct.pack("!H", len(shorturl)) + shorturl
    if http.upper() in HTTP_VERSIONS:
        output += chr(HTTP_VERSIONS.index(http.upper()))
    else:
        output += '\xff' + http + '\x00'
    return output

def expand_reqline(line):
    global HTTP_TYPES, HTTP_VERSIONS
    output = ''
    reqtype = line[0]
    if reqtype == '\xff':
        reqtype = line[1:line.find('\x00')]
        position = line.find('\x00')+1
    else:
        reqtype = HTTP_TYPES[ord(reqtype)]
        position = 1
    loclen = struct.unpack("!H", line[position:position + 2])[0]
    position = position + 2
    location = bases.encode(line[position:position + loclen], chars)
    http = line[position + loclen]
    if http == '\xff':
        position = position+loclen
        http = line[position+1:line.find('\x00',position)]
    else:
        http = HTTP_VERSIONS[ord(http)]
    return " ".join([reqtype, location, http])