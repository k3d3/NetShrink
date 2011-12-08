def dump(n):
  s = '%x' % n
  if len(s) & 1:
    s = '0' + s
  return s.decode('hex')

def encode(value, chars):
    """
    encode string 'value' as a base58 string; returns string
    """

    encoded = ''
    value = int(value.encode('hex'), 16)
    while value >= len(chars):
        div, mod = divmod(value, len(chars))
        encoded = chars[mod] + encoded # add to left
        value = div
    encoded = chars[value] + encoded # most significant remainder
    return encoded

def decode(encoded, chars):
    """
    decodes base58 string 'encoded' to return integer
    """

    value = 0
    
    column_multiplier = 1;
    for c in encoded[::-1]:
        column = chars.index(c)
        value += column * column_multiplier
        column_multiplier *= len(chars)
    return dump(value)