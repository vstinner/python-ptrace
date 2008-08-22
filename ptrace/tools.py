from ctypes import sizeof
from ptrace.ctypes_tools import formatUintHex16, formatUintHex32, formatWordHex
from datetime import datetime, timedelta
from os import getenv, access, X_OK
from os.path import join as path_join

def dumpRegs(log, regs):
    width = max( len(name) for name, type in regs._fields_ )
    name_format = "%% %us" % width
    for name, type in regs._fields_:
        value = getattr(regs, name)
        name = name_format % name
        if sizeof(type) == 32:
            value = formatUintHex32(value)
        elif sizeof(type) == 16:
            value = formatUintHex16(value)
        else:
            value = formatWordHex(value)
        log("%s = %s" % (name, value))

def readBits(value, bitmasks):
    text = []
    for mask, item in bitmasks:
        if not value & mask:
            continue
        text.append(item)
        value = value & ~mask
    return text

def formatBits(value, bitmasks, empty_text=None, format_value=str):
    orig_value = value
    text = readBits(value, bitmasks)
    if text:
        text = "%s" % ("|".join(text))
        if value:
            text = "<%s> (%s)" % (text, format_value(orig_value))
        return text
    else:
        if empty_text:
            return empty_text
        else:
            return str(value)

LOCAL_TIMEZONE_OFFSET = datetime.fromtimestamp(0) - datetime.utcfromtimestamp(0)

# Start of UNIX timestamp (Epoch): 1st January 1970 at 00:00
UNIX_TIMESTAMP_T0 = datetime(1970, 1, 1)

def timestampUNIX(value, is_local):
    """
    Convert an UNIX (32-bit) timestamp to datetime object. Timestamp value
    is the number of seconds since the 1st January 1970 at 00:00. Maximum
    value is 2147483647: 19 january 2038 at 03:14:07.

    May raise ValueError for invalid value: value have to be in 0..2147483647.

    >>> timestampUNIX(0, False)
    datetime.datetime(1970, 1, 1, 0, 0)
    >>> timestampUNIX(1154175644.37, False)
    datetime.datetime(2006, 7, 29, 12, 20, 44, 370000)
    """
    timestamp = UNIX_TIMESTAMP_T0 + timedelta(seconds=value)
    if is_local:
        timestamp += LOCAL_TIMEZONE_OFFSET
    return timestamp

def locateProgram(program):
    # FIXME: Fix for Windows
    if program[0] == '/':
        return program
    path = getenv('PATH')
    if not path:
        return program
    for dirname in path.split(":"):
        filename = path_join(dirname, program)
        if access(filename, X_OK):
            return filename
    return program

def minmax(min_value, value, max_value):
    """
    Restrict value to [min_value; max_value]

    >>> minmax(-2, -3, 10)
    -2
    >>> minmax(-2, 27, 10)
    10
    >>> minmax(-2, 0, 10)
    0
    """
    return min(max(min_value, value), max_value)

def inverseDict(data):
    result = {}
    for key, value in data.iteritems():
        result[value] = key
    return result

