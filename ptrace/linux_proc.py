from os import readlink, listdir
from os.path import join as path_join
from resource import getpagesize
from ptrace.tools import timestampUNIX
from datetime import timedelta

class ProcError(Exception):
    pass

PROC_DIRNAME = '/proc'
PAGE_SIZE = getpagesize()

def procFilename(*args):
    return path_join(PROC_DIRNAME, *args)

def openProc(path):
    try:
        filename = procFilename(path)
        return open(filename)
    except IOError, err:
        raise ProcError("Unable to open %r: %s" % (filename, err))

def readProc(path):
    procfile = openProc(path)
    content = procfile.read()
    procfile.close()
    return content

def readProcessProc(pid, key):
    try:
        return readProc(path_join(str(pid), str(key)))
    except ProcError, error:
        raise ProcError("Process %s doesn't exist: %s" % (
            pid, error))

class ProcessState:
    """
    Attributes:
    - pid, ppid, pgrp (int)
    - program (str)
    - state (str)
    - queue (list of int)
    """
    STATE_NAMES = {
        "R": "running",
        "S": "sleeping",
        "D": "disk",
        "Z": "zombie",
        "T": "traced",
        "W": "pagging",
    }
    def __init__(self, stat):
        # pid (program) ... => "pid (program", "..."
        part, stat = stat.rsplit(')', 1)
        self.pid, self.program = part.split('(', 1)
        self.pid = int(self.pid)

        # "state ..." => state, "..."
        stat = stat.split()
        self.state = stat[0]
        stat = [ int(item) for item in stat[1:] ]

        # Read next numbers
        self.ppid = stat[0]
        self.pgrp = stat[1]
        self.session = stat[2]
        self.tty_nr = stat[3]
        self.tpgid = stat[4]
        self.utime = stat[10]
        self.stime = stat[11]
        self.starttime = stat[18]

def readProcessStat(pid):
    stat = readProcessProc(pid, 'stat')
    return ProcessState(stat)

def readProcessStatm(pid):
    statm = readProcessProc(pid, 'statm')
    statm = [ int(item)*PAGE_SIZE for item in statm.split() ]
    return statm

def readProcessProcList(pid, key):
    data = readProcessProc(pid, key)
    if not data:
        # Empty file: empty list
        return []
    data = data.split("\0")
    if not data[-1]:
        del data[-1]
    return data

def readProcessLink(pid, key):
    try:
        filename = procFilename(str(pid), str(key))
        return readlink(filename)
    except OSError, err:
        raise ProcError("Unable to read proc link %r: %s" % (filename, err))

def readProcesses():
    """
    Iterate on process directories from /proc
    """
    for filename in listdir(PROC_DIRNAME):
        try:
            yield int(filename)
        except ValueError:
            # Filename is not an integer (eg. "stat" from /proc/stat)
            continue

def readProcessCmdline(pid, escape_stat=True):
    # Try /proc/42/cmdline
    try:
        cmdline = readProcessProcList(pid, 'cmdline')
        if cmdline:
            return cmdline
    except ProcError:
        pass

    # Try /proc/42/stat
    try:
        stat = readProcessStat(pid)
        program = stat.program
        if escape_stat:
            program = "[%s]" % program
        return [program]
    except ProcError:
        return None

def searchProcessesByName(process_name):
    """
    Find all processes have the specified name
    (eg. "ssh" to find "/usr/bin/ssh").
    This function is a generating yielding the process identifier.
    """
    suffix = '/'+process_name
    for pid in readProcesses():
        cmdline = readProcessCmdline(pid)
        if not cmdline:
            continue
        program = cmdline[0]
        if program == process_name or program.endswith(suffix):
            yield pid

def searchProcessByName(process_name):
    """
    Find process identifier (PID) using its name
    (eg. "ssh" to find "/usr/bin/ssh").
    """
    for pid in searchProcessesByName(process_name):
        return pid
    raise ProcError("Unable to find process: %r" % process_name)

def getUptime():
    """
    Get system uptime: return datetime.timedelta object.
    """
    uptime = readProc('uptime')
    uptime = uptime.strip().split()
    uptime = float(uptime[0])
    return timedelta(seconds=uptime)

def getSystemBoot():
    """
    Get system boot date, return datetime.datetime object.
    """
    if getSystemBoot.value is None:
        stat_file = openProc('stat')
        for line in stat_file:
            if not line.startswith("btime "):
                continue
            seconds = int(line[6:])
            btime = timestampUNIX(seconds, True)
            getSystemBoot.value = btime
            break
        stat_file.close()
        if getSystemBoot.value is None:
            raise ProcError("Unable to read system boot time!")
    return getSystemBoot.value
getSystemBoot.value = None

