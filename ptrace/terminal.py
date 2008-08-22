from termios import tcgetattr, tcsetattr, ECHO, TCSADRAIN, TIOCGWINSZ
from sys import stdin, stdout
from fcntl import ioctl
from struct import unpack

TERMIO_LFLAGS = 3

def _terminalSize():
    fd = stdout.fileno()
    size = ioctl(fd, TIOCGWINSZ, '1234')
    height, width = unpack('hh', size)
    return (width, height)

def terminalWidth():
    return _terminalSize()[0]

def enableEchoMode():
    fd = stdin.fileno()
    state = tcgetattr(fd)
    if state[TERMIO_LFLAGS] & ECHO:
        return False
    state[TERMIO_LFLAGS] = state[TERMIO_LFLAGS] | ECHO
    tcsetattr(fd, TCSADRAIN, state)
    return True


