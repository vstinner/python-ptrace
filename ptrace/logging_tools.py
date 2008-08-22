from ptrace.tools import minmax
from logging import ERROR, WARNING, INFO, DEBUG

def getLogFunc(logger, level):
    if level == ERROR:
        return logger.error
    elif level == WARNING:
        return logger.warning
    elif level == INFO:
        return logger.info
    elif level == DEBUG:
        return logger.debug
    else:
        return logger.error

def changeLogLevel(level, delta):
    return minmax(DEBUG, level + delta*10, ERROR)

