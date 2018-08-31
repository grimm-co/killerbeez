class Error(Exception):
    """Base class for all Killerbeez exceptions"""

class InternalError(Error):
    """Internal code used incorrectly"""

class BoincError(Error):
    """Error interacting with BOINC"""
