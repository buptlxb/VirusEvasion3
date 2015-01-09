# -*- coding: utf-8 -*-


class PEException(Exception):
    """Base exception class."""
    pass


class PEFormatError(PEException):
    """Raised when an invalid field on the PE instance was found."""
    pass
