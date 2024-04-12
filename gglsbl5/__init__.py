#!/usr/bin/env python

__all__ = [
    'SafeBrowsingList'
]

from gglsbl5.client import SafeBrowsingList

from gglsbl5._version import get_versions
__version__ = get_versions()['version']
del get_versions
