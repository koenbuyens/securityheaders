#!/usr/bin/env python
# PYTHON_ARGCOMPLETE_OK
import sys

from multiprocessing import freeze_support
import securityheaders.command_line

if __name__== "__main__":
    freeze_support()
    securityheaders.command_line.main(sys.argv[1:])
