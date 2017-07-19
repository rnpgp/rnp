#!/usr/bin/python

import sys
import distutils.spawn
import tempfile
from os import path
import os
import shutil
import subprocess

def setup():
    return

def run_rnp_tests():
    
    return

def run_rnpkeys_tests():
    return

def run_tests():
    if not len(sys.argv) == 2:
        print "Wrong usage. Run cli_tests [rnp | rnpkeys]"
        sys.exit(1)

    if sys.argv[1] == 'rnp':
        run_rnp_tests()
    elif sys.argv[1] == 'rnpkeys':
        run_rnpkeys_tests()
    else:
        print "Wrong parameter {}".format(sys.argv[1])
        sys.exit(1)

    return

def cleanup():
    return

if __name__ == '__main__':
    setup()
    run_tests()
    cleanup()