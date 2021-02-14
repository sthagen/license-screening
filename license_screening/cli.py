#! /usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Add logical documentation here later TODO."""
import os
import sys

from license_screening.license_screening import main as process_trees

DEBUG = os.getenv("LICENSE_SCREENING_DEBUG")


# pylint: disable=expression-not-assigned
def main(argv=None):
    """Process ... TODO."""
    argv = sys.argv[1:] if argv is None else argv
    verbose = True if "-v" in argv or "--verbose" in argv else False
    DEBUG and print(f"Not yet implemented")
    process_trees(argv)
