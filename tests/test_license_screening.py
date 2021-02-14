# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring,unused-import,reimported
import pytest  # type: ignore

import tests.context as ctx

import license_screening.license_screening as lis


def test_parse_ok_empty_string():
    assert lis.parse('') is NotImplemented


def test_parse_ok_known_tree():
    assert lis.main(["tests/data"]) == 0
