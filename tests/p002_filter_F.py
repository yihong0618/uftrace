#!/usr/bin/env python

import os

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
# DURATION     TID     FUNCTION
            [ 28142] | a() {
            [ 28142] |   b() {
            [ 28142] |     c() {
   0.753 us [ 28142] |       posix.getpid();
   1.430 us [ 28142] |     } /* c */
   1.915 us [ 28142] |   } /* b */
   2.405 us [ 28142] | } /* a */
""", lang='Python', sort='simple')

    def setup(self):
        self.option = '-F a'
