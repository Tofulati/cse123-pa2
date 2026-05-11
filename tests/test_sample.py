from base import *
import unittest
import random

class Test2(CSE123TestBase):
    
    def setUp(self):
        # debug enables captured packet printing
        self.setUpEnvironment()
        # Any other initialization goes here

    def tearDown(self):
        self.tearDownEnvironment()
        # Any other cleanup goes here

    def test_case(self):
        self.assertTrue(True)

if __name__ == "__main__":
    unittest.main()
