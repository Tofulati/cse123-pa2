from base import *
import unittest
import random

class TestICMP(CSE123TestBase):

    def setUp(self):
        # debug enables captured packet printing
        self.setUpEnvironment(rtable='rtable', build=True, debug=False, manual_sr=False)
        # Any other initialization goes here

    def tearDown(self):
        self.tearDownEnvironment()
        # Any other cleanup goes here

    def test_icmp_cmd(self):
        output = self.client["m"].cmd(f"ping -c 1 {self.server1['ip']}")
        self.assertTrue("1 packets received" in output, msg="ICMP request failed between client and server1")
        output = self.client["m"].cmd(f"ping -c 1 {self.server2['ip']}")
        self.assertTrue("1 packets received" in output, msg="ICMP request failed between client and server2")

    def test_icmp_custom_packet(self):
        # Test ICMP server 1
        self.clearPcapBuffers()
        id = random.randint(1, 65535)
        src = self.client
        dst = self.server1
        pkt = Ether(src=src["mac"], dst=src["gwmac"])/IP(src=src["ip"], dst=dst["ip"], id=id)/ICMP(type=8, id=0x10)   # Echo request
        sent = self.sendPacket(pkt, node=src["m"].name)
        # print(f"Sent: {sent[0]}")

        icmps = self.expectPackets(dst["m"].name, type='icmp', timewait_sec=0.1)
        routed = False
        for icmp in icmps:
            if icmp[0][IP].id == pkt[IP].id:
                routed = True
        self.assertTrue(routed, msg="ICMP packet was not routed between {} and {}.".format(src["m"].name, dst["m"].name))

        # Test ICMP server 2
        self.clearPcapBuffers()
        id = random.randint(1, 65535)
        dst = self.server2
        pkt = Ether(src=src["mac"], dst=src["gwmac"])/IP(src=src["ip"], dst=dst["ip"], id=id)/ICMP(type=8, id=0x10)   # Echo request
        sent = self.sendPacket(pkt, node=src["m"].name)
        # print(f"Sent: {sent[0]}")

        icmps = self.expectPackets(dst["m"].name, type='icmp', timewait_sec=0.1)
        routed = False
        for icmp in icmps:
            if icmp[0][IP].id == pkt[IP].id:
                routed = True
        self.assertTrue(routed, msg="ICMP packet was not routed between {} and {}.".format(src["m"].name, dst["m"].name))

if __name__ == "__main__":
    unittest.main()
