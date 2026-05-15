from base import *
import unittest
import random


class TestSamplePlaceholder(CSE123TestBase):
    """Original stub — kept so `test_case` still runs if you want a no-op."""

    def setUp(self):
        self.setUpEnvironment(rtable="rtable", build=True, debug=False, manual_sr=False)

    def tearDown(self):
        self.tearDownEnvironment()

    def test_case(self):
        self.assertTrue(True)


class TestIntermediateManualPings(CSE123TestBase):
    """
    Regression tests mirroring what you run in the Mininet CLI (see PA2a handout).
    Requires: ln -s /project-base/ project_base in this directory (inside the container).
    """

    def setUp(self):
        self.setUpEnvironment(rtable="rtable", build=True, debug=False, manual_sr=False)

    def tearDown(self):
        self.tearDownEnvironment()

    def _assert_ping_ok(self, output, label):
        self.assertIn(
            "1 packets received",
            output,
            msg="ICMP ping failed for %s; output was:\n%s" % (label, output),
        )

    def test_intermediate_ping_router_sw0_eth1(self):
        out = self.client["m"].cmd("ping -c 1 192.168.2.1")
        self._assert_ping_ok(out, "router 192.168.2.1 (sw0-eth1)")

    def test_intermediate_ping_router_sw0_eth2(self):
        out = self.client["m"].cmd("ping -c 1 172.64.3.1")
        self._assert_ping_ok(out, "router 172.64.3.1 (sw0-eth2)")

    def test_intermediate_ping_router_sw0_eth3(self):
        out = self.client["m"].cmd("ping -c 1 10.0.1.1")
        self._assert_ping_ok(out, "router 10.0.1.1 (sw0-eth3)")

    def test_intermediate_ping_server1(self):
        out = self.client["m"].cmd("ping -c 1 %s" % self.server1["ip"])
        self._assert_ping_ok(out, "server1")

    def test_intermediate_ping_server2(self):
        out = self.client["m"].cmd("ping -c 1 %s" % self.server2["ip"])
        self._assert_ping_ok(out, "server2")


class TestAdvancedRouterEcho(CSE123TestBase):
    """
    Scapy-style check: ICMP echo to the router’s own IP should produce an echo reply
    seen back on the client link (same pattern as test_icmp_custom_packet).
    """

    def setUp(self):
        self.setUpEnvironment(rtable="rtable", build=True, debug=False, manual_sr=False)

    def tearDown(self):
        self.tearDownEnvironment()

    def test_advanced_icmp_echo_to_router_eth3(self):
        self.clearPcapBuffers()
        ip_id = random.randint(1, 65535)
        src = self.client
        dst_ip = "10.0.1.1"
        pkt = (
            Ether(src=src["mac"], dst=src["gwmac"])
            / IP(src=src["ip"], dst=dst_ip, id=ip_id, ttl=64)
            / ICMP(type=8, id=0xAB, seq=7)
        )
        self.sendPacket(pkt, node=src["m"].name)
        icmps = self.expectPackets(src["m"].name, type="icmp", timewait_sec=0.25)
        saw_reply = False
        for icmp_tup in icmps:
            icmp_pkt = icmp_tup[0]
            if ICMP not in icmp_pkt:
                continue
            if icmp_pkt[ICMP].type != 0:
                continue
            if IP not in icmp_pkt:
                continue
            if icmp_pkt[IP].id != ip_id:
                continue
            saw_reply = True
            break
        self.assertTrue(
            saw_reply,
            msg="Expected ICMP echo reply (type 0) on client for IP.id=%s to %s"
            % (ip_id, dst_ip),
        )


if __name__ == "__main__":
    unittest.main()
