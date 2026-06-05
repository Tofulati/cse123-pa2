from base import *
from scapy.all import Raw
import unittest
import random

# ============================================================
# Topology reference (from router startup output):
#
#   client   : 10.0.1.100   -- router eth3 : 10.0.1.1
#   server1  : 192.168.2.2  -- router eth1 : 192.168.2.1
#   server2  : 172.64.3.10  -- router eth2 : 172.64.3.1
#
# Routing table loaded by the router (exact-host /32 entries):
#   192.168.2.2  via 192.168.2.2  255.255.255.255  eth1
#   172.64.3.10  via 172.64.3.10  255.255.255.255  eth2
#   10.0.1.100   via 10.0.1.100   255.255.255.255  eth3
# ============================================================


# ------------------------------------------------------------------
# Shared setUp / tearDown mixin so every class is one-liner clean.
# ------------------------------------------------------------------
class _RouterTestMixin:
    """Provides standard setUp/tearDown for all router test classes."""

    def setUp(self):
        self.setUpEnvironment(rtable="rtable", build=True, debug=False, manual_sr=False)

    def tearDown(self):
        self.tearDownEnvironment()


# ==================================================================
# TestARP
# ==================================================================
class TestARP(_RouterTestMixin, CSE123TestBase):
    """
    Pure ARP tests: verify the router replies to ARP requests on each
    of its directly-connected interfaces, and that it correctly ignores
    ARP requests destined for a *different* interface gateway as well as
    unsolicited (gratuitous-style) ARP replies it never asked for.
    """

    def _send_arp_request_and_expect_reply(self, src_node, target_ip):
        """
        Helper: broadcast an ARP request from `src_node` asking who-has
        `target_ip`, then assert we receive an ARP reply whose sender
        hardware address is the router MAC for that interface.

        ARP packet structure recap:
          - Ether: src=our MAC, dst=ff:ff:ff:ff:ff:ff (broadcast)
          - ARP:   op=1 (who-has), pdst=target_ip, psrc=our IP
        """
        self.clearPcapBuffers()
        pkt = (
            Ether(src=src_node["mac"], dst="ff:ff:ff:ff:ff:ff")
            / ARP(op=1,                        # 1 = ARP request
                  hwsrc=src_node["mac"],
                  psrc=src_node["ip"],
                  hwdst="00:00:00:00:00:00",   # unknown at request time
                  pdst=target_ip)
        )
        self.sendPacket(pkt, node=src_node["m"].name)
        replies = self.expectPackets(src_node["m"].name, type="arp", timewait_sec=1.0)

        saw_reply = False
        for tup in replies:
            arp_pkt = tup[0]
            if ARP not in arp_pkt:
                continue
            if arp_pkt[ARP].op != 2:           # 2 = ARP reply (is-at)
                continue
            if arp_pkt[ARP].psrc != target_ip:
                continue
            saw_reply = True
            break

        self.assertTrue(
            saw_reply,
            msg="Expected ARP reply for %s from node %s but got none.\nPackets: %s"
                % (target_ip, src_node["m"].name, replies),
        )

    # ------------------------------------------------------------------
    # test_arp_client
    # ARP from client → ask for router's eth3 gateway (10.0.1.1)
    # ------------------------------------------------------------------
    def test_arp_client(self):
        """Client broadcasts ARP for its gateway (10.0.1.1); router must reply."""
        self._send_arp_request_and_expect_reply(self.client, self.client["gw"])

    # ------------------------------------------------------------------
    # test_arp_server1
    # ARP from server1 → ask for router's eth1 gateway (192.168.2.1)
    # ------------------------------------------------------------------
    def test_arp_server1(self):
        """Server1 broadcasts ARP for its gateway (192.168.2.1); router must reply."""
        self._send_arp_request_and_expect_reply(self.server1, self.server1["gw"])

    # ------------------------------------------------------------------
    # test_arp_server2
    # ARP from server2 → ask for router's eth2 gateway (172.64.3.1)
    # ------------------------------------------------------------------
    def test_arp_server2(self):
        """Server2 broadcasts ARP for its gateway (172.64.3.1); router must reply."""
        self._send_arp_request_and_expect_reply(self.server2, self.server2["gw"])

    # ------------------------------------------------------------------
    # test_negative_arp
    # Send ARP requests for a *different* subnet's gateway from each node.
    # Example: client asks "who has 192.168.2.1?" — that is server1's
    # gateway, not client's. The router should NOT forward or reply to
    # such cross-subnet ARP requests.
    # ------------------------------------------------------------------
    def test_negative_arp(self):
        """
        ARP requests for gateways on other subnets must not be answered
        or forwarded by the router.
        """
        # client asks for server1's gateway IP — should be silently dropped
        self.clearPcapBuffers()
        pkt = (
            Ether(src=self.client["mac"], dst="ff:ff:ff:ff:ff:ff")
            / ARP(op=1,
                  hwsrc=self.client["mac"],
                  psrc=self.client["ip"],
                  hwdst="00:00:00:00:00:00",
                  pdst=self.server1["gw"])   # 192.168.2.1 — wrong subnet
        )
        self.sendPacket(pkt, node=self.client["m"].name)
        replies = self.expectPackets(self.client["m"].name, type="arp", timewait_sec=1.0)

        # Filter to only ARP replies (op==2) that claim to be from 192.168.2.1
        bad_replies = [
            tup for tup in replies
            if ARP in tup[0]
            and tup[0][ARP].op == 2
            and tup[0][ARP].psrc == self.server1["gw"]
        ]
        self.assertEqual(
            len(bad_replies), 0,
            msg="Router must NOT reply to ARP for %s received on client's link.\nGot: %s"
                % (self.server1["gw"], bad_replies),
        )

        # server1 asks for server2's gateway — should also be dropped
        self.clearPcapBuffers()
        pkt2 = (
            Ether(src=self.server1["mac"], dst="ff:ff:ff:ff:ff:ff")
            / ARP(op=1,
                  hwsrc=self.server1["mac"],
                  psrc=self.server1["ip"],
                  hwdst="00:00:00:00:00:00",
                  pdst=self.server2["gw"])   # 172.64.3.1 — wrong subnet
        )
        self.sendPacket(pkt2, node=self.server1["m"].name)
        replies2 = self.expectPackets(self.server1["m"].name, type="arp", timewait_sec=1.0)

        bad_replies2 = [
            tup for tup in replies2
            if ARP in tup[0]
            and tup[0][ARP].op == 2
            and tup[0][ARP].psrc == self.server2["gw"]
        ]
        self.assertEqual(
            len(bad_replies2), 0,
            msg="Router must NOT reply to ARP for %s received on server1's link.\nGot: %s"
                % (self.server2["gw"], bad_replies2),
        )

    # ------------------------------------------------------------------
    # test_unsolicited_response
    # Send an ARP *reply* (op=2) that the router never asked for.
    # The router must ignore it — nothing should be forwarded/replied to.
    # ------------------------------------------------------------------
    def test_unsolicited_response(self):
        """
        An unsolicited ARP reply (gratuitous-style) sent to the router
        must be silently dropped; no packets should be emitted by the router.
        """
        self.clearPcapBuffers()
        fake_mac = "de:ad:be:ef:00:01"
        # We claim server1 is now at a bogus MAC — the router did not ask
        pkt = (
            Ether(src=self.client["mac"], dst=self.client["gwmac"])
            / ARP(op=2,                          # 2 = ARP reply
                  hwsrc=fake_mac,
                  psrc=self.server1["ip"],        # lying about server1's MAC
                  hwdst=self.client["gwmac"],
                  pdst=self.client["gw"])
        )
        self.sendPacket(pkt, node=self.client["m"].name)

        # Wait a moment and make sure the router emits nothing in response
        pkts = self.expectPackets(self.client["m"].name, type="arp", timewait_sec=1.0)
        unexpected = [
            tup for tup in pkts
            if ARP in tup[0] and tup[0][ARP].op == 2
        ]
        self.assertEqual(
            len(unexpected), 0,
            msg="Router must silently drop unsolicited ARP replies.\nGot: %s"
                % unexpected,
        )


# ==================================================================
# TestARPBeforeIP
# ==================================================================
class TestARPBeforeIP(_RouterTestMixin, CSE123TestBase):
    """
    Verify that when the router needs to forward a UDP packet, it first
    issues an ARP request for the next-hop MAC before transmitting.
    These tests inject a UDP packet from client and observe: (1) that
    the router emits an ARP request, and optionally (2) that the
    forwarded UDP payload is intact.
    """

    def _build_udp_pkt(self, src_node, dst_ip, payload=b"hello"):
        """Convenience: Ethernet/IP/UDP packet from src_node to dst_ip."""
        return (
            Ether(src=src_node["mac"], dst=src_node["gwmac"])
            / IP(src=src_node["ip"], dst=dst_ip, ttl=64)
            / UDP(sport=5000, dport=5001)
            / Raw(load=payload)
        )

    def _expect_arp_request_for(self, node_name, target_ip, timewait=2.0):
        """
        Wait for an ARP request (op=1) asking who-has `target_ip`
        on the link visible from `node_name`.  Returns True if found.
        """
        pkts = self.expectPackets(node_name, type="arp", timewait_sec=timewait)
        for tup in pkts:
            p = tup[0]
            if ARP in p and p[ARP].op == 1 and p[ARP].pdst == target_ip:
                return True
        return False

    # ------------------------------------------------------------------
    # test_client_server1_no_payload_check
    # Send UDP from client→server1; confirm router ARPs for server1 first.
    # ------------------------------------------------------------------
    def test_client_server1_no_payload_check(self):
        """Router must ARP for server1 (192.168.2.2) before forwarding UDP."""
        self.clearPcapBuffers()
        pkt = self._build_udp_pkt(self.client, self.server1["ip"])
        self.sendPacket(pkt, node=self.client["m"].name)

        found = self._expect_arp_request_for(self.server1["m"].name, self.server1["ip"])
        self.assertTrue(
            found,
            msg="Router did not emit ARP request for server1 (%s) on eth1 link."
                % self.server1["ip"],
        )

    # ------------------------------------------------------------------
    # test_client_server2_no_payload_check
    # ------------------------------------------------------------------
    def test_client_server2_no_payload_check(self):
        """Router must ARP for server2 (172.64.3.10) before forwarding UDP."""
        self.clearPcapBuffers()
        pkt = self._build_udp_pkt(self.client, self.server2["ip"])
        self.sendPacket(pkt, node=self.client["m"].name)

        found = self._expect_arp_request_for(self.server2["m"].name, self.server2["ip"])
        self.assertTrue(
            found,
            msg="Router did not emit ARP request for server2 (%s) on eth2 link."
                % self.server2["ip"],
        )

    # ------------------------------------------------------------------
    # test_send_arp_and_udp_check_arp
    # Send a UDP packet that the server will never reply to.
    # Confirm router issues an ARP request (the key observable behavior).
    # ------------------------------------------------------------------
    def test_send_arp_and_udp_check_arp(self):
        """
        UDP to server1 on a port server1 won't respond to; router must
        still emit an ARP request — this proves the router tried to forward.
        """
        self.clearPcapBuffers()
        pkt = self._build_udp_pkt(self.client, self.server1["ip"], payload=b"no-reply")
        self.sendPacket(pkt, node=self.client["m"].name)

        found = self._expect_arp_request_for(self.server1["m"].name, self.server1["ip"])
        self.assertTrue(
            found,
            msg="Router must ARP for server1 even when no application-layer reply expected.",
        )

    # ------------------------------------------------------------------
    # test_send_arp_and_udp_check_arp_twice
    # Same scenario, repeated twice in a single test run.
    # Confirms the router ARP path works consistently across calls.
    # ------------------------------------------------------------------
    def test_send_arp_and_udp_check_arp_twice(self):
        """ARP-before-forward behavior holds on a second back-to-back send."""
        for i in range(2):
            self.clearPcapBuffers()
            pkt = self._build_udp_pkt(self.client, self.server1["ip"],
                                       payload=("round-%d" % i).encode())
            self.sendPacket(pkt, node=self.client["m"].name)

            found = self._expect_arp_request_for(self.server1["m"].name,
                                                  self.server1["ip"])
            self.assertTrue(
                found,
                msg="Round %d: Router did not ARP for server1 before forwarding." % i,
            )

    # ------------------------------------------------------------------
    # test_send_arp_and_udp_check_both
    # Checks ARP *and* UDP payload integrity on a forwarded packet.
    # Uses IP options (type-of-service byte) to mark the packet so we can
    # identify it among all forwarded traffic.
    # ------------------------------------------------------------------
    def test_send_arp_and_udp_check_both(self):
        """
        Send UDP to server1 with a recognisable payload and a non-default
        IP TOS field (acting as an 'IP option' marker for identification).
        Assert: (1) router ARPs for server1, (2) server1 receives the UDP
        with the original payload intact.
        """
        self.clearPcapBuffers()
        marker_payload = b"integrity-check-" + str(random.randint(0, 9999)).encode()
        pkt = (
            Ether(src=self.client["mac"], dst=self.client["gwmac"])
            / IP(src=self.client["ip"], dst=self.server1["ip"],
                 ttl=64, tos=0x10)           # tos=0x10 as our IP-option marker
            / UDP(sport=5000, dport=5001)
            / Raw(load=marker_payload)
        )
        self.sendPacket(pkt, node=self.client["m"].name)

        # 1. Router must ARP for server1
        arp_found = self._expect_arp_request_for(self.server1["m"].name,
                                                  self.server1["ip"])
        self.assertTrue(arp_found, msg="Router did not ARP for server1 before forwarding.")

        # 2. Server1 must receive the UDP with the same payload
        fwd_pkts = self.expectPackets(self.server1["m"].name, type="udp",
                                      timewait_sec=2.0)
        payload_found = any(
            Raw in tup[0] and tup[0][Raw].load == marker_payload
            for tup in fwd_pkts
        )
        self.assertTrue(
            payload_found,
            msg="Forwarded UDP did not arrive at server1 with intact payload '%s'."
                % marker_payload,
        )

    # ------------------------------------------------------------------
    # test_twice_client_server1_no_payload_check  (redundant / regression)
    # ------------------------------------------------------------------
    def test_twice_client_server1_no_payload_check(self):
        """Redundant regression: ARP-before-forward for server1, twice."""
        for _ in range(2):
            self.clearPcapBuffers()
            pkt = self._build_udp_pkt(self.client, self.server1["ip"])
            self.sendPacket(pkt, node=self.client["m"].name)

            found = self._expect_arp_request_for(self.server1["m"].name,
                                                  self.server1["ip"])
            self.assertTrue(found,
                            msg="Router did not ARP for server1 on repeated send.")

    # ------------------------------------------------------------------
    # test_twice_client_server2_no_payload_check  (redundant / regression)
    # ------------------------------------------------------------------
    def test_twice_client_server2_no_payload_check(self):
        """Redundant regression: ARP-before-forward for server2, twice."""
        for _ in range(2):
            self.clearPcapBuffers()
            pkt = self._build_udp_pkt(self.client, self.server2["ip"])
            self.sendPacket(pkt, node=self.client["m"].name)

            found = self._expect_arp_request_for(self.server2["m"].name,
                                                  self.server2["ip"])
            self.assertTrue(found,
                            msg="Router did not ARP for server2 on repeated send.")


# ==================================================================
# TestBadICMP
# ==================================================================
class TestBadICMP(_RouterTestMixin, CSE123TestBase):
    """
    Malformed-packet rejection tests.  The router must silently drop
    packets with bad checksums and generate the correct ICMP error
    messages for unknown destinations.
    """

    # ------------------------------------------------------------------
    # test_bad_icmp_checksum
    # Router should drop an ICMP echo with a deliberately wrong checksum.
    # ------------------------------------------------------------------
    def test_bad_icmp_checksum(self):
        """
        ICMP echo to router's far-end interface (eth1, 192.168.2.1) with
        a bad ICMP checksum must be silently dropped — no reply.
        """
        self.clearPcapBuffers()
        pkt = (
            Ether(src=self.client["mac"], dst=self.client["gwmac"])
            / IP(src=self.client["ip"], dst=self.server1["gw"], ttl=64)
            / ICMP(type=8, chksum=0xDEAD)     # deliberately wrong checksum
        )
        self.sendPacket(pkt, node=self.client["m"].name)
        replies = self.expectPackets(self.client["m"].name, type="icmp",
                                     timewait_sec=1.0)
        # No ICMP reply of any kind should come back
        icmp_replies = [
            tup for tup in replies
            if ICMP in tup[0] and tup[0][ICMP].type in (0, 3, 11)
        ]
        self.assertEqual(
            len(icmp_replies), 0,
            msg="Router must drop ICMP with bad checksum; got reply(s): %s"
                % icmp_replies,
        )

    # ------------------------------------------------------------------
    # test_bad_ip_checksum
    # Bad IP-header checksum → router drops immediately before L4.
    # ------------------------------------------------------------------
    def test_bad_ip_checksum(self):
        """
        IP packet to router eth1 (192.168.2.1) with a bad IP header
        checksum must be dropped — no forwarding, no ICMP error.
        """
        self.clearPcapBuffers()
        pkt = (
            Ether(src=self.client["mac"], dst=self.client["gwmac"])
            / IP(src=self.client["ip"], dst=self.server1["gw"],
                 ttl=64, chksum=0xBAD0)        # force bad IP checksum
            / ICMP(type=8)
        )
        self.sendPacket(pkt, node=self.client["m"].name)
        pkts = self.expectPackets(self.client["m"].name, type="icmp",
                                  timewait_sec=1.0)
        unexpected = [tup for tup in pkts if ICMP in tup[0]]
        self.assertEqual(
            len(unexpected), 0,
            msg="Router must drop IP packets with bad IP checksum; got: %s"
                % unexpected,
        )

    # ------------------------------------------------------------------
    # test_ping_unknown_host
    # Destination IP not in routing table → ICMP Destination Net Unreachable
    # (type=3, code=0).  Source IP of the ICMP must be the router's *ingress*
    # interface IP (the one facing the sender), NOT a far-end interface.
    # ------------------------------------------------------------------
    def test_ping_unknown_host(self):
        """
        Ping to an IP not in the routing table (e.g. 1.2.3.4).
        Router must reply with ICMP type 3 code 0 (Destination Net Unreachable)
        sourced from the router's eth3 interface (10.0.1.1).
        """
        self.clearPcapBuffers()
        unknown_ip = "1.2.3.4"
        pkt = (
            Ether(src=self.client["mac"], dst=self.client["gwmac"])
            / IP(src=self.client["ip"], dst=unknown_ip, ttl=64)
            / ICMP(type=8)
        )
        self.sendPacket(pkt, node=self.client["m"].name)
        replies = self.expectPackets(self.client["m"].name, type="icmp",
                                     timewait_sec=2.0)

        found = False
        for tup in replies:
            p = tup[0]
            if ICMP not in p or IP not in p:
                continue
            if p[ICMP].type == 3 and p[ICMP].code == 0:   # Net Unreachable
                # Source must be the ingress interface (eth3)
                self.assertEqual(
                    p[IP].src, self.client["gw"],
                    msg="ICMP Unreachable source must be router eth3 (%s), got %s"
                        % (self.client["gw"], p[IP].src),
                )
                found = True
                break

        self.assertTrue(
            found,
            msg="Expected ICMP type 3 code 0 for unknown dst %s, got: %s"
                % (unknown_ip, replies),
        )

    # ------------------------------------------------------------------
    # test_ping_unknown_ip  (different unknown address, same logic)
    # ------------------------------------------------------------------
    def test_ping_unknown_ip(self):
        """Same as test_ping_unknown_host but with a different unknown IP."""
        self.clearPcapBuffers()
        unknown_ip = "9.8.7.6"
        pkt = (
            Ether(src=self.client["mac"], dst=self.client["gwmac"])
            / IP(src=self.client["ip"], dst=unknown_ip, ttl=64)
            / ICMP(type=8)
        )
        self.sendPacket(pkt, node=self.client["m"].name)
        replies = self.expectPackets(self.client["m"].name, type="icmp",
                                     timewait_sec=2.0)

        found = False
        for tup in replies:
            p = tup[0]
            if ICMP not in p or IP not in p:
                continue
            if p[ICMP].type == 3 and p[ICMP].code == 0:
                self.assertEqual(
                    p[IP].src, self.client["gw"],
                    msg="ICMP source must be eth3 (%s), got %s"
                        % (self.client["gw"], p[IP].src),
                )
                found = True
                break

        self.assertTrue(
            found,
            msg="Expected ICMP type 3 code 0 for unknown dst %s" % unknown_ip,
        )


# ==================================================================
# TestBadRTable / TestBadRTableEntry
# ==================================================================
class TestBadRTable(_RouterTestMixin, CSE123TestBase):
    """
    Routing table has an entry for the *network* but no ARP response
    is possible for the specific host → ICMP Host Unreachable (type 3, code 1).
    """

    def test_ping_unknown_ip(self):
        """
        IP is in the routing table but the host never answers ARP.
        Expect ICMP Destination Host Unreachable (type 3, code 1) after
        the router exhausts its ARP retries.
        """
        self.clearPcapBuffers()
        # Use server1's subnet but a host address not actually present
        ghost_ip = "192.168.2.99"
        pkt = (
            Ether(src=self.client["mac"], dst=self.client["gwmac"])
            / IP(src=self.client["ip"], dst=ghost_ip, ttl=64)
            / ICMP(type=8)
        )
        self.sendPacket(pkt, node=self.client["m"].name)
        # Allow generous time for ARP retries to expire (typically 5 s)
        replies = self.expectPackets(self.client["m"].name, type="icmp",
                                     timewait_sec=6.0)

        found = False
        for tup in replies:
            p = tup[0]
            if ICMP not in p or IP not in p:
                continue
            if p[ICMP].type == 3 and p[ICMP].code == 1:   # Host Unreachable
                found = True
                break

        self.assertTrue(
            found,
            msg="Expected ICMP type 3 code 1 (Host Unreachable) for %s" % ghost_ip,
        )


class TestBadRTableEntry(_RouterTestMixin, CSE123TestBase):
    """
    Routing table lookup edge cases: missing entry vs. a non-exact match.
    """

    def test_ping_bad_ip(self):
        """
        IP not in routing table at all → ICMP Destination Net Unreachable
        (type 3, code 0).
        """
        self.clearPcapBuffers()
        unknown_ip = "55.66.77.88"
        pkt = (
            Ether(src=self.client["mac"], dst=self.client["gwmac"])
            / IP(src=self.client["ip"], dst=unknown_ip, ttl=64)
            / ICMP(type=8)
        )
        self.sendPacket(pkt, node=self.client["m"].name)
        replies = self.expectPackets(self.client["m"].name, type="icmp",
                                     timewait_sec=2.0)

        found = False
        for tup in replies:
            p = tup[0]
            if ICMP not in p or IP not in p:
                continue
            if p[ICMP].type == 3 and p[ICMP].code == 0:
                found = True
                break

        self.assertTrue(
            found,
            msg="Expected Net Unreachable (type 3 code 0) for IP not in table: %s"
                % unknown_ip,
        )

    def test_ping_good_ip(self):
        """
        IP *is* listed in the routing table but only as a non-exact match
        (subnet entry, not /32).  Since no exact-match host entry exists,
        the router should return ICMP Destination Net Unreachable (type 3, code 0).

        Note: the routing table loaded by this project uses /32 host routes,
        so any address in the same subnet that isn't the exact host entry
        qualifies as this scenario.
        """
        self.clearPcapBuffers()
        # 192.168.2.50 is in server1's subnet but not an exact routing table entry
        partial_ip = "192.168.2.50"
        pkt = (
            Ether(src=self.client["mac"], dst=self.client["gwmac"])
            / IP(src=self.client["ip"], dst=partial_ip, ttl=64)
            / ICMP(type=8)
        )
        self.sendPacket(pkt, node=self.client["m"].name)
        replies = self.expectPackets(self.client["m"].name, type="icmp",
                                     timewait_sec=2.0)

        found = False
        for tup in replies:
            p = tup[0]
            if ICMP not in p or IP not in p:
                continue
            if p[ICMP].type == 3 and p[ICMP].code == 0:
                found = True
                break

        self.assertTrue(
            found,
            msg="Expected Net Unreachable for non-exact route match to %s" % partial_ip,
        )


# ==================================================================
# TestDelayARP
# ==================================================================
class TestDelayARP(_RouterTestMixin, CSE123TestBase):
    """
    ARP retry / queuing tests.  The servers are configured to delay
    their ARP replies; we verify the router retries ARP at least once
    and eventually delivers queued packets.
    """

    def _send_udp_and_check_arp_retry(self, dst_node, count=1, timewait=6.0):
        """
        Send `count` UDP packets toward `dst_node` and confirm the router
        issues *multiple* ARP requests (op=1, pdst=dst_node["ip"]) on
        that link — evidence of retry behaviour.
        Returns the list of ARP requests seen.
        """
        self.clearPcapBuffers()
        for i in range(count):
            pkt = (
                Ether(src=self.client["mac"], dst=self.client["gwmac"])
                / IP(src=self.client["ip"], dst=dst_node["ip"], ttl=64)
                / UDP(sport=5000 + i, dport=5001)
                / Raw(load=("pkt-%d" % i).encode())
            )
            self.sendPacket(pkt, node=self.client["m"].name)

        all_pkts = self.expectPackets(dst_node["m"].name, type="arp",
                                      timewait_sec=timewait)
        arp_requests = [
            tup for tup in all_pkts
            if ARP in tup[0]
            and tup[0][ARP].op == 1
            and tup[0][ARP].pdst == dst_node["ip"]
        ]
        return arp_requests

    # ------------------------------------------------------------------
    # test_client_server1
    # ------------------------------------------------------------------
    def test_client_server1(self):
        """
        With server1 delaying ARP replies, the router must retry its ARP
        request; we expect to see more than one ARP request for server1.
        """
        arp_reqs = self._send_udp_and_check_arp_retry(self.server1)
        self.assertGreater(
            len(arp_reqs), 1,
            msg="Router should retry ARP for server1; saw only %d request(s)."
                % len(arp_reqs),
        )

    # ------------------------------------------------------------------
    # test_client_server2
    # ------------------------------------------------------------------
    def test_client_server2(self):
        """Same delay-ARP retry test for server2."""
        arp_reqs = self._send_udp_and_check_arp_retry(self.server2)
        self.assertGreater(
            len(arp_reqs), 1,
            msg="Router should retry ARP for server2; saw only %d request(s)."
                % len(arp_reqs),
        )

    # ------------------------------------------------------------------
    # test_multiple_client_server1
    # Multiple packets queued while ARP is pending for server1.
    # ------------------------------------------------------------------
    def test_multiple_client_server1(self):
        """
        Send 3 UDP packets toward server1 while ARP is pending.
        The router must still retry ARP and (eventually) forward queued packets.
        """
        arp_reqs = self._send_udp_and_check_arp_retry(self.server1, count=3)
        self.assertGreater(
            len(arp_reqs), 1,
            msg="Router should retry ARP even with multiple packets queued for server1.",
        )

    # ------------------------------------------------------------------
    # test_multiple_client_server2
    # ------------------------------------------------------------------
    def test_multiple_client_server2(self):
        """Same multiple-queued-packet retry test for server2."""
        arp_reqs = self._send_udp_and_check_arp_retry(self.server2, count=3)
        self.assertGreater(
            len(arp_reqs), 1,
            msg="Router should retry ARP even with multiple packets queued for server2.",
        )

    # ------------------------------------------------------------------
    # test_multiple_client_server1_check_udp
    # Note from spec: packet is actually sent to server2 despite the name.
    # Verifies UDP payload integrity after delayed-ARP resolution.
    # ------------------------------------------------------------------
    def test_multiple_client_server1_check_udp(self):
        """
        Send multiple UDP packets (actually toward server2, per spec note)
        while ARP is delayed; after ARP resolves, verify at least one UDP
        with the correct payload arrives at server2.
        """
        self.clearPcapBuffers()
        marker = b"delay-udp-check"
        for i in range(3):
            pkt = (
                Ether(src=self.client["mac"], dst=self.client["gwmac"])
                / IP(src=self.client["ip"], dst=self.server2["ip"], ttl=64)
                / UDP(sport=5000 + i, dport=5001)
                / Raw(load=marker)
            )
            self.sendPacket(pkt, node=self.client["m"].name)

        # Wait for ARP retry + forwarding to complete
        udp_pkts = self.expectPackets(self.server2["m"].name, type="udp",
                                      timewait_sec=6.0)
        payload_arrived = any(
            Raw in tup[0] and tup[0][Raw].load == marker
            for tup in udp_pkts
        )
        self.assertTrue(
            payload_arrived,
            msg="Expected forwarded UDP with payload '%s' at server2 after ARP retry."
                % marker,
        )


# ==================================================================
# TestDropIP
# ==================================================================
class TestDropIP(_RouterTestMixin, CSE123TestBase):
    """
    Non-ICMP IP packets addressed *to the router itself* (not to a
    host behind it) should be dropped — the router is not an endpoint
    for arbitrary IP protocols.
    """

    def test_send_ip_to_router(self):
        """
        Send a raw IP packet (protocol 253, experimental) directly to
        the router's eth3 IP (10.0.1.1).  No forwarding, no ICMP reply.
        """
        self.clearPcapBuffers()
        pkt = (
            Ether(src=self.client["mac"], dst=self.client["gwmac"])
            / IP(src=self.client["ip"], dst=self.client["gw"],
                 proto=253, ttl=64)            # protocol 253 = experimental
            / Raw(load=b"not-icmp-not-udp")
        )
        self.sendPacket(pkt, node=self.client["m"].name)
        pkts = self.expectPackets(self.client["m"].name, timewait_sec=1.0)
        unexpected = [
            tup for tup in pkts
            if IP in tup[0] and tup[0][IP].dst == self.client["ip"]
        ]
        self.assertEqual(
            len(unexpected), 0,
            msg="Router must drop non-ICMP IP packets addressed to itself; "
                "got %s" % unexpected,
        )


# ==================================================================
# TestDropOnNoARP
# ==================================================================
class TestDropOnNoARP(_RouterTestMixin, CSE123TestBase):
    """
    When the router cannot resolve an ARP reply after exhausting retries,
    it must drop the queued packet(s) and send ICMP Host Unreachable
    (type 3, code 1) back to the originating host.  The ICMP source IP
    must be the router interface that *received* the original packet.
    """

    def _check_drop_with_icmp(self, dst_node, label):
        """
        Send a UDP to `dst_node` (which will not respond to ARP).
        Assert we receive ICMP type 3 code 1 sourced from the correct
        router interface IP.
        """
        self.clearPcapBuffers()
        pkt = (
            Ether(src=self.client["mac"], dst=self.client["gwmac"])
            / IP(src=self.client["ip"], dst=dst_node["ip"], ttl=64)
            / UDP(sport=5000, dport=5001)
            / Raw(load=b"drop-me")
        )
        self.sendPacket(pkt, node=self.client["m"].name)
        replies = self.expectPackets(self.client["m"].name, type="icmp",
                                     timewait_sec=6.0)

        found = False
        for tup in replies:
            p = tup[0]
            if ICMP not in p or IP not in p:
                continue
            if p[ICMP].type == 3 and p[ICMP].code == 1:   # Host Unreachable
                self.assertEqual(
                    p[IP].src, self.client["gw"],
                    msg="[%s] ICMP Host Unreachable must come from router eth3 (%s), "
                        "not %s" % (label, self.client["gw"], p[IP].src),
                )
                found = True
                break

        self.assertTrue(
            found,
            msg="[%s] Expected ICMP Host Unreachable after ARP timeout for %s"
                % (label, dst_node["ip"]),
        )

    def test_client_server1(self):
        """Drop + ICMP Host Unreachable when server1 never replies to ARP."""
        self._check_drop_with_icmp(self.server1, "server1")

    def test_client_server2(self):
        """Drop + ICMP Host Unreachable when server2 never replies to ARP."""
        self._check_drop_with_icmp(self.server2, "server2")

    def test_twice_client_server1(self):
        """Same drop+ICMP test for server1, run twice for regression."""
        for _ in range(2):
            self._check_drop_with_icmp(self.server1, "server1")

    def test_twice_client_server2(self):
        """Same drop+ICMP test for server2, run twice for regression."""
        for _ in range(2):
            self._check_drop_with_icmp(self.server2, "server2")


# ==================================================================
# TestEthertype
# ==================================================================
class TestEthertype(_RouterTestMixin, CSE123TestBase):
    """
    Frames with an unrecognised EtherType must be dropped by the router
    without forwarding or generating any reply.
    """

    def test_drop_invalid_ethertype(self):
        """
        Send an Ethernet frame with EtherType 0x88B5 (IEEE 802 local
        experimental — not IP/ARP).  The router must silently drop it.
        """
        self.clearPcapBuffers()
        pkt = Ether(src=self.client["mac"],
                    dst=self.client["gwmac"],
                    type=0x88B5)              # non-IP, non-ARP ethertype
        pkt = pkt / Raw(load=b"\x00" * 20)
        self.sendPacket(pkt, node=self.client["m"].name)

        pkts = self.expectPackets(self.client["m"].name, timewait_sec=1.0)
        # Nothing should come back
        self.assertEqual(
            len(pkts), 0,
            msg="Router must drop frames with unsupported EtherType 0x88B5; "
                "got: %s" % pkts,
        )


# ==================================================================
# TestICMP
# ==================================================================
class TestICMP(_RouterTestMixin, CSE123TestBase):
    """
    End-to-end ICMP echo (ping) forwarding tests using Scapy.
    """

    def _ping_through_router(self, dst_ip, src_node, payload=None):
        """
        Build an ICMP echo-request from src_node to dst_ip, send it,
        and wait for an ICMP echo-reply (type 0) to come back on
        src_node's link.  Returns True if a reply is found.
        """
        self.clearPcapBuffers()
        ip_id = random.randint(1, 65535)
        pkt = (
            Ether(src=src_node["mac"], dst=src_node["gwmac"])
            / IP(src=src_node["ip"], dst=dst_ip, id=ip_id, ttl=64)
            / ICMP(type=8, id=0xBB, seq=1)
        )
        if payload:
            pkt = pkt / Raw(load=payload)

        self.sendPacket(pkt, node=src_node["m"].name)
        replies = self.expectPackets(src_node["m"].name, type="icmp",
                                     timewait_sec=3.0)
        for tup in replies:
            p = tup[0]
            if ICMP in p and p[ICMP].type == 0 and IP in p:
                if p[IP].id == ip_id:
                    return True
        return False

    def test_icmp_cmd(self):
        """
        Ping from client to server1 and server2 through the router.
        Both should receive and echo back.
        """
        ok1 = self._ping_through_router(self.server1["ip"], self.client)
        self.assertTrue(ok1, msg="ICMP ping from client to server1 failed.")

        ok2 = self._ping_through_router(self.server2["ip"], self.client)
        self.assertTrue(ok2, msg="ICMP ping from client to server2 failed.")

    def test_icmp_custom_packet(self):
        """
        Same as test_icmp_cmd but with a random-content payload to guard
        against a router that might generate fake replies.
        """
        random_payload = bytes(random.randint(0, 255) for _ in range(16))
        ok1 = self._ping_through_router(self.server1["ip"], self.client,
                                         payload=random_payload)
        self.assertTrue(ok1,
                        msg="Custom-payload ICMP ping to server1 failed.")

        ok2 = self._ping_through_router(self.server2["ip"], self.client,
                                         payload=random_payload)
        self.assertTrue(ok2,
                        msg="Custom-payload ICMP ping to server2 failed.")


# ==================================================================
# TestPing
# ==================================================================
class TestPing(_RouterTestMixin, CSE123TestBase):
    """
    Comprehensive ping suite: link-local pings, cross-network pings,
    TTL expiry behaviour, and size boundary checks.
    """

    def _expect_icmp_reply(self, src_node, dst_ip, expected_type=0,
                            expected_code=None, ttl=64, timewait=2.0):
        """
        Send an ICMP echo from src_node to dst_ip and assert we get
        back an ICMP packet of `expected_type` (and optionally `expected_code`).
        Returns the matching packet or None.
        """
        self.clearPcapBuffers()
        ip_id = random.randint(1, 65535)
        pkt = (
            Ether(src=src_node["mac"], dst=src_node["gwmac"])
            / IP(src=src_node["ip"], dst=dst_ip, id=ip_id, ttl=ttl)
            / ICMP(type=8, id=0xCC, seq=1)
        )
        self.sendPacket(pkt, node=src_node["m"].name)
        replies = self.expectPackets(src_node["m"].name, type="icmp",
                                     timewait_sec=timewait)
        for tup in replies:
            p = tup[0]
            if ICMP not in p or IP not in p:
                continue
            if p[ICMP].type != expected_type:
                continue
            if expected_code is not None and p[ICMP].code != expected_code:
                continue
            return p
        return None

    # ------------------------------------------------------------------
    # test_all_gw
    # Each host pings its own directly-connected router interface.
    # ------------------------------------------------------------------
    def test_all_gw(self):
        """
        client → 10.0.1.1, server1 → 192.168.2.1, server2 → 172.64.3.1
        Each should receive an ICMP echo-reply (type 0).
        """
        pairs = [
            (self.client,  self.client["gw"],  "client→eth3"),
            (self.server1, self.server1["gw"], "server1→eth1"),
            (self.server2, self.server2["gw"], "server2→eth2"),
        ]
        for node, gw_ip, label in pairs:
            p = self._expect_icmp_reply(node, gw_ip)
            self.assertIsNotNone(
                p, msg="[%s] No ICMP reply from router gateway %s" % (label, gw_ip)
            )

    # ------------------------------------------------------------------
    # test_large_size
    # Ping server1 with a large payload (close to MTU).
    # ------------------------------------------------------------------
    def test_large_size(self):
        """Large ICMP payload (1400 bytes) from client to server1."""
        self.clearPcapBuffers()
        ip_id = random.randint(1, 65535)
        large_payload = b"X" * 1400
        pkt = (
            Ether(src=self.client["mac"], dst=self.client["gwmac"])
            / IP(src=self.client["ip"], dst=self.server1["ip"], id=ip_id, ttl=64)
            / ICMP(type=8)
            / Raw(load=large_payload)
        )
        self.sendPacket(pkt, node=self.client["m"].name)
        replies = self.expectPackets(self.client["m"].name, type="icmp",
                                     timewait_sec=3.0)
        found = any(
            ICMP in tup[0] and tup[0][ICMP].type == 0 and
            IP in tup[0] and tup[0][IP].id == ip_id
            for tup in replies
        )
        self.assertTrue(found, msg="Large ICMP echo to server1 got no reply.")

    # ------------------------------------------------------------------
    # test_ping_client
    # Ping from client to its own link-local router interface (eth3).
    # ------------------------------------------------------------------
    def test_ping_client(self):
        """Client pings router eth3 (10.0.1.1) — must get echo-reply."""
        p = self._expect_icmp_reply(self.client, self.client["gw"])
        self.assertIsNotNone(p, msg="No ICMP reply from router eth3 (10.0.1.1).")

    # ------------------------------------------------------------------
    # test_ping_router_check_ttl
    # Send ICMP with TTL=1 to a router IP → router must *consume* it
    # (not decrement and drop), so we still get an echo-reply.
    # ------------------------------------------------------------------
    def test_ping_router_check_ttl(self):
        """
        TTL=1 ICMP to router's own IP (eth3).  The router itself is the
        destination so it should still reply — no Time Exceeded expected.
        """
        p = self._expect_icmp_reply(self.client, self.client["gw"], ttl=1)
        self.assertIsNotNone(
            p, msg="Router should reply to TTL=1 ICMP addressed to itself."
        )

    # ------------------------------------------------------------------
    # test_ping_router_check_ttl_dest
    # TTL=1 to a *forwarded* destination → Time Exceeded; TTL=2 → works.
    # ------------------------------------------------------------------
    def test_ping_router_check_ttl_dest(self):
        """
        TTL=1 toward server1 (must be forwarded) → ICMP Time Exceeded
        (type 11, code 0) from router.
        TTL=2 toward server1 → router decrements to 1, forwards; server1
        echoes back.
        """
        # TTL=1 — should yield Time Exceeded
        p_ttl1 = self._expect_icmp_reply(
            self.client, self.server1["ip"],
            expected_type=11, expected_code=0, ttl=1
        )
        self.assertIsNotNone(
            p_ttl1,
            msg="Expected ICMP Time Exceeded (type 11) for TTL=1 toward server1.",
        )

        # TTL=2 — router decrements to 1 and forwards; server1 replies
        p_ttl2 = self._expect_icmp_reply(
            self.client, self.server1["ip"],
            expected_type=0, ttl=2, timewait=3.0
        )
        self.assertIsNotNone(
            p_ttl2,
            msg="Expected echo-reply for TTL=2 toward server1.",
        )

    # ------------------------------------------------------------------
    # test_ping_router_check_ttl_other_iface
    # TTL=1 to a non-directly-connected router interface (e.g. eth1 from client).
    # The router should treat this as addressed-to-self and reply.
    # ------------------------------------------------------------------
    def test_ping_router_check_ttl_other_iface(self):
        """
        TTL=1 ICMP from client to router's eth1 IP (192.168.2.1).
        eth1 is not on client's subnet but the router owns it; it should
        still generate an echo-reply (not Time Exceeded).
        """
        p = self._expect_icmp_reply(
            self.client, self.server1["gw"],   # 192.168.2.1 = router eth1
            expected_type=0, ttl=1
        )
        self.assertIsNotNone(
            p,
            msg="Router must reply to TTL=1 ICMP addressed to its own eth1 (192.168.2.1).",
        )

    # ------------------------------------------------------------------
    # test_ping_server1
    # server1 pings its own gateway (eth1).
    # ------------------------------------------------------------------
    def test_ping_server1(self):
        """server1 pings router eth1 (192.168.2.1) and expects a reply."""
        p = self._expect_icmp_reply(self.server1, self.server1["gw"])
        self.assertIsNotNone(p, msg="No ICMP reply from router eth1 for server1.")

    # ------------------------------------------------------------------
    # test_ping_server1_to_server2
    # Cross-network ping: server1 → server2 via router.
    # ------------------------------------------------------------------
    def test_ping_server1_to_server2(self):
        """server1 pings server2 (172.64.3.10) through the router."""
        p = self._expect_icmp_reply(
            self.server1, self.server2["ip"], timewait=3.0
        )
        self.assertIsNotNone(
            p, msg="No ICMP echo-reply from server2 seen at server1."
        )

    # ------------------------------------------------------------------
    # test_ping_server2
    # server2 pings its own gateway (eth2).
    # ------------------------------------------------------------------
    def test_ping_server2(self):
        """server2 pings router eth2 (172.64.3.1) and expects a reply."""
        p = self._expect_icmp_reply(self.server2, self.server2["gw"])
        self.assertIsNotNone(p, msg="No ICMP reply from router eth2 for server2.")

    # ------------------------------------------------------------------
    # test_small_size
    # Ping server1 with a minimal (1-byte) payload.
    # ------------------------------------------------------------------
    def test_small_size(self):
        """Tiny ICMP payload (1 byte) from client to server1."""
        self.clearPcapBuffers()
        ip_id = random.randint(1, 65535)
        pkt = (
            Ether(src=self.client["mac"], dst=self.client["gwmac"])
            / IP(src=self.client["ip"], dst=self.server1["ip"], id=ip_id, ttl=64)
            / ICMP(type=8)
            / Raw(load=b"\x42")               # single byte payload
        )
        self.sendPacket(pkt, node=self.client["m"].name)
        replies = self.expectPackets(self.client["m"].name, type="icmp",
                                     timewait_sec=3.0)
        found = any(
            ICMP in tup[0] and tup[0][ICMP].type == 0 and
            IP in tup[0] and tup[0][IP].id == ip_id
            for tup in replies
        )
        self.assertTrue(found, msg="Small ICMP echo to server1 got no reply.")


# ==================================================================
# Original stubs (kept for compatibility)
# ==================================================================
class TestSamplePlaceholder(CSE123TestBase):
    """Original stub — kept so `test_case` still runs if you want a no-op."""

    def setUp(self):
        self.setUpEnvironment(rtable="rtable", build=True, debug=False, manual_sr=False)

    def tearDown(self):
        self.tearDownEnvironment()

    def test_case(self):
        self.assertTrue(True)


if __name__ == "__main__":
    unittest.main()
