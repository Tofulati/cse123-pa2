"""
CSE 123 autograder library.
(Adapted from "cse123_test_base.py")

Author      : Adyanth Hosavalike (ahosavalike@ucsd.edu)
Author      : Rajdeep Das (r4das@ucsd.edu)
Offering    : Spring 2023
"""

import pexpect
import unittest
import os
import re
import subprocess
import threading
import time
import shutil
import traceback
import logging
import warnings
import contextlib
import io
import sys

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from scapy.all import sendp, sniff, Ether, ARP, ICMP, IP, IPv6, TCP, UDP
from queue import Queue, Empty

from project_base.lab import *

@contextlib.contextmanager
def nostdout():
    tso = sys.stdout
    sys.stdout = io.StringIO()
    yield
    sys.stdout = tso

class cd:
    """Context manager for changing the current working directory"""
    def __init__(self, new_path):
        self.new_path = os.path.expanduser(new_path)

    def __enter__(self):
        self.saved_path = os.getcwd()
        if self.saved_path != self.new_path:
            os.chdir(self.new_path)

    def __exit__(self, etype, value, traceback):
        os.chdir(self.saved_path)

"""
Base unit test class for all tests. Contains environment setup and test utility functions.
"""
class CSE123TestBase(unittest.TestCase):
    TEST_DIR = os.getcwd()
    LOCK_FILE = os.path.join(TEST_DIR, 'test.lock')

    SUBMISSION_DIR = os.path.join(TEST_DIR, "..")
    VNET_BASE_PATH = "/project-base/"

    NODES = ('server1', 'server2', 'client')

    DEFAULT_NODE = 'client'

    def buildSRSolution(self):
        logging.info("Building solution ... ")
        with cd(self.SUBMISSION_DIR):
            with open( os.path.join(self.SUBMISSION_DIR, 'test_make_stderr.log'), 'w') as logf_stdout, \
                open( os.path.join(self.SUBMISSION_DIR, 'test_make_stdout.log'), 'w') as logf_stderr:
                try:
                    assert(os.system("make clean > /dev/null") == 0)
                    subprocess.check_call(
                        "make",
                        stdout=logf_stdout,
                        stderr=logf_stderr
                    )
                except AssertionError:
                    logging.info("Make clean failed!")
                except subprocess.CalledProcessError:
                    logging.info("Solution build failed!")
                    logging.info(traceback.format_exc())
                    return False
        return True

    def cleanupEnvironment(self):
        os.system("pkill -9 sr")
        os.system("pkill -9 python2.7")
        os.system("mn -c 2> /dev/null")
        if os.path.exists(self.LOCK_FILE):
            print("Cleaning up ... ")
            os.remove(self.LOCK_FILE)

    def setUpEnvironment(self, rtable='rtable', build=True, debug=False, manual_sr=False):

        global IPBASE, IP_SETTING

        assert(self.VNET_BASE_PATH is not None)
        assert(self.SUBMISSION_DIR is not None)

        self.cleanupEnvironment()

        with open(self.LOCK_FILE, 'w') as f:
            # pids = str(subprocess.check_output("ps -e | grep python | cut -f2 -d' '", shell=True)).splitlines()
            # f.write(",".join(pids))
            f.write("\n")
            f.close()


        self.ROUTING_TABLE = os.path.join(self.SUBMISSION_DIR, "rtables", rtable)
        shutil.copyfile(self.ROUTING_TABLE, os.path.join(self.SUBMISSION_DIR, "rtable"))

        self.pox = None
        self.mininet = None
        self.router = None

        pox_path = os.path.join(self.VNET_BASE_PATH, 'pox', 'pox.py')
        os.environ["PYTHONPATH"] = os.path.join(self.VNET_BASE_PATH, 'pox_module')
        router_path = os.path.join(self.SUBMISSION_DIR, 'sr')

        if build:
            self.assertTrue(self.buildSRSolution())

        with cd(self.VNET_BASE_PATH):
            self.pox_log = open(os.path.join(self.SUBMISSION_DIR, 'test_pox.log'), 'w')
            self.pox = pexpect.spawn(
                pox_path,
                args=['--verbose', 'ofhandler', 'srhandler', "openflow.of_01", "--port=6653"],
                logfile=self.pox_log,
                encoding="utf-8"
            )
            self.pox.expect('DEBUG:openflow.of_01:Listening on 0.0.0.0:6653')
            logging.info("POX started.")
            stophttp()
            with warnings.catch_warnings(), nostdout():
                warnings.simplefilter("ignore")
                
                get_ip_setting()
                topo = CS144Topo()
                # Gives warning even after ignore
                self.mininet = Mininet( topo=topo, controller=RemoteController, ipBase=IPBASE )
                self.mininet.start()
            server1, server2, client = self.mininet.get( 'server1', 'server2', 'client')
            s1intf = server1.defaultIntf()
            s2intf = server2.defaultIntf()
            clintf = client.defaultIntf()
            logging.info('Lab:')
            s1intf.setIP('%s/8' % IP_SETTING['server1'])
            s2intf.setIP('%s/8' % IP_SETTING['server2'])
            clintf.setIP('%s/8' % IP_SETTING['client'])

            with nostdout():
                for host in server1, server2, client:
                    set_default_route(host)
            starthttp( server1 )
            starthttp( server2 )
            self.pox.expect('.*srhandler:SRServerListener catch RouterInfo even.*')
            logging.info("Mininet started.")

        with cd(self.SUBMISSION_DIR):
            if manual_sr:
                input("Start router now and hit enter:")
            else:
                self.router_log = open(os.path.join(self.SUBMISSION_DIR, 'test_sr.log'), 'w')
                self.router = pexpect.spawn(
                    router_path,
                    ["-l", "test.pcap"],
                    logfile=self.router_log,
                    encoding="utf-8"
                )
                self.router.expect('<-- Ready to process packets -->', timeout=3)
                logging.info("Router started.")

        self.pcap_stream_client = PacketTest(clintf.link.intf2.name, client, debug=debug)
        self.pcap_stream_server1 = PacketTest(s1intf.link.intf2.name, server1, debug=debug)
        self.pcap_stream_server2 = PacketTest(s2intf.link.intf2.name, server2, debug=debug)
        self.pcap_stream_client.run()
        self.pcap_stream_server1.run()
        self.pcap_stream_server2.run()

        self.client = {
            "ip": "10.0.1.100",
            "gw": "10.0.1.1",
            "m": self.mininet.get("client"),
            "mac": self.mininet.get("client").MAC(),
            "gwmac": self.mininet.get("sw0").MAC(intf=self.mininet.get("client").defaultIntf().link.intf2.name),
        }
        self.server1 = {
            "ip": "192.168.2.2",
            "gw": "192.168.2.1",
            "m": self.mininet.get("server1"),
            "mac": self.mininet.get("server1").MAC(),
            "gwmac": self.mininet.get("sw0").MAC(intf=self.mininet.get("server1").defaultIntf().link.intf2.name),
        }
        self.server2 = {
            "ip": "172.64.3.10",
            "gw": "172.64.3.1",
            "m": self.mininet.get("server2"),
            "mac": self.mininet.get("server2").MAC(),
            "gwmac": self.mininet.get("sw0").MAC(intf=self.mininet.get("server2").defaultIntf().link.intf2.name),
        }
        self.gateways = list(map(lambda x: x["gw"], [self.client, self.server1, self.server2]))

    def tearDownEnvironment(self):
        stophttp()

        self.pcap_stream_client.stop()
        self.pcap_stream_server1.stop()
        self.pcap_stream_server2.stop()

        if self.router:
            if not self.router.terminate(force=True):
                print("Could not stop router")
            self.router.close()
            self.router_log.flush()
            self.router_log.close()

        if not self.pox.terminate(force=True):
            print("Could not stop pox")
        self.pox.close()
        self.pox_log.flush()
        self.pox_log.close()
        
        self.mininet.stop()
        
        os.remove(self.LOCK_FILE)

    def clearPcapBuffers(self):
        self.pcap_stream_client.clear()
        self.pcap_stream_server1.clear()
        self.pcap_stream_server2.clear()

    def fetchPcapBuffers(self):
        buffers = {
            'client'    : self.pcap_stream_client.fetch(),
            'server1'   : self.pcap_stream_server1.fetch(),
            'server2'   : self.pcap_stream_server2.fetch()
        }
        return buffers

    def sendPacket(self, pkt, node=None):
        if node is None:
            node = self.DEFAULT_NODE
        testNode = getattr(self, 'pcap_stream_{}'.format(node))
        return testNode.sendPkt(pkt)

    def expectPackets(self, node, type='any', pkt=None, timewait_sec=1):
        stream = getattr(self, 'pcap_stream_{}'.format(node))
        if stream is None:
            raise Exception("Invalid node!")
        time.sleep(timewait_sec)
        buffers = stream.fetch()
        matched = []
        idx = 0
        for p in buffers:
            if type == 'any':
                matched.append((p, idx))
            elif type == 'arp':
                if ARP in p:
                    matched.append((p, idx))
            elif type == 'icmp':
                if ICMP in p:
                    matched.append((p, idx))
            elif type == 'ip':
                if IP in p:
                    matched.append((p, idx))
            elif type == 'tcp':
                if TCP in p:
                    matched.append((p, idx))
            elif type == 'udp':
                if UDP in p:
                    matched.append((p, idx))
            else:
                raise Exception("Invalid type!")
            idx += 1
        return matched

    def expectNoPacket(self, sentPkt=None, sentNode=None):
        
        if sentNode is not None and sentNode not in self.NODES:
            raise Exception("Invalid node!")

        buffers = self.fetchPcapBuffers()

        for node in buffers:
            for pkt in buffers[node]:
                if (bytes(pkt) == bytes(sentPkt) and node == sentNode) or IPv6 in pkt:
                    continue
                # print(f"Received at {node}")
                # pkt.show2()
                return False
        return True

    def printPackets(self, pkts):
        idx = 1
        for p in pkts:
            if type(p) is tuple:
                pkt = p[0]
            else:
                pkt = p
            print("{}.\t{}".format(idx, str(pkt)))
            idx += 1

"""
Packet testing utilities.
"""
class PacketTest:
    """
    Observes packets on links instead of ports/interfaces.
    Similar to a tcpdump/wireshark raw capture.
    Caveat: cannot tell direction/source of packets.
    """

    def __init__(self, host_iface, mn_node, debug=False) -> None:
        self.iface = host_iface
        self.node = mn_node
        self.stream = None
        self.buffer = Queue()
        self.debug = debug
        self.stop_flag = False
        if self.debug:
            print("Packet test setup for {} on interface {}.".format(mn_node, host_iface))

    def onPktReceive(self, pkt):
        if self.debug:
            print(f"Received packet on {self.node} interface: {pkt}")
        self.buffer.put(pkt)

    def monitor(self):
        logging.info("Monitoring pcap stream on iface {} ... ".format(self.iface))
        try:
            sniff(iface=self.iface, store=False, prn=self.onPktReceive, stop_filter=lambda _: self.stop_flag)
        except Exception as e:
            print(f"Failed to sniff, {e}")

    def run(self):
        self.stream = threading.Thread(target=self.monitor)
        self.stream.start()
        # time.sleep(1) # Let scapy hook into the interface
    
    def stop(self):
        self.stop_flag = True
        self.sendPkt(Ether(src=0xffffffff, dst=0xffffffff)/ARP())
        self.stream.join(timeout=1)
        if self.stream.is_alive():
            print(f"Failed to stop sniff on {self.node} {self.iface}")

    def fetch(self):
        buffer = []
        while not self.buffer.empty():
            try:
                buffer.append(self.buffer.get(block=False))
            except Empty:
                continue
        return buffer

    def clear(self):
        with self.buffer.mutex:
            unfinished = self.buffer.unfinished_tasks - len(self.buffer.queue)
            if unfinished <= 0:
                if unfinished < 0:
                    raise ValueError('task_done() called too many times')
                self.buffer.all_tasks_done.notify_all()
            self.buffer.unfinished_tasks = unfinished
            self.buffer.queue.clear()
            self.buffer.not_full.notify_all()

    def sendPkt(self, pkt):
        proc = self.node.popen(['python3', 'remote_sender.py'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result = proc.communicate(input=pkt.build())
        assert(len(result) > 0)
        result = re.findall("sent ([0-9]+) bytes", str(result[0]))
        assert(len(result) > 0)
        return [pkt]

    # # Does not work, no idea why :) Mostly scapy needs something that is not possible when running sniff in the same process
    # def sendPkt(self, pkt):
    #     iface = self.node.intf().link.intf2
    #     if self.debug:
    #         print(f"Sending to {iface.name}")
    #     sent = sendp(Ether(bytes(pkt)), verbose=False, return_packets=True)
    #     print(f"sent {len(bytes(pkt))} bytes from {self.node} node interface {self.iface}")
    #     return sent
