#!/usr/bin/python3
# vi:si:et:sw=4:sts=4:ts=4
# -*- coding: UTF-8 -*-
# -*- Mode: Python -*-

import socket, re, sys, select
from . import sip, sipparser

import pprint


class CreateSocketError(Exception):
    pass


class BindSocketError(Exception):
    pass


class SendDataError(Exception):
    pass


class UnsupportedSIPVersion(Exception):
    pass


class UnsupportedSIPTransport(Exception):
    pass


class CollectorServer:
    '''

    The CollectorServer object opens a SIP socket to receive RTCP-XR packets,
    parses them, then sends the data to a handler.

    Args:
        - None -

    Attributes:
        local_ip (ipV4 address): [None] Local IPV4 address to bind to (None: Autodetect)
        port (int)             : [5060] Local Port to bind to
        reply_to_socket (bool) : [False] Should we reply to the address from the socket, or the SIP Header
        debug (bool)           : [False] Print Debugging information
        handler (func)         : [None] Handler function for recieved data (None: pprint res data)

    Handler Function:
        Takes 1 arg that is the parsed data structure.
    '''
    def __init__(self, local_ip=None, port=5060, reply_to_socket=False, debug=False, handler=None):
        self.port = port
        self.reply_to_socket = reply_to_socket
        self.debug = debug

        self.handler = handler
        if self.handler is None:
            self.handler = self.default_handler

        self.local_ip = local_ip
        if self.local_ip is None:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('google.com', 80))
            self.local_ip = s.getsockname()[0]
            s.close()

        self.printDebug("Local IP: %s" % self.local_ip)

        self.recvsocket = self._create_socket()

    def printDebug(self, *args, **kwargs):
        if self.debug:
            print(*args, file=sys.stderr, **kwargs)

    def listen(self):
        inputs = [self.recvsocket]
        outputs = []

        self.printDebug("Starting listening loop")

        while inputs:
            readable, writable, exceptional = select.select(inputs, outputs, inputs)
            for s in readable:
                if s is self.recvsocket:
                    if not self.handle_sip_packet():
                        continue

    def handle_sip_packet(self):
        data, remote = self.recvsocket.recvfrom(10240)
        try:
            request = sip.Request(data)
        except sip.SipUnpackError:
            return False

        self.printDebug("Received request from %s:%d : \n%s" % (remote[0], remote[1], str(request)))

        # Verify SIP transport and Version
        # Regexp parsing via Header: SIP/2.0/UDP 172.16.18.90:5060;rport
        m = re.search(r'SIP/(.*)/(.*)\s(.*):([0-9]*);*', request.headers['via'])
        if not m:
            SendDataError("Wrong Via: header")
            return False
        if m.group(1) != "2.0":
            UnsupportedSIPVersion("Unsupported SIP version in Via header: %s" % m.group(1))
            return False
        if m.group(2).upper() != "UDP":
            UnsupportedSIPTransport("Unsupported Transport in Via: header")
            return False

        # Build our response
        response = sip.Response()
        if request.method != "PUBLISH" \
                or "content-type" not in request.headers \
                or request.headers["content-type"] != "application/vq-rtcpxr":
            self.printDebug("Received a non PUBLISH: %s" % request.method)
            response.reason = "Not implemented"
            response.status = "501"
        for i in ['via', 'from', 'to', 'cseq', 'call-id']:
            if i in request.headers:
                response.headers[i] = request.headers[i]
            else:
                response.headers[i] = ''
        response.headers['content-length'] = 0
        response.headers['expires'] = 0
        response.headers['contact'] = "<sip:%s:%d;transport=tcp;handler=dum>" % (self.local_ip, self.port)

        # Determine endpoint to send to
        if self.reply_to_socket is False:
            sipaddr = sipparser.parseSipAddr(request.headers['contact'])
            if sipaddr:
                phone_ip = sipaddr['ip']
                phone_port = sipaddr['port']
                self.printDebug("Phone IP and port from Contact header: %s:%s" % (phone_ip, phone_port))
        else:
            phone_ip = remote[0]
            phone_port = remote[1]
            self.printDebug("Phone IP and port from socket: %s:%d" % (phone_ip, phone_port))

        self.send_response(phone_ip, phone_port, response)

        self.handler(sipparser.parsesip(request))

    def default_handler(self, request):
        pp = pprint.PrettyPrinter(indent=2)
        pp.pprint(request)

    def send_response(self, phone_ip, phone_port, response):
        self.printDebug("Creating send socket")
        try:
            self.sendsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        except Exception as e:
            CreateSocketError("Cannot create socket: %s" % e)
        try:
            self.sendsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sendsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        try:
            self.printDebug("Binding to local ip:port %s:%s" % (self.local_ip, self.port))
            self.sendsock.bind((self.local_ip, self.port))
        except Exception as e:
            SendDataError("Cannot bind socket to %s:%d: %s" % (self.local_ip, self.port, e))

        # sent the OK (or 501)
        try:
            self.printDebug("Sending response to %s:%s : \n%s" % (phone_ip, phone_port, str(response)))
            sent = self.sendsock.sendto(str(response).encode("utf-8"), (phone_ip, int(phone_port)))
            self.printDebug("Sent %s bytes" % sent)
        except Exception as e:
            SendDataError("Cannot send OK/DENY response to %s:%s: %s" % (phone_ip, phone_port, e))
        self.sendsock.close()

    def _create_socket(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setblocking(0)
        except Exception as e:
            raise CreateSocketError("Cannot create socket: %s" % e)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        try:
            sock.bind((socket.gethostbyname(self.local_ip), self.port))
        except Exception as e:
            raise BindSocketError("Cannot bind socket to %s:%d: %s" % (self.local_ip, self.port, e))
        return sock
