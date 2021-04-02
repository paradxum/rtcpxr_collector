#!/usr/bin/python3
# vi:si:et:sw=4:sts=4:ts=4
# -*- coding: UTF-8 -*-
# -*- Mode: Python -*-
#

import re


def parseSipAddr(addr):
    if isinstance(addr, str):
        addr = [addr]
    for a in addr:
        m = re.search(r'(\"(.+)\" |)\<sip\:([0-9A-F]+)\@([0-9.]+)(\:([0-9]+)|)(;.*|)\>', a)
        if m:
            res = {}
            res['desc'] = ''
            if m.group(2) is not None:
                res['desc'] = m.group(2)
            res['name'] = m.group(3)
            res['ip'] = m.group(4)
            res['port'] = ''
            if m.group(6) is not None:
                res['port'] = m.group(6)
            return res
        # else:
        #     print("Could not parse Address: ##%s##" % a)
    return False


def parsesip(r):
    res = {}

    # Grab what we want from the header
    res['Handset'] = {}
    packetTo = parseSipAddr(r.headers['to'])
    if packetTo \
            and packetTo['name'] is not None \
            and packetTo['name'] != '' \
            and re.match(r'[0-9A-F]{12}', packetTo['name']):
        res['Handset']['MAC'] = packetTo['name']
    # else:
    #     print("Error with to: ##%s##" % r.headers['to'])
    res['Handset']['from'] = parseSipAddr(r.headers['from'])
    res['Handset']['contact'] = parseSipAddr(r.headers['contact'])
    res['Handset']['user-agent'] = r.headers['user-agent']

    # Process the Body
    for e in r.body.split('\r\n'):
        if e == '':
            continue

        esp = e.split(':', 1)
        if len(esp) == 0:
            continue

        if len(esp) == 1:
            res[esp[0]] = []
            continue

        if esp[0] in ('RemoteID', 'OrigID', 'LocalID'):
            res[esp[0]] = parseSipAddr(esp[1])
            continue

        values = re.split(r' |;', esp[1])
        if len(values) == 1:
            res[esp[0]] = values[0]
            continue

        res[esp[0]] = {}
        for v in values:
            vvs = v.split('=', 1)
            if len(vvs) == 1:
                res[esp[0]][vvs[0]] = ''
            else:
                res[esp[0]][vvs[0]] = vvs[1]
    return res
