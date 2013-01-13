#!/usr/bin/python
#coding=utf-8

try:
    from gevent import socket
    from gevent import monkey
    monkey.patch_all()
except:
    import socket

import re
import time
import urllib2
from config import TLDS, WHOIS_SERVER, NO_MATCH_INFO, TIMEOUT, MAX_RETRY_TIMES

socket.setdefaulttimeout(TIMEOUT)

def whois(server, domain):
    '''get whois info from whois server'''
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    fail_times = 0
    while fail_times < MAX_RETRY_TIMES:
        try:
            s.connect((server, 43))
            break
        except socket.error:
            fail_times += 1

    if fail_times == MAX_RETRY_TIMES:
        s.close()
        return None

    s.send('%s \r\n' % domain)
    response = []
    while 1:
        try:
            data = s.recv(1024)
        except socket.error:
            s.close()
            return None
        response.append(data)
        if data == '' or data == None:
            break
    s.close()
    whois_info = ''.join(response)
    return whois_info

if __name__ == '__main__':
    pass
