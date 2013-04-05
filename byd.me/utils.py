#!/usr/bin/python
#coding=utf-8

import config
import re
import time
try:
    from gevent import socket
    from gevent import monkey
    monkey.patch_all()
except:
    import socket
    socket.setdefaulttimeout(config.TIMEOUT)
import urllib2

def whois(server, domain):
    '''get whois info from whois server'''
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    fail_times = 0
    while fail_times < config.MAX_RETRY_TIMES:
        try:
            s.connect((server, 43))
            break
        except socket.error:
            fail_times += 1

    if fail_times == config.MAX_RETRY_TIMES:
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

def check(domain):
    '''check whether domain can be registered'''

    if '.' not in domain :
        domain = '%s.com' % domain
    tld = domain.split('.')[-1]
    whois_info = whois(config.WHOIS_SERVER[tld], domain)
    if not whois_info:
        message = u'你错了还是我错了，亲？ /抠鼻'
        return message
    if config.NO_MATCH_INFO[tld] in whois_info:
        message = u'%s 可以注册，亲 /微笑' % domain
    else:
        message = u'%s 已被注册，亲 /难过 \nwhois: byd.me/whois/%s' % (domain, domain)
    return message


if __name__ == '__main__':
    pass
