#!/usr/bin/python
#coding=utf-8

import gevent
from gevent import socket
from gevent import monkey
monkey.patch_all()

import re
import config
import json
import requests

GPR_HASH_SEED = ("Mining PageRank is AGAINST GOOGLE'S TERMS OF SERVICE. "
                 "Yes, I'm talking to you, scammer.")

s = requests.Session()


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
        if data == '' or data is None:
            break
    s.close()
    whois_info = ''.join(response)
    return whois_info


def check(domain):
    '''check whether domain can be registered'''

    if '.' not in domain:
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


def checkone(prefix, suffix):

    with gevent.Timeout(config.TIMEOUT, False):
        try:
            whois_info = whois(
                config.WHOIS_SERVER[suffix], '%s.%s' % (prefix, suffix))
        except KeyError:
            return -1
        if not whois_info:
            return -1
        return config.NO_MATCH_INFO[suffix] in whois_info


def checkall(prefix):

    pop_tlds = ['com', 'net', 'org', 'cc', 'co', 'me', 'in', 'info',
                'mobi', 'biz', 'cn']
    jobs = [gevent.spawn(checkone, prefix, suffix) for suffix in pop_tlds]
    gevent.joinall(jobs)
    results = [job.value for job in jobs]
    results = map(lambda r: r if r is not None else -1, results)
    return results

baidu_site_match = re.compile('class="nums"[^>]*?>.*?(?P<baidu>[,0-9]+).*?<')
baidu_link_match = re.compile('class="nums"[^>]*?>.*?(?P<baidu>[,0-9]+).*?<')
sogou_site_match = re.compile(r'zhanzhang.*?em>(?P<sogou>[,0-9]+)<')
sogou_link_match = re.compile(r'id="scd_num">(?P<sogou>[,0-9]+)<')
google_site_match = re.compile('"estimatedResultCount":"(?P<google>\d+)"')
google_link_match = re.compile('"estimatedResultCount":"(?P<google>\d+)"')

SITES = {
    'baidu_site': {
        'name': '',
        'match': baidu_site_match,
        'url': 'http://www.baidu.com/s?wd=site:%s',
    },
    'baidu_link': {
        'name': '',
        'match': baidu_link_match,
        'url': 'http://www.baidu.com/s?wd=domain:%s',
    },
    'sogou_site': {
        'name': '',
        'match': sogou_site_match,
        'url': 'http://www.sogou.com/web?query=site:%s',
    },
    'sogou_link': {
        'name': '',
        'match': sogou_link_match,
        'url': 'http://www.sogou.com/web?query="%s"',
    },
    'google_site': {
        'name': '',
        'match': google_site_match,
        'url': ('http://ajax.googleapis.com/ajax/services/search/web?v=1.0&'
                'q=site:%s'),
    },
    'google_link': {
        'name': '',
        'match': google_link_match,
        'url': ('http://ajax.googleapis.com/ajax/services/search/web?v=1.0&'
                'q=link:%s'),
    }
}


def get_seo_info(domain):
    info = {}
    for typ in SITES:
        url = SITES[typ]['url'] % domain
        content = requests.get(url).content
        try:
            num = int(SITES[typ]['match'].findall(content)[0].replace(',', ''))
        except:
            num = -1
        info[typ] = num
    return json.dumps(info)


def get_pagerank(domain):
    q = 'http://%s' % domain if not domain.startswith('http://') else domain
    try:
        url = ("http://toolbarqueries.google.com/tbr?client=navclient-auto&ch="
               "%s&features=Rank&q=info:%s") % (google_hash(q), q)
        response = requests.get(url).content
        pr = int(response[response.rindex(':')+1:])
    except:
        pr = -1
    return pr


def google_hash(value):
    magic = 0x01020345
    for i in xrange(len(value)):
        magic ^= ord(GPR_HASH_SEED[i % len(GPR_HASH_SEED)]) ^ ord(value[i])
        magic = magic >> 23 | magic << 9
        magic &= 0xffffffff
    return "8%x" % magic


if __name__ == '__main__':
    pass
