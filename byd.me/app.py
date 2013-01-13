#!/usr/bin/python
#coding=utf-8

from gevent import monkey
monkey.patch_all()

from flask import Flask
from flask import render_template, url_for, redirect, request
import json
from config import WHOIS_SERVER, TLDS, NO_MATCH_INFO, HOST, PORT
import utils

app = Flask(__name__)

@app.route('/')
@app.route('/index.htm')
@app.route('/index.html')
def index():
    return render_template('index.html')

@app.route('/whois', methods=["GET"])
def whois_get():
    try:
        domain = request.args.get('domain','')
        if domain:
            return redirect('/whois/' + domain)
        else:
            return render_template('whois_query.html', whois_info='', domain='')
    except:
        return render_template('whois_query.html', whois_info='', domain='')
    
@app.route('/whois/<domain>', methods=["GET"])
def whois_query(domain):
    try:
        tld = domain.split('.')[-1]
        raw_info = utils.whois(WHOIS_SERVER[tld], domain)
        whois_info=raw_info.replace('\n', '<br/>').decode('utf-8')
        return render_template('whois.html', whois_info=whois_info, domain=domain)
    except:
        return render_template('whois.html', whois_info='', domain=domain)

@app.route('/whois', methods=["POST"])
def whois_post():
    try:
        domain = request.form['domain']
        return redirect('/whois/' + domain)
    except:
        return render_template('whois.html', whois_info='', domain='')

@app.route('/api/whois/<domain>', methods=["GET", "POST"])
def domain_check(domain):
    try:
        tld = domain.split('.')[-1]
    except:
        return json.dumps({'code':1, 'message':'抱歉，发生了错误，亲'})
    whois_info = utils.whois(WHOIS_SERVER[tld], domain)
    return whois_info if whois_info else ''

@app.route('/api/check/<domain>', methods=["GET", "POST"])
def w(domain):
    try:
        tld = domain.split('.')[-1]
        whois_info = utils.whois(WHOIS_SERVER[tld], domain)
        if not whois_info:
            return json.dumps({'code':1, 'message':'抱歉，发生了错误，亲'})
        if NO_MATCH_INFO[tld] in whois_info:
            return json.dumps({'code':0, 'status': 1, 'message':'恭喜，域名可以注册, 赶紧注册吧，亲'})
        else:
            message = ''.join([domain, u'已经被注册, 换一个吧，亲'])
            return json.dumps({'code':0, 'status': 0, 'message':message})
    except Exception, e:
        print e
        return json.dumps({'code':1, 'message':'抱歉，发生了错误，亲'})

@app.route('/api/weixin', methods=["GET"])
def weixin():
    signature = request.args.get('signature','')
    timestamp = request.args.get('timestamp','')
    nonce = request.args.get('nonce','')
    echostr = request.args.get('echostr','')
    return echostr

if __name__ == '__main__':
    app.debug = True
    app.run(host=HOST, port=PORT)
