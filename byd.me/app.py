#!/usr/bin/python
#coding=utf-8

from gevent import monkey
monkey.patch_all()

from flask import Flask
from flask import render_template, redirect, request, Response
import json
import config
import utils
from lxml import etree
from lxml.builder import E
import time
import hashlib

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
        raw_info = utils.whois(config.WHOIS_SERVER[tld], domain)
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
    whois_info = utils.whois(config.WHOIS_SERVER[tld], domain)
    return whois_info if whois_info else ''

@app.route('/api/check/<domain>', methods=["GET", "POST"])
def w(domain):
    try:
        tld = domain.split('.')[-1]
        whois_info = utils.whois(config.WHOIS_SERVER[tld], domain)
        if not whois_info:
            return json.dumps({'code':1, 'message':'抱歉，发生了错误，亲'})
        if config.NO_MATCH_INFO[tld] in whois_info:
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

@app.route('/api/weixin', methods=["GET", "POST"])
def weixin():
    if request.method == "POST":
        try:
            xml = etree.XML(request.data)
            info = {}
            for item in xml:
                info[item.tag] = item.text

            to_user= info['FromUserName']
            from_user= info['ToUserName']
            msg_type = info['MsgType']
            func_flag = '0'

            res_xml = etree.Element("xml")
            toUserName = etree.SubElement(res_xml, "ToUserName")
            toUserName.text = etree.CDATA(to_user)
            fromUserName = etree.SubElement(res_xml, "FromUserName")
            fromUserName.text = etree.CDATA(from_user)
            MsgType = etree.SubElement(res_xml, "MsgType")
            MsgType.text = etree.CDATA('text')
            Content = etree.SubElement(res_xml, "Content")
            funcFlag = etree.SubElement(res_xml, "FuncFlag")
            funcFlag.text = etree.CDATA(func_flag)
            createTime = etree.SubElement(res_xml, "CreateTime")

            create_time = str(int(time.time()))
            createTime.text = etree.CDATA(create_time)

            if msg_type == 'text':
                domain = info['Content'].strip()
                content = utils.check(domain)
            elif msg_type == 'event' and info['Event'] == 'subscribe':
                content = u'欢迎使用byd.me域名注册查询，支持多种后缀。请直接输入域名查询，不输入后缀默认查询.com域名。'
            elif msg_type == 'event' and info['Event'] == 'unsubscribe':
                content = u'感谢您使用byd.me域名注册查询，欢迎重新关注。'
            else:
                content = u'亲，请输入要查询的域名'

            Content.text = etree.CDATA(content)
            response = etree.tostring(res_xml, encoding=unicode)
            return Response(response, mimetype='text/xml')

        except Exception, e:
            print request.data, e
            content = u'额，出错了，请检查输入是否正确，汇报bug请发邮件到 solos@solos.so'
            Content.text = etree.CDATA(content)
            response = etree.tostring(res_xml, encoding=unicode)
            return Response(response, mimetype='text/xml')
    else:
        signature = request.args.get('signature','')
        timestamp = request.args.get('timestamp','')
        nonce = request.args.get('nonce','')
        echostr = request.args.get('echostr','')
        hashstr = hashlib.sha1(''.join([signature, timestamp, nonce])).hexdigest()
        if hashstr == echostr:
            return hashstr
        else:
            return ''

if __name__ == '__main__':
    HOST = 'byd.me'
    PORT = 80
    app.debug = True
    app.run(host=HOST, port=PORT)
