# -*- coding: utf-8 -*-

from flask import Flask
from flask import jsonify
import CommonConfigProcessor
import CommonDBProcessor
import time
import secsensor
from flask import make_response
from flask_httpauth import HTTPBasicAuth

##############################################################################


class DBHandler(secsensor.DBHandler):
    """handle db"""

    def __init__(self, database):
        super(DBHandler, self).__init__(database)

##############################################################################


app = Flask(__name__)

auth = HTTPBasicAuth()

@auth.get_password
def get_password(username):
    if username == confprocessor.get_username():
        return confprocessor.get_password()
    else: return None

@auth.error_handler
def unauthorized():
    return make_response(jsonify({'results': 'Unauthorized access'}), 401)

@app.route('/', methods=['GET'])
def index():
    return u'''<html><head><title>欢迎使用资源和漏洞管理平台</title></head>
               <body><h1>本平台开放以下能力</h1>
               <ul>
               <li>查询能力：get https://x.x.x.x:2018/query</li>
               </ul>
               </body></html>
            '''

@app.route('/query', methods=['GET'])
def query():
    """Used ONLY for searching"""

    return u'''<html><head><title>查询能力</title></head>
               <body><h1>【查询】能力提供以下API</h1>
               <ul>
               <li>全部漏洞介绍：get https://x.x.x.x:2018/query/vuls</li>
               <li>某漏洞介绍：get https://x.x.x.x:2018/query/vuls/[vulname]</li>
               <li>全网活跃资源：get https://x.x.x.x:2018/query/hosts</li>
               <li>某活跃资源：get https://x.x.x.x:2018/query/hosts/[y.y.y.y]</li>
               <li>读取hosts数据表：get https://x.x.x.x:2018/query/hosts/table</li>
               <li>全网活跃端口：get https://x.x.x.x:2018/query/ports</li>
               <li>某活跃端口：get https://x.x.x.x:2018/query/ports/[portid]</li>
               <li>全网IP安全态势：get https://x.x.x.x:2018/query/situations</li>
               <li>某IP安全态势：get https://x.x.x.x:2018/query/situations/[y.y.y.y]</li>
               <li>高危态势：get https://x.x.x.x:2018/query/situations/high</li>
               <li>某安全态势分布：get https://x.x.x.x:2018/query/situations/distribution/[vulname]</li>
               <li>Last100急需更新状态的资产：get https://x.x.x.x:2018/query/last100</li>
               </ul>
               </body></html>
            '''

@app.route('/query/vuls', methods=['GET'])
@auth.login_required
def get_vuls():
    """get vulnerbilities information, include:
       vulnerbility name, level, description, resolution, release date, cve"""

    results = []
    records = DBHandler('secsensor.db').select_query(
        "SELECT DISTINCT * FROM vulnerbilities")
    if records:
        for record in records:
            result = {
                'vulname': record[0], 'level': record[1], 'desc': record[2],
                'resolution': record[3], 'releasedate': record[4],
                'cve': record[5]}
            results.append(result)
    return jsonify({'results': results})

@app.route('/query/vuls/<string:vulname>', methods=['GET'])
@auth.login_required
def get_vulname(vulname):
    """get specific vulnerbility information, include:
       vulnerbility name, level, description, resolution, release date, cve"""

    results = []
    records = DBHandler('secsensor.db').select_query(
        "SELECT DISTINCT * FROM vulnerbilities WHERE vulname='%s'" %(vulname))
    if records:
        for record in records:
            result = {
                'vulname': record[0], 'level': record[1], 'desc': record[2],
                'resolution': record[3], 'releasedate': record[4],
                'cve': record[5]}
            results.append(result)
    return jsonify({'results': results})

@app.route('/query/hosts', methods=['GET'])
@auth.login_required
def get_hosts():
    """get all hosts information, include:
       ip, hostname, ostype, timestamp"""

    results = []
    deadline = int(time.time()) - secsensor.Const.DEADLINE * 86400
    records = DBHandler('secsensor.db').select_query(
        "SELECT DISTINCT ip, hostname, ostype, timestamp FROM hosts WHERE timestamp > %s" %(deadline))
    if records:
        for record in records:
            timestr = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(record[3]))
            result = {
                'ip': record[0], 'hostname': record[1], 'ostype': record[2],
                'lastckeck': timestr}
            results.append(result)
    return jsonify({'results': results})

@app.route('/query/hosts/<string:ip>', methods=['GET'])
@auth.login_required
def get_host(ip):
    """get a host by ip, include:
       ip, hostname, ostype, timestamp"""

    results = []
    deadline = int(time.time()) - secsensor.Const.DEADLINE * 86400
    records = DBHandler('secsensor.db').select_query(
        "SELECT DISTINCT ip, hostname, ostype, timestamp FROM hosts WHERE ip='%s' AND timestamp>%d" %(ip, deadline))
    if records:
        record = records[0]
        timestr = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(record[3]))
        result = {
            'ip': record[0], 'hostname': record[1], 'ostype': record[2],
            'lastckeck': timestr}
        results.append(result)
    return jsonify({'results': results})

@app.route('/query/hosts/table', methods=['GET'])
@auth.login_required
def get_hosts_table():
    """get hosts table in db """

    results = []
    records = DBHandler('secsensor.db').select_query("SELECT * FROM hosts")
    if records:
        for record in records:
            result = {
                'id': record[0], 'ip': record[1], 'hostname': record[2],
                'ostype': record[3], 'portid': record[4], 'proto': record[5],
                'service': record[6], 'vulname': record[7], 'timestamp': record[8]}
            results.append(result)
    return jsonify({'results': results})

@app.route('/query/ports', methods=['GET'])
@auth.login_required
def get_ports():
    """get all ports information, include:
       ip, portid, protocol, service, timestamp"""

    results = []
    deadline = int(time.time()) - secsensor.Const.DEADLINE * 86400
    records = DBHandler('secsensor.db').select_query(
        "SELECT DISTINCT ip, portid, proto, service, timestamp FROM hosts WHERE portid IS NOT NULL AND timestamp > %s" %(deadline))
    if records:
        for record in records:
            timestr = time.strftime(
                '%Y-%m-%d %H:%M:%S', time.localtime(record[4]))
            result = {
                'ip': record[0], 'portid': record[1], 'proto': record[2],
                'service': record[3], 'lastckeck': timestr}
            results.append(result)
    return jsonify({'results': results})

@app.route('/query/ports/<int:portid>', methods=['GET'])
@auth.login_required
def get_port(portid):
    """get port information by portid, include:
       ip, portid, protocol, service, timestamp"""

    results = []
    deadline = int(time.time()) - secsensor.Const.DEADLINE * 86400
    records = DBHandler('secsensor.db').select_query(
        "SELECT DISTINCT ip, portid, proto, service, timestamp FROM hosts WHERE portid=%d AND timestamp > %s" %(portid, deadline))
    if records:
        for record in records:
            timestr = time.strftime(
                '%Y-%m-%d %H:%M:%S', time.localtime(record[4]))
            result = {
                'ip': record[0], 'portid': record[1], 'proto': record[2],
                'service': record[3], 'lastckeck': timestr}
            results.append(result)
    return jsonify({'results': results})

@app.route('/query/situations', methods=['GET'])
@auth.login_required
def get_situations():
    """get all ips information, include:
       ip, portid, protocol, service, vulnerbility name, leve, cve, timestamp
       not include low level vulnerbilities"""

    results = []
    deadline = int(time.time()) - secsensor.Const.DEADLINE * 86400
    records = DBHandler('secsensor.db').select_query(
        "SELECT DISTINCT ip, portid, proto, service, hosts.vulname, vulnerbilities.vulname, level, cve, timestamp FROM hosts,vulnerbilities WHERE hosts.vulname=vulnerbilities.vulname AND timestamp > %s AND level!='l'" %(deadline))
    if records:
        for record in records:
            timestr = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(record[8]))
            result = {
                'ip': record[0],
                'portid': record[1],
                'proto': record[2],
                'service': record[3],
                'vulname': record[4],
                'level': record[6],
                'cve': record[7],
                'lastckeck': timestr}
            results.append(result)
    return jsonify({'results': results})

@app.route('/query/situations/<string:ip>', methods=['GET'])
@auth.login_required
def get_situations_ip(ip):
    """get ip information by ip, include:
       ip, portid, protocol, service, vulnerbility name, leve, cve, timestamp
       not include low level vulnerbilities"""

    results = []
    deadline = int(time.time()) - secsensor.Const.DEADLINE * 86400
    records = DBHandler('secsensor.db').select_query(
        "SELECT DISTINCT ip, portid, proto, service, hosts.vulname, vulnerbilities.vulname, level, cve, timestamp FROM hosts,vulnerbilities WHERE hosts.vulname=vulnerbilities.vulname AND ip='%s' AND timestamp>%s AND level!='l'" %(ip, deadline))
    if records:
        for record in records:
            timestr = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(record[8]))
            result = {
                'ip': record[0],
                'portid': record[1],
                'proto': record[2],
                'service': record[3],
                'vulname': record[4],
                'level': record[6],
                'cve': record[7],
                'lastckeck': timestr}
            results.append(result)
    return jsonify({'results': results})

@app.route('/query/situations/high', methods=['GET'])
@auth.login_required
def get_situations_high():
    """get all high level vulnerbilities, include:
       ip, portid, protocol, service, vulnerbility name, cve, timestamp"""

    results = []
    deadline = int(time.time()) - secsensor.Const.DEADLINE * 86400
    records = DBHandler('secsensor.db').select_query(
        "SELECT DISTINCT ip, portid, proto, service, hosts.vulname, vulnerbilities.vulname, cve, timestamp FROM hosts,vulnerbilities WHERE hosts.vulname=vulnerbilities.vulname AND level='h' AND timestamp>%s" %(deadline))
    if records:
        for record in records:
            timestr = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(record[7]))
            result = {
                'ip': record[0],
                'portid': record[1],
                'proto': record[2],
                'service': record[3],
                'vulname': record[4],
                'cve': record[6],
                'lastckeck': timestr}
            results.append(result)
    return jsonify({'results': results})

@app.route('/query/situations/distribution/<string:vulname>', methods=['GET'])
@auth.login_required
def get_situations_distribution_vulname(vulname):
    """get distribution by vulnerbility name, include:
       ip, portid, protocol, service, vulnerbility name, leve, cve, timestamp
       not include low level vulnerbilities"""

    results = []
    deadline = int(time.time()) - secsensor.Const.DEADLINE * 86400
    records = DBHandler('secsensor.db').select_query(
        "SELECT DISTINCT ip, portid, proto, service, hosts.vulname, vulnerbilities.vulname, level, cve, timestamp FROM hosts,vulnerbilities WHERE hosts.vulname=vulnerbilities.vulname AND hosts.vulname='%s' AND timestamp>%s AND level!='l'" %(vulname, deadline))
    if records:
        for record in records:
            timestr = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(record[8]))
            result = {
                'ip': record[0],
                'portid': record[1],
                'proto': record[2],
                'service': record[3],
                'vulname': record[4],
                'level': record[6],
                'cve': record[7],
                'lastckeck': timestr}
            results.append(result)
    return jsonify({'results': results})

@app.route('/query/last100', methods=['GET'])
@auth.login_required
def get_last100():
    """get last 100 ips whose status need to be updated"""

    results = []
    records = DBHandler('secsensor.db').select_query(
        "SELECT DISTINCT ip, timestamp FROM hosts ORDER BY timestamp ASC LIMIT 100")
    if records:
        for record in records:
            result = {'ip': record[0], 'timestamp': record[1]}
            results.append(result)
    return jsonify({'results': results})

##############################################################################


if __name__ == '__main__':
    confprocessor = CommonConfigProcessor.CommonConfigProcessor(
        'config_secsensor.txt')
    app.run(host='0.0.0.0', port=confprocessor.get_port(), ssl_context='adhoc')

