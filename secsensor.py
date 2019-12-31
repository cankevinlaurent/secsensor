# -*- coding: utf-8 -*-

import time
import os
import zipfile
import sqlite3
import CommonDBProcessor
from bs4 import BeautifulSoup

##############################################################################

class Const(object):
    """Used for defining const peremiters"""

    #Determine if file's ready (in second)
    DELAY_TIME = 10

    #Wait to loop
    WAIT_TIME = 60

    #In which folder the reports located, use / for ending
    BASE_DIR = '/home/report/'#'/home/kevin/Downloads/'

    #duration that outdates
    DEADLINE = 99

##############################################################################


class ZipProcessor(object):
    """Prepare given folder and choose the oldest zipfile"""

    def __init__(self, basedir='/home/report/'):
        self.basedir = basedir

    def _clear_basedir_other_than_zips(self):
        """delete all files other than zipfiles"""

        files = os.listdir(self.basedir)
        if files:
            for file in files:
                if os.path.isdir(self.basedir + file):
                    self.file_del(file) #del !EMPTY! dir
                elif file[-4:] != '.zip':
                    self.file_del(file) #not a zipfile

    def _is_file_ready(self, file):
        """size diff means file occupied"""

        size1st = os.path.getsize(self.basedir + file)
        time.sleep(Const.DELAY_TIME)
        size2nd = os.path.getsize(self.basedir + file)
        if size1st == size2nd: return True
        else: return False
        
    def get_oldest_zipfile(self):
        """get the oldest zipfile, return None if not found"""

        self._clear_basedir_other_than_zips()
        files = os.listdir(self.basedir)
        if not files: return None
        files.sort(
            key = lambda file: os.path.getmtime(self.basedir + file) if not os.path.isdir(self.basedir + file) else 99999999999)
        return files[0]

    def get_htmls_from_zip(self, file):
        """get all htmls from a ready zipfile
           index.html is at the first place"""

        while True:
            if self._is_file_ready(file): break
        pzip = None
        try:
            pzip = zipfile.ZipFile(self.basedir + file) #open zipfile
            htmls = []
            for fn in pzip.namelist():
                if '.html' == fn[-5:]:
                    if fn == 'index.html':
                        htmls.insert(0, pzip.read(fn))
                    else:
                        htmls.append(pzip.read(fn))
        except:
            return None
        finally:
            pzip and pzip.close() #close a zipfile
        return htmls

    def file_del(self, file):
        """delete a file or folder by given"""

        if os.path.isdir(self.basedir + file):
            os.rmdir(self.basedir + file) #del folder
        else:
            os.remove(self.basedir + file) #del file

##############################################################################


class HtmlProcessor(object):
    """Prepare htmls to reports"""

    def __init__(self):
        self.timestamp = 0
        self.hosts = []
        self.vulnerbilities = []

    def _generate_vulnerbilities_report(self, html):
        """processing index.html and get timestamp and vulnerbilities"""

        #obtaining timestamp
        document = BeautifulSoup(html, 'html.parser', from_encoding='utf-8')
        for text in document.stripped_strings:
            if u'开始：' in text:
                str_time = text[3:] #get time string
                self.timestamp = int(time.mktime(
                    time.strptime(str_time, "%Y-%m-%d %H:%M:%S")))

        #obtaining vulnerbilities
        as_ = document.find_all('a', class_=['vul-vh', 'vul-vm', 'vul-vl'])
        if as_:
            for a in as_:
                vul_name = a.string.strip()
                vul_level = a['class'][0][-1]
                vul_desc = None
                vul_resolution = None
                vul_releasedate = None
                vul_cve = None
                tag = a.parent
                while True:
                    if tag.name == 'img': tag = tag.parent
                    else: break
                tableTag = tag.parent.next_sibling.next_sibling.table
                if tableTag:
                    for tr in tableTag.find_all('tr'):
                        if tr.td.string == u'详细描述':
                            vul_desc = unicode(str(tr), 'utf-8')
                        elif tr.td.string == u'解决办法':
                            vul_resolution = unicode(str(tr), 'utf-8')
                        elif tr.td.string == u'发现日期':
                            vul_releasedate = tr.td.next_sibling.next_sibling.string
                        elif tr.td.string == u'CVE编号':
                            vul_cve = tr.a.string
                self.vulnerbilities.append((
                    vul_name, vul_level, vul_desc, vul_resolution,
                    vul_releasedate, vul_cve))

    def _generate_host_report(self, html):
        """dealing with hostxxx.html"""

        document = BeautifulSoup(html, 'html.parser', from_encoding='utf-8')

        #set host timestamp
        host = {'timestamp': self.timestamp}

        #set host ports
        host['ports'] = []

        #get ip
        tag = document.find('td', string=u'IP地址')
        if not tag:
            tag = document.find('th', string=u'IP地址')
        host['ip'] = tag.next_sibling.string.strip()

        #get hostname
        tag = document.find('td', string=u'主机名')
        if tag: host['hostname'] = tag.next_sibling.string.strip()

        #get ostype
        tag = document.find('td', string=u'操作系统')
        if tag: host['ostype'] = tag.next_sibling.string.strip()

        #get ports and vulnerbility
        tagDiv = document.find('div', id='portwithvulnlist')
        if not tagDiv: #port not found
            self.hosts.append(host)
            return
        trs = tagDiv.table.find_all('tr')
        if trs:
            #avoid appearing double ICMP segments
            i = 1
            while i < len(trs):
                if u'的漏洞信息' not in trs[i].td.string: break
                else: i += 2
            #get ports
            if i < len(trs): #found ports
                for tr in trs[i:]:
                #<tr class="odd"><td>22</td><td>TCP</td><td>SSH</td><td>
                    #avoid double segments
                    if u'的漏洞信息' in tr.td.string: break 
                    tds = tr.find_all('td')
                    port = {
                        'portid': tds[0].string.strip(),
                        'proto': tds[1].string.strip(),
                        'service': tds[2].string.strip(),
                        'vuls': []}
                    if port.get('service') == '--': port['service'] = None
                    #get vulnerbilities
                    as_ = tds[3].find_all('a')
                    if not as_: #found no vulnerbility
                        host['ports'].append(port)
                        continue
                    for a in as_:
                        class_ = a['class'][0]
                        if 'responseMsg' in class_: continue
                        port['vuls'].append(a.string.strip())
                    host['ports'].append(port)
        self.hosts.append(host)

    def generate_reports(self, htmls):
        """generate reports from inside htmls"""

        self._generate_vulnerbilities_report(htmls[0])

        for html in htmls[1:]: #is hostxxx.html
            self._generate_host_report(html)

    def get_hosts_reports(self):
        """get hosts reports, in tuple style"""

        if not self.hosts: return None
        reports = []
        for host in self.hosts:
            ip =  host.get('ip')
            hostname = host.get('hostname')
            ostype = host.get('ostype')
            portid = None
            proto = None
            service = None
            vulname = None
            timestamp = host.get('timestamp')
            ports = host.get('ports')
            if not ports: #contains no port
                reports.append((
                    None, ip, hostname, ostype, portid, proto, service,
                    vulname, timestamp))
                continue
            for port in ports:
                portid = port.get('portid')
                proto = port.get('proto')
                service = port.get('service')
                vulname = None
                vuls = port.get('vuls')
                if not vuls: #contains no vulnerbility
                    reports.append((
                        None, ip, hostname, ostype, portid, proto, service,
                        vulname, timestamp))
                    continue
                indicate_duplication = ['indicate_duplication']
                for vulname in vuls:
                    if vulname in indicate_duplication: continue
                    else:
                        reports.append((
                            None, ip, hostname, ostype, portid, proto,
                            service, vulname, timestamp))
                        indicate_duplication.append(vulname)
        return reports

    def get_vulnerbilities_reports(self):
        """get vulnerbilities reports"""

        return self.vulnerbilities

##############################################################################


class DBHandler(CommonDBProcessor.CommonDBProcessor):
    """数据库操作"""

    def __init__(self, database):
        super(DBHandler, self).__init__(database)

    def _remove_outdate_hosts(self, days=99):
        """delete records that older than x days, x prefers 99days"""

        if days > 0:
            timestamp = int(time.time())
            outdate_timestamp = timestamp - 86400 * days #-days
            self.cursor.execute(
                "DELETE FROM hosts WHERE timestamp < %d" %(outdate_timestamp))
            self.conn.commit()

    def _remove_hosts_by_ip(self, ip):
        """delete records that contain ip in db"""

        if ip:
            self.cursor.execute("DELETE FROM hosts WHERE ip='%s'" %(ip))
            self.conn.commit()

    def select_query(self, querystr):
        """used for responding select command"""

        if not querystr: return None
        results = self.cursor.execute(querystr)
        return self.cursor.fetchall()

    def writing(self, hosts_reports, vulnerbilities_reports):
        """write hosts and vulnerbilities to database"""

        #remove outdate hosts in db
        self._remove_outdate_hosts(Const.DEADLINE)

        #processing hosts
        if hosts_reports:
            need_writing_reports = []
            need_writing_ips = ['indicator_ip']
            need_skip_ips = ['indicator_ip']
            for record in hosts_reports:
                ip = record[1]
                if not ip: continue
                if ip in need_writing_ips: need_writing_reports.append(record)
                elif ip in need_skip_ips: continue
                else: #ip not in both writing_ips and skip_ips
                    querystr = "SELECT DISTINCT timestamp FROM hosts WHERE ip='%s'" %ip
                    lastchecktimes = self.select_query(querystr)
                    if not lastchecktimes: #means brandnew for db
                        need_writing_ips.append(ip)
                        need_writing_reports.append(record)
                    elif lastchecktimes[0][0] < record[8]: #newer than db
                        self._remove_hosts_by_ip(ip)
                        need_writing_ips.append(ip)
                        need_writing_reports.append(record)
                    else: #lastchecktimes[0][0] >= record.get('timestamp')
                        need_skip_ips.append(ip)

            #writing hosts
            if need_writing_reports:
                self.cursor.executemany(
                    'INSERT INTO hosts VALUES(?,?,?,?,?,?,?,?,?)', need_writing_reports)
                self.conn.commit()

        #writing vulnerbilities
        if vulnerbilities_reports:
            self.cursor.executemany(
                'INSERT OR IGNORE INTO vulnerbilities VALUES(?,?,?,?,?,?)',
                vulnerbilities_reports)
            self.conn.commit()

##############################################################################


def main():

    while True:
        print 'Waiting %ss ...' %(Const.WAIT_TIME)
        time.sleep(Const.WAIT_TIME)
        print 'Start!'

        #----handling zipfile
        print 'Getting htmls ...',
        zipprocessor = ZipProcessor(Const.BASE_DIR)
        file = zipprocessor.get_oldest_zipfile()
        if file:
            htmls = zipprocessor.get_htmls_from_zip(file)
            print 'Done!'
        else:
            print 'Found no zipfile!'
            continue

        #----handling report
        print 'Get records and vulnerbilities ...',
        htmlprocessor = HtmlProcessor()
        htmlprocessor.generate_reports(htmls)
        hosts_reports = htmlprocessor.get_hosts_reports()
        vulnerbilities_reports = htmlprocessor.get_vulnerbilities_reports()
        print 'Done!'

        #----handling record
        print 'Write to db ...',
        DBHandler('secsensor.db').writing(hosts_reports,
            vulnerbilities_reports)
        print 'Done!'

        #----delete handled zipfile
        zipprocessor.file_del(file)

##############################################################################


if __name__ == '__main__':
    main()

