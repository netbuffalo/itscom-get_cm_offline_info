#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# version       : 2.0.6
# updated at    : 2022-09-10
# updated by    : shosaka@ossbn.co.jp

############################################
#クラス・スクリプト実行情報
############################################
class ClsExecInfo:
    '''
    '''

    #有効CMTS一覧。CMTSの対象ホストの調整はここで行う。EoCは数が膨大な為、別方法で管理
    cmtses={
        'cbr':(
            'cbr1-aoba', 'cbr2-aoba',
            'cbr1-tama', 'cbr2-tama',
            'cbr1-moto', 'cbr2-moto',
            'cbr1-gaku', 'cbr2-gaku',
            'cbr1-futa', 'cbr2-futa',
            'cbr1-sina', 'cbr2-sina'
            ),
        'pubr':(
            'pubrtudu11',
            'pubraoba01', 'pubraoba02',
            'pubrshib01'
            ),
        'c4':(
            'c4tudu11', 'c4tudu12',
            'c4shib11', 'c4shib12'
            ),
        'pc4':(
            'pc4tama11', 'pc4tama12', 'pc4tama13',
            'pc4moto11', 'pc4moto12', 'pc4moto13',
            'pc4gaku11', 'pc4gaku12', 'pc4gaku13',
            'pc4futa11', 'pc4futa12'
            ),
        'eoc':(
            'eocXXXX-aoba, eocXXXX-tama, eocXXXX-moto, eocXXXX-gaku'
            ),
        'rcmts':(
            'rcmtsXXXX-aoba, rcmtsXXXX-tama, rcmtsXXXX-moto, rcmtsXXXX-gaku'
            )
        }

    #スクリーンの情報を得る為のCMTSとzabbixサーバ対応辞書
    zbxsvs = {
            'c4tudu11':'192.168.220.11', 'c4tudu12':'192.168.220.11',
            'pubrtudu11':'192.168.220.11',
            'cbr1-aoba':'192.168.220.12', 'cbr2-aoba':'192.168.220.12',
            'pubraoba01':'192.168.220.12', 'pubraoba02':'192.168.220.12',
            'cbr1-tama':'192.168.220.13', 'cbr2-tama':'192.168.220.13',
            'pc4tama11':'192.168.220.13', 'pc4tama11':'192.168.220.13', 'pc4tama13':'192.168.220.13',
            'cbr1-moto':'192.168.220.14', 'cbr2-moto':'192.168.220.14',
            'pc4moto11':'192.168.220.14', 'pc4moto12':'192.168.220.14', 'pc4moto13':'192.168.220.14',
            'cbr1-gaku':'192.168.220.15', 'cbr2-gaku':'192.168.220.15',
            'pc4gaku11':'192.168.220.15', 'pc4gaku12':'192.168.220.15', 'pc4gaku13':'192.168.220.15',
            'c4shib11':'192.168.220.16', 'c4shib12':'192.168.220.16',
            'pubrshib01':'192.168.220.16',
            'cbr1-futa':'192.168.220.17', 'cbr2-futa':'192.168.220.17',
            'pc4futa11':'192.168.220.17', 'pc4futa12':'192.168.220.17',
            'cbr1-sina':'192.168.220.18', 'cbr2-sina':'192.168.220.18'
            }

    #コンストラクタ
    def __init__(self, *params):
        if len(params) == 9:
            #引数が8つなら各々割り当てる
            self.host, self.cif, self.us, self.stime, self.etime, self.trigger, self.alert, self.reboot, self.quitproc = params

            #住所情報はNone暫定
            self.addrinfo = None

            #アラート名、トリガー名を指定しているなら分解する
            if not self.alert is None:
                self.host, self.cif, self.us = self.analAlert(self.alert)
            elif not self.trigger is None:
                self.cif, self.us = self.analTrigger(self.trigger)

            #CMTSのタイプをチェックしてモデム情報を抽出するクラスのインスタンスを割り当てる
            self.type = self.getHostType(self.host)
            if self.type in (self.cmtses.keys()):
                self.hostip = ClsSshTools().getHostIpFromHosts(self.host)
                if self.type == 'eoc':
                    self.cminfo = ClsTelnetToolsEoc(self)
                elif self.type == 'rcmts':
                    self.cminfo = ClsTelnetToolsRCMTS(self)
                elif self.type == 'c4' or self.type == 'pc4':
                    self.cminfo = ClsTelnetToolsC4(self)
                elif self.type == 'cbr' or self.type == 'pubr':
                    self.cminfo = ClsTelnetToolsCbrUbr(self)
                else:
                    self.cminfo = ClsTelnetTools(self) #暫定

                #時間編集はこの辺りに
                self.stime = ClsTimeEditTools().editGettingTime(self.stime, -1, 0, 0)
                self.etime = ClsTimeEditTools().editGettingTime(self.etime, 0, 0, 0)

                #CMTSのノード＆スクリーン情報
                if self.host in self.zbxsvs:
                    nodes = self.cminfo.getNodeInfo()
                    self.nodescreen = ClsZabbixApi().getScreenUrl(nodes, self.host, self.zbxsvs)
                elif self.type == 'eoc':
                    self.nodescreen = ClsZabbixApi().getEocLastDataUrl(self.host)
                else:
                    self.nodescreen = ''

                #実行情報表示
                self.showInforms()
            else:
                self.hostip = ''
                self.cminfo = ClsTelnetTools(self)
        else:
            self.host = self.cif = self.us = self.stime = self.etime = self.trigger = self.alert = self.reboot = self.quitproc = None
            self.type = self.hostip = self.nodescreen = self.addrinfo = None

    #ホスト種別
    def getHostType(self, *params):
        #初期化。検索ホストは引数が無いならクラス内のホスト名を使用
        type = None
        if len(params) == 0:
            target = self.host
        else:
            target = params[0]

        #hosts内検索(CMTS)
        for model in self.cmtses:
            if target in self.cmtses[model]:
                type = model
                break

        #ヒットしない場合は、ホスト名の先頭3文字がEoCならhostsファイルからのIP検索を呼び出してチェック
        if type is None and target[:3] == 'eoc':
            if not ClsSshTools().getHostIpFromHosts(target) is None:
                type = 'eoc'

        if type is None and target.startswith('rcmts'):
            if not ClsSshTools().getHostIpFromHosts(target) is None:
                type = 'rcmts'

        #結局見つからない場合は候補を表示
        if type is None:
            print('Warning!! ' + target + ' is undef. chose host')
            for model in self.cmtses:
                print('----- ' + model + ' -----')
                print(str(self.cmtses[model]).replace("'","").replace("(","").replace(")",""))

        #種別を返す
        return type

    #引数解析・アラート
    def analAlert(self, alert):
        host = alert.split('/')[0]
        cif, us = self.analTrigger(alert.replace(host + '/', ''))
        return host, cif, us

    #引数解析・トリガー
    def analTrigger(self, trigger):
        #モジュール定義
        import re

        #パターンチェック
        c4_total = 'Resource_cable-upstream +([0-9]+)_U([0-9]+)\.[0-9]+-([0-9]+)\.[0-9]+_.+'
        c4_normal = 'Resource_cable-upstream +([0-9]+/[0-9]+)\.[0-9]+_.+'
        ubr_cbr_total = 'Resource_Cable([0-9]+/[0-9]+/[0-9]+)-upstream([0-9]+)-([0-9]+)_.+'
        ubr_cbr_normal = 'Resource_Cable([0-9]+/[0-9]+/[0-9]+)-upstream([0-9]+)_.+'

        #パターンに合致したCableIF、USを抽出
        if re.search(c4_total, trigger):
            cif = None
            slot = int(re.search(c4_total, trigger).group(1))
            usbeg = int(re.search(c4_total, trigger).group(2))
            usend = int(re.search(c4_total, trigger).group(3))
            us = ''
            for val in range(usbeg, usend + 1):
                us += str(slot) + '/' + str(val) + ','
            us = us[:-1]
        elif re.search(c4_normal, trigger):
            cif = None
            us = re.search(c4_normal, trigger).group(1)
        elif re.search(ubr_cbr_total, trigger):
            cif = re.search(ubr_cbr_total, trigger).group(1)
            usbeg = int(re.search(ubr_cbr_total, trigger).group(2))
            usend = int(re.search(ubr_cbr_total, trigger).group(3))
            us = ''
            for val in range(usbeg, usend + 1):
                us += str(val) + ','
            us = us[:-1]
        elif re.search(ubr_cbr_normal, trigger):
            cif = re.search(ubr_cbr_normal, trigger).group(1)
            us = re.search(ubr_cbr_normal, trigger).group(2)
        else:
            cif = us = None

        #値を返す
        return cif, us

    #実行情報表示
    def showInforms(self):
        print('**************************************')
        print('Execution Informations')
        print('**************************************')
        print('Host     : %s (%s)' % (self.host, self.hostip))
        print('CableIF  : %s' % self.cif)
        print('upstream : %s' % self.us)
        print('Node     : %s' % self.nodescreen)
        print('StartTime: %s' % self.stime)
        print('EndTime  : %s' % self.etime)
        print('Reboot   : %s' % self.reboot)
        print('Caution  : 応答に時間がかかる場合が有ります')
        print('**************************************')

    #住所情報表示
    def showAddress(self):
        if not len(self.addrinfo) == 0:
            print('\n' + '*'.ljust(30,'*') + '\nResult\n' + '*'.ljust(30,'*') + '\n' + 'Date'.ljust(17) + 'Mac'.ljust(19) + 'Article')
        for modem in sorted(self.addrinfo.keys(), reverse=True):
            print(modem + self.addrinfo[modem])


############################################
#クラス・zabbix api関連
############################################
class ClsZabbixApi:
    '''
    '''

    #コンストラクタ
    def __init__(self):
        pass

    #スクリーンのURLを取得
    def getScreenUrl(self, nodes, cmts, zsvers):
        #モジュール定義
        import simplejson as json

        #APIのURL
        zbxsv = 'http://' + zsvers[cmts] + '/zabbix/api_jsonrpc.php'

        # 認証用json を生成
        jsondata = json.dumps({'jsonrpc':'2.0', 'method':'user.login', 'id':1, 'params':{'user':'Admin', 'password':'zabbix'}})

        # APIの結果を辞書型に変換
        contens_dict = json.loads(self.reqJson(zbxsv, jsondata))

        # 認証トークン取得
        token = contens_dict['result']
        #print '認証トークン：' + str(token)

        #例外処理をいれとく
        screenurl = ''
        try:
            for node in nodes.split(','):
                # 市ヶ尾の場合はノード名調整(先頭のG1を無くす)
                if zsvers[cmts] == '192.168.220.11' and node[:2] == 'G1':
                    nodework =  node[2:] + ' ' #' | '
                else:
                    nodework = node + ' ' #' | '

                # スクリーンID取得(json作成 -> リクエスト -> 情報成形 -> ID取得)
                jsondata = json.dumps({'jsonrpc':'2.0', 'auth':token, 'method':'screen.get', 'id':1, 'params':{'output':['screenid','name'], 'search':{'name':nodework}}})
                contens_dict = json.loads(self.reqJson(zbxsv, jsondata))
                for val in contens_dict['result']:
                    screenid = val['screenid']
                    screenurl += node + '(http://' + zsvers[cmts] + '/zabbix/screens.php?elementid=' + screenid + ')\n           '

            #認証コード破棄
            jsondata = json.dumps({'jsonrpc':'2.0', 'method':'user.logout', 'auth':token, 'id':1, 'params':{}})
            contens_dict = json.loads(self.reqJson(zbxsv, jsondata))
        except:
            print('***** Error *****')
            print('認証トークン：' + str(token))
            #認証コード破棄
            jsondata = json.dumps({'jsonrpc':'2.0', 'method':'user.logout', 'auth':token, 'id':1, 'params':{}})
            print(json.loads(self.reqJson(zbxsv, jsondata)))

        #値を返す
        return screenurl[:len('\n           ') * -1]

    #最新データのURLを取得(EoC)
    def getEocLastDataUrl(self, cmts):
        #モジュール定義
        import simplejson as json

        #APIのURL
        if 'aoba' in cmts:
            zbxsv = 'http://192.168.220.83/zabbix/api_jsonrpc.php'
        elif 'tama' in cmts:
            zbxsv = 'http://192.168.220.24/zabbix/api_jsonrpc.php'
        elif 'moto' in cmts:
            zbxsv = 'http://192.168.220.86/zabbix/api_jsonrpc.php'
        elif 'gaku' in cmts:
            zbxsv = 'http://192.168.220.85/zabbix/api_jsonrpc.php'
        elif 'tsuz' in cmts:
            zbxsv = 'http://192.168.220.87/zabbix/api_jsonrpc.php'
        elif 'dikn' in cmts:
            zbxsv = 'http://192.168.220.82/zabbix/api_jsonrpc.php'
        elif 'nfta' in cmts:
            zbxsv = 'http://192.168.220.84/zabbix/api_jsonrpc.php'
        elif 'sngw' in cmts:
            zbxsv = 'http://192.168.220.90/zabbix/api_jsonrpc.php'
        else:
            pass

        # 認証用json を生成
        jsondata = json.dumps({'jsonrpc':'2.0', 'method':'user.login', 'id':1, 'params':{'user':'Admin', 'password':'zabbix'}})

        # APIの結果を辞書型に変換
        contens_dict = json.loads(self.reqJson(zbxsv, jsondata))

        # 認証トークン取得
        token = contens_dict['result']
        #print '認証トークン：' + str(token)

        #例外処理をいれとく
        lastdataurl = ''
        try:
            # ホストID取得
            jsondata = json.dumps({'jsonrpc':'2.0', 'auth':token, 'method':'host.get', 'id':1, 'params':{'output':['hostid','name'], 'filter':{'host':cmts}}})
            contens_dict = json.loads(self.reqJson(zbxsv, jsondata))
            hostid = contens_dict['result'][0]['hostid']

            # アイテムID取得
            jsondata = json.dumps({'jsonrpc':'2.0', 'auth':token, 'method':'item.get', 'id':1, 'params':{'hostids':hostid, 'output':['itemid','name'], 'filter':{'name':'Resource_CABLE 0/1/0_CM_Active'}}})
            contens_dict = json.loads(self.reqJson(zbxsv, jsondata))
            itemid = contens_dict['result'][0]['itemid']

            #URL
            lastdataurl = 'UNKNOWN(' + zbxsv.replace('api_jsonrpc.php','') + 'history.php?action=showgraph&itemids[]=' + itemid + ')'

            #認証コード破棄
            jsondata = json.dumps({'jsonrpc':'2.0', 'method':'user.logout', 'auth':token, 'id':1, 'params':{}})
            contens_dict = json.loads(self.reqJson(zbxsv, jsondata))
        except:
            print('***** Error *****')
            print('認証トークン：' + str(token))
            #認証コード破棄
            jsondata = json.dumps({'jsonrpc':'2.0', 'method':'user.logout', 'auth':token, 'id':1, 'params':{}})
            print(json.loads(self.reqJson(zbxsv, jsondata)))

        #値を返す
        return lastdataurl

    #json使ってAPIを投げる
    def reqJson(self, zbxsv, jsondata):
        #モジュール定義
        import urllib2

        # リクエストヘッダ
        headers = {'Content-Type':'application/json-rpc'}

        # リクエストを生成
        request = urllib2.Request(zbxsv, jsondata, headers)

        # リクエスト送信
        contents = urllib2.urlopen(request)

        # 結果の中身を読み取り返す
        return contents.read()


############################################
#クラス・SSH関連
############################################
class ClsSshTools:
    '''
    '''

    #コンストラクタ
    def __init__(self):
        self.hostip = None #ホストのIP
        self.addrs = {} #住所情報

    #hostsからIPゲット
    def getHostIpFromHosts(self, host):
        #モジュール定義
        import pexpect, re

        #何らかエラーが出たら一律Noneを返すようにしておく
        try:
            #sshでhosts内検索
            child = pexpect.spawn ('ssh -oStrictHostKeyChecking=no -l op223m01 192.168.254.76')
            child.expect ('password:')
            child.sendline ('ma2take58n')
            child.expect ('][$#] ')
            child.sendline ('grep -w ' + host + ' /etc/hosts')
            child.expect ('][$#] ')
            ret = child.before
            child.sendline ('exit')
            child.close()

            #IP抽出
            self.hostip = re.search('[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', ret).group()
        except:
            pass

        #値を返す
        return self.hostip

    #住所情報の取得
    def getStreetAddressFromMac(self, host, scm, cmts):
        #モジュール定義
        import pexpect

        dsp = {}

        #問い合わせ先設定
        #if 'tudu' in host or 'aoba' in host or 'tama' in host or 'moto' in host:
        #    server = '192.168.220.74'
        #else:
        #    server = '192.168.220.73'
        server = None
        if 'tudu' in host or 'tsuz' in host:
            server = '192.168.220.87'
        elif 'tama' in host:
            server = '192.168.220.24'
        elif 'dikn' in host or 'shib' in host:
            server = '192.168.220.82'
        elif 'aoba' in host:
            server = '192.168.220.83'
        elif 'nfta' in host or 'futa' in host:
            server = '192.168.220.84'
        elif 'gaku' in host:
            server = '192.168.220.85'
        elif 'moto' in host:
            server = '192.168.220.86'
        elif 'sngw' in host or 'sina' in host:
            server = '192.168.220.90'

        if not server:
            return dsp

        #SQLに指定するアドレス
        addrs = ''
        for mac in scm:
            addrs += "'" + mac + "'" + ','

        sql = 'mysql -u mdu MDU -N -s -e "select bukken_address,bukken_name,netmac,emtamac from subscribers where netmac in (' + addrs[:-1] + ') or emtamac in (' + addrs[:-1] + ')' + ';"'

        #SQL実行
        print('zabbix に住所情報を問い合わせています')
        child = pexpect.spawn ('ssh -oStrictHostKeyChecking=no -l op223m01 ' + server)
        child.expect ('password:')
        child.sendline ('ma2take58n')
        child.expect ('][$#] ')
        child.sendline (sql + " | sed 's/\\t/<split>/g'")
        child.readline ()
        child.expect ('][$#] ')
        result =  child.before
        child.sendline ('exit')
        child.close()

        #整形
        dicnet = {}
        dicphone = {}
        print('問い合わせ結果整形中')
        for val in result.split('\r\n'):
            if len(val.split('<split>')) == 4:
                baddr = val.split('<split>')[0]
                bname = val.split('<split>')[1]
                nmac = val.split('<split>')[2]
                pmac = val.split('<split>')[3]

                if not nmac in dicnet:
                    dicnet.update({nmac : ' ... NET     物件：' + bname + '   住所：' + baddr})
                else:
                    pass
                    #print 'MAC重複(NET)：', nmac
                    #print '既存：', dicnet[nmac]
                    #print '重複：', ' ... 物件：' + bname + '   住所：' + baddr

                if not pmac in dicphone:
                    dicphone.update({pmac : ' ... PHONE   物件：' + bname + '   住所：' + baddr})
                else:
                    pass
                    #print 'MAC重複(PHONE)：', pmac
                    #print '既存：', dicphone[pmac]
                    #print '重複：', ' ... 物件：' + bname + '   住所：' + baddr

        #結果
        print('CMTS MACアドレス検索')
        for mac in scm:
            if mac in dicnet:
                dsp[scm[mac]] = dicnet[mac]
            elif mac in dicphone:
                dsp[scm[mac]] = dicphone[mac]
            else:
                dsp[scm[mac]] = ' ... Not Found'

        #情報を返す
        return dsp


############################################
#クラス・TELNET関連
############################################
class ClsTelnetTools:
    '''
    '''

    #コンストラクタ
    def __init__(self, clsparent):
        self.parent = clsparent #親変数を参照する為
        self.scm = {} #show cable modem結果
        self.nodes = '' #CMTSから見えるノード
        self.teltimeout = 180 #タイムアウトを暫定3分とする

    #CMTSからモデム情報取得
    def getModemInfo(self):
        #Telnetツールの親クラスは何もしない
        return self.scm

    #ノード情報取得
    def getNodeInfo(self):
        #Telnetツールの親クラスは何もしない
        return ''


############################################
#子クラス・TELNET関連(EoC)
############################################
class ClsTelnetToolsEoc(ClsTelnetTools):
    '''
    '''

    #CMTSからモデム情報取得
    def getModemInfo(self):
        #モジュール定義
        import pexpect, re

        #何らかエラーが出たら一律Noneを返すようにしておく
        try:
            #scm実行
            results = []
            child = pexpect.spawn ('telnet ' + self.parent.hostip)
            child.expect ('>>User name:')
            child.sendline ('op223m01')
            child.expect ('>>User password:')
            child.sendline ('ma2take58n')
            child.expect ('>')
            child.sendline ('en')
            child.expect ('#')
            child.sendline ('scroll')
            child.expect ('{ <cr>|number<U><10,512> }:')
            child.sendline ('')
            child.expect ('#')
            if self.parent.reboot == True:
                child.sendline ('display cable modem online detail | include MAC Address|Host Interface|Arrival Time')
                child.expect ('#', timeout = self.teltimeout)
                results.append(self._editRebootInfo(child.before)) #再起動情報はオフライン情報に形式を事前に合わせる
            else:
                child.sendline ('display cable modem offline')
                child.expect ('{ <cr>|cpe<K>|sort-index<K>|sort-mac<K>||<K> }:')
                child.sendline ('')
                child.expect ('#', timeout = self.teltimeout)
                results.append(child.before)
            child.sendline ('exit')
            child.expect ('Are you sure to log out\? \(y/n\)\[n\]:')
            child.sendline ('y')
            child.close()

            #情報成形
            pattern = re.compile('[^ ]+ +([a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}) +[^ ]+ +[^ ]+ +[^ ]+ +[^ ]+ +([0-9]{4})-([0-9]{2})-([0-9]{2}) ([0-9]{2}:[0-9]{2}) +[^\r\n]+ +\r\n +(:[0-9]{2})')
            for result in results:
                if pattern.search(result):
                    for val in pattern.findall(result):
                        kmac = val[0].replace('-','').upper()
                        vmac = val[0]

                        ayear = val[1]
                        amonth = val[2]
                        aday = val[3]
                        atimes = val[4] + val[5]
                        aisdiff = None
                        vclock = ClsTimeEditTools().unityFormat(ayear, amonth, aday, atimes, aisdiff)

                        #指定時刻に収まっている情報のみ辞書に入れる
                        if self.parent.stime <= vclock and vclock <= self.parent.etime:
                            self.scm.update({str(kmac):vclock[5:] + '   ' + vmac})
                            #self.scm.update({str(kmac):vclock + '   ' + vmac})
        except pexpect.TIMEOUT:
            print('command timeout. ( setting value is ' + self.teltimeout + ' )')
        #except:
        #    pass

        #結果を返す
        return self.scm

    #再起動情報をオフライン情報の様な表示形式に(強引に)変える
    def _editRebootInfo(self, bufstr):
        #モジュール定義
        import re

        #返す文字列の初期化
        result = ''

        #時間情報の抽出
        workstr =  ''.join(bufstr) \
            .replace('\r\n  Host Interface','  Host Interface') \
            .replace('\r\n  Arrival Time','  Arrival Time')

        #SCM出力結果の抽出、編集
        pattern = re.compile('MAC Address +: +([a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}) +' \
                            'Host Interface +: +([a-zA-Z0-9]+/[a-zA-Z0-9]+/[a-zA-Z0-9]+/[a-zA-Z0-9]+) +' \
                            'Arrival Time +: +([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2})(:[0-9]{2}).*')
        for val in pattern.findall(workstr):
            wmac = val[0]
            wif = val[1]
            wtime = val[2]
            result += 'dmy ' + wmac + ' ' + wif + ' dmy dmy dmy ' + wtime + ' dmy \r\n ' + val[3] + '+09:00\r\n'

        return result


############################################
#子クラス・TELNET関連(R-CMTS)
############################################
class ClsTelnetToolsRCMTS(ClsTelnetTools):
    '''
    '''

    #CMTSからモデム情報取得
    def getModemInfo(self):
        #モジュール定義
        import pexpect, re
        from datetime import datetime,timedelta
        import traceback,time

        max_retries = 3
        cur_retries = 0
        while cur_retries < max_retries:
            #何らかエラーが出たら一律Noneを返すようにしておく
            try:
                #scm実行
                results = []
                child = pexpect.spawn ('telnet ' + self.parent.hostip)
                child.expect('Username:')

                child.sendline('op223m01')
                child.expect('Password:')

                child.sendline('ma2take58n')
                child.expect('>')

                child.sendline('enable')
                child.expect('#')

                child.sendline('terminal length 0')
                child.expect('#')

                if self.parent.reboot == True:
                    child.sendline('show cable modem')
                    child.expect('#')
                    bf = child.before
                    lines = bf.split('\n')
                    ptn = '(\d+)d(\d+)h(\d+)m'
                    for line in lines:
                        # 'ccb6.91c4.2f5a 10.152.177.53 C1/U4 online 1 14.0 1478 1 no 101d22h59m'
                        line = ' '.join(line.split()) # replace multiple whitespace to single whitespace.
                        columns = line.split()
                        if len(columns) == 10 and len(columns[0]) == 14:
                            vmac = columns[0]
                            kmac = vmac.replace('.', '').upper()
                            uptime_string = columns[9]

                            now = datetime.now()
                            result = re.match(ptn, uptime_string)
                            if result:
                                d   = int(result.group(1))
                                h   = int(result.group(2))
                                m   = int(result.group(3))
                                if (d + h + m) > 0: # online?
                                    startup = now - timedelta(days=d, hours=h, minutes=m)
                                    vclock =  startup.strftime('%Y/%m/%d %H:%M:%S')
                                    #指定時刻に収まっている情報のみ辞書に入れる
                                    if self.parent.stime <= vclock and vclock <= self.parent.etime:
                                        self.scm.update({str(kmac):vclock[5:] + '   ' + vmac})
                else:
                    child.sendline('show cable modem offline')
                    child.expect('#')
                    bf = child.before
                    lines = bf.split('\n')
                    for line in lines:
                        line = ' '.join(line.split()) # replace multiple whitespace to single whitespace.
                        columns = line.split()
                        # Interface MAC Address Prim Previous Offline Rx Rx SM
                        # C1/U1 0002.0068.4378 38 p-online Aug 22 18:30:12 14.0 37.6 0
                        if len(columns) == 10 and len(columns[1]) == 14: # target line?
                            vmac    = columns[1]
                            kmac    = vmac.replace('.', '').upper()
                            mon     = columns[4]
                            day     = columns[5]
                            hms     = columns[6]
                            year    = datetime.now().year
                            ctime   = datetime.strptime('%s %s %s' % (mon, day, hms), "%b %d %H:%M:%S").replace(year=year)
                            vclock =  ctime.strftime('%Y/%m/%d %H:%M:%S')
                            #指定時刻に収まっている情報のみ辞書に入れる
                            if self.parent.stime <= vclock and vclock <= self.parent.etime:
                                self.scm.update({str(kmac):vclock[5:] + '   ' + vmac})

                child.close()
                break
            except pexpect.TIMEOUT:
                cur_retries += 1
                print('command timeout. ( setting value is ' + self.teltimeout + ' )')
                break
            except pexpect.exceptions.EOF as eof:
                cur_retries += 1
                if cur_retries == max_retries:
                    traceback.print_exc()
                else:
                    time.sleep(3 * cur_retries)
            except Exception as e:
                cur_retries += 1
                traceback.print_exc()
                break

        #結果を返す
        return self.scm


############################################
#子クラス・TELNET関連(C4)
############################################
class ClsTelnetToolsC4(ClsTelnetTools):
    '''
    '''

    #CMTSからモデム情報取得
    def getModemInfo(self):
        #モジュール定義
        import pexpect, re

        #何らかエラーが出たら一律Noneを返すようにしておく
        try:
            #scm実行
            results = []
            child = pexpect.spawn ('telnet ' + self.parent.hostip)
            child.expect ('Login:')
            child.sendline ('bbsec')
            child.expect ('Password:')
            child.sendline ('testtest')
            child.expect ('#')
            for val in self.parent.us.split(','):
                print('US' + val + ' ...取得中')
                if self.parent.reboot == True:
                    #offlineコマンド側の表示列数と合わせる。欲しいのはuptimeとMAC。uptime複数で列を埋めるが、後々使うかもしれないのでIFも入れて置く
                    child.sendline ('show cable modem cable-upstream ' + val + ' operational column interface uptime uptime uptime uptime uptime cm-mac')
                else:
                    child.sendline ('show cable modem cable-upstream ' + val + ' offline')
                child.expect ('#', timeout = self.teltimeout)
                results.append(child.before)
            child.sendline ('exit')
            child.close()

            #情報成形
            pattern = re.compile('[ ]*[^ ]+ +([0-9]+:[0-9]{2}:[0-9]{2}) +[0-9]+:[0-9]{2}:[0-9]{2} +[^ ]+ +[^ ]+ +[^ ]+ +([a-fA-F0-9]{4}\.[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}).*')
            for result in results:
                if pattern.search(result):
                    ntime = re.compile('(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +([0-9]+) +([0-9]{2}:[0-9]{2}:[0-9]{2})')
                    for val in pattern.findall(result):
                        kmac = val[1].replace('.','').upper()
                        vmac = val[1]

                        ayear = ''
                        amonth = ntime.search(result).group(1)
                        aday = ntime.search(result).group(2)
                        atimes = ntime.search(result).group(3)
                        aisdiff = val[0]
                        vclock = ClsTimeEditTools().unityFormat(ayear, amonth, aday, atimes, aisdiff)

                        #指定時刻に収まっている情報のみ辞書に入れる
                        if self.parent.stime[5:] <= vclock and vclock <= self.parent.etime[5:]:
                            self.scm.update({str(kmac):vclock + '   ' + vmac})
        except pexpect.TIMEOUT:
            print('command timeout. ( setting value is ' + self.teltimeout + ')')
        #except:
        #    pass

        #結果を返す
        return self.scm

    #ノード情報取得
    def getNodeInfo(self):
        #モジュール定義
        import pexpect, re

        #何らかエラーが出たら一律空白を返すようにしておく
        try:
            #scm実行
            results = []
            child = pexpect.spawn ('telnet ' + self.parent.hostip)
            child.expect ('Login:')
            child.sendline ('bbsec')
            child.expect ('Password:')
            child.sendline ('testtest')
            child.expect ('#')
            for val in self.parent.us.split(','):
                child.sendline ("show cable modem summary | include '" + val.replace('/','/U') + " '")
                child.readline ()
                child.expect ('#', timeout = self.teltimeout)
                results.append(child.before)
            child.sendline ('exit')
            child.close()

            #情報成形
            pattern = re.compile('([^ ]+).+% +([^ ]+)')
            for result in results:
                if pattern.search(result):
                    for val in pattern.findall(result):
                        if not val[1] in self.nodes:
                            self.nodes += val[1] + ','
        except pexpect.TIMEOUT:
            print('command timeout. ( setting value is ' +  self.teltimeout + ')')

        #値を返す
        return self.nodes[:-1]


############################################
#子クラス・TELNET関連(cbr/ubr)
############################################
class ClsTelnetToolsCbrUbr(ClsTelnetTools):
    '''
    '''

    #CMTSからモデム情報取得
    def getModemInfo(self):
        #モジュール定義
        import pexpect, re

        #何らかエラーが出たら一律Noneを返すようにしておく
        try:
            #scm実行
            results = []
            child = pexpect.spawn ('telnet ' + self.parent.hostip)
            child.expect ('Password:')
            child.sendline ('iki2kan')
            child.expect ('>')
            child.sendline ('login')
            child.expect ('Username:')
            child.sendline ('bbsec')
            child.expect ('Password:')
            child.sendline ('testtest')
            child.expect ('#')
            child.sendline ('terminal length 0')
            child.expect ('#')
            for val in self.parent.us.split(','):
                print('Cable' + self.parent.cif + ' US' + val + ' ...取得中')
                if self.parent.reboot == True:
                    child.sendline ('show cable modem cabl ' + self.parent.cif + ' upstream ' + val + ' verbose | include Modem Status|Time source is NTP|Total Time|MAC Address|Host Interface')
                    child.expect ('#', timeout = self.teltimeout)
                    results.extend(self._editRebootInfo(child.before).split('\n')) #再起動情報はオフライン情報に形式を事前に合わせる
                else:
                    child.sendline ('show cable modem cabl ' + self.parent.cif + ' upstream ' + val + ' offline')
                    child.expect ('#', timeout = self.teltimeout)
                    results.append(child.before)
            child.sendline ('exit')
            child.close()

            #情報成形
            pattern = re.compile('[^ ]+ +([a-fA-F0-9]{4}\.[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}) +[^ ]+ +[^ ]+ +([^ ]+) +([^ ]+) +([^ ]+) +.*')
            for result in results:
                if pattern.search(result):
                    for val in pattern.findall(result):
                        kmac = val[0].replace('.','').upper()
                        vmac = val[0]

                        ayear = ''
                        amonth = val[1]
                        aday = val[2]
                        atimes = val[3]
                        aisdiff = None
                        vclock = ClsTimeEditTools().unityFormat(ayear, amonth, aday, atimes, aisdiff)

                        #指定時刻に収まっている情報のみ辞書に入れる
                        if self.parent.stime[5:] <= vclock and vclock <= self.parent.etime[5:]:
                            self.scm.update({str(kmac):vclock + '   ' + vmac})
        except pexpect.TIMEOUT:
            print('command timeout. ( setting value is ' + self.teltimeout + ' )')
        #except:
        #    pass

        #結果を返す
        return self.scm

    #再起動情報をオフライン情報の様な表示形式に(強引に)変える
    def _editRebootInfo(self, bufstr):
        #モジュール定義
        import re

        #返す文字列の初期化
        result = ''

        #時間情報の抽出
        workstr =  ''.join(bufstr) \
            .replace('\r\nHost Interface',' Host Interface') \
            .replace('\r\nTotal Time Online',' Total Time Online') \
            .replace('\r\nModem Status',' Modem Status')

        pattern = re.compile('Time source is NTP, ([0-9]{2}:[0-9]{2}:[0-9]{2})\.[0-9]+ JST [^ ]+ ([^ ]+) ([0-9]+) ([0-9]+)')
        ayear = pattern.search(workstr).group(4)
        amonth = pattern.search(workstr).group(2)
        aday = pattern.search(workstr).group(3)
        atimes = pattern.search(workstr).group(1)

        #SCM出力結果の抽出、編集
        pattern = re.compile('MAC Address +: +([a-fA-F0-9]{4}\.[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}) +' \
                            'Host Interface +: +([a-zA-Z0-9]+/[a-zA-Z0-9]+/[a-zA-Z0-9]+/[a-zA-Z0-9]+) +' \
                            'Modem Status +: +\{Modem= +([^ ]*online)?,.+\} +' \
                            'Total Time Online +: +([^ ]+).*') #'Total Time Online +: +(.+) +\(.+\)')
        for val in pattern.findall(workstr):
            wmac = val[0]
            wif = val[1]
            wstatus = val[2]
            wtime = val[3]

            whour = 0
            wmin = 0
            wsec = 0

            if 'd' in wtime:
                whour += int(wtime.split('d')[0]) * 24
                wtime =  wtime.split('d')[1]

            if 'h' in wtime:
                whour += int(wtime.split('h')[0])
                wtime =  wtime.split('h')[1]

            if 'm' in wtime:
                wmin = int(wtime.split('m')[0])
                wtime =  wtime.split('m')[1]

            if ':' in wtime:
                wmin = int(wtime.split(':')[0])
                wsec = int(wtime.split(':')[1])

            wtime = str(whour) + ':' + str(wmin) + ':' + str(wsec)
            wdays = ClsTimeEditTools().unityFormat(ayear, amonth, aday, atimes, wtime)

            wtime = str(whour) + ':' + str(wmin) + ':' + str(wsec)
            wdays = ClsTimeEditTools().unityFormat(ayear, amonth, aday, atimes, wtime)

            result += wif + ' ' + wmac + ' dmy ' + wstatus + ' ' + wdays.split('/')[1] + ' ' + wdays.split(' ')[0].split('/')[2] + ' ' + wdays.split(' ')[1] + ' dmy dmy dmy\n'

        return result

    #ノード情報取得
    def getNodeInfo(self):
        #モジュール定義
        import pexpect, re

        #何らかエラーが出たら一律空白を返すようにしておく
        try:
            #scm実行
            results = []
            child = pexpect.spawn ('telnet ' + self.parent.hostip)
            child.expect ('Password:')
            child.sendline ('iki2kan')
            child.expect ('>')
            child.sendline ('login')
            child.expect ('Username:')
            child.sendline ('bbsec')
            child.expect ('Password:')
            child.sendline ('testtest')
            child.expect ('#')
            child.sendline ('terminal length 0')
            child.expect ('#')
            for val in self.parent.us.split(','):
                child.sendline ('show cable modem summary | include C' + self.parent.cif + '/U' + val)
                child.readline ()
                child.expect ('#', timeout = self.teltimeout)
                results.append(child.before)
            child.sendline ('exit')
            child.close()

            #情報成形
            pattern = re.compile('([^ ]+)[ 0-9]+([a-zA-Z0-9]+)')
            for result in results:
                if pattern.search(result):
                    for val in pattern.findall(result):
                        if not val[1] in self.nodes:
                            self.nodes += val[1] + ','
        except pexpect.TIMEOUT:
            print('command timeout. ( setting value is ' + self.teltimeout + ' )')

        #値を返す
        return self.nodes[:-1]


############################################
#クラス・時間編集関連
############################################
class ClsTimeEditTools:
    '''
    '''

    #コンストラクタ
    def __init__(self):
        pass

    #SCM実行時の抽出時間帯編集
    def editGettingTime(self, sclock, diffh, diffm, diffs):
        #モジュール定義
        import re
        from datetime import datetime , timedelta

        #未指定ならば現在時刻＆引数分調整かける
        if sclock is None:
            tclock = (datetime.now() + timedelta(hours=diffh, minutes=diffm, seconds=diffs)).strftime('%Y/%m/%d %H:%M:%S')
        #YYYY/MM/DD HH:MM:SS or YYYY/MM/DD-HH:MM:SS の書式になっているかチェック
        elif re.match('[1-9][0-9]{3}/[0-9]{2}/[0-9]{2}(-| )[0-9]{2}:[0-9]{2}:[0-9]{2}', sclock) is None:
            #なって無いなら書き換える。その前に元のデータをバックアップ
            wclock = sclock

            #YYYY/MM/DDが存在しないなら、今日を指定
            if re.match('[1-9][0-9]{3}/[0-9]{2}/[0-9]{2}.*', sclock) is None:
                cdays = datetime.now().strftime('%Y/%m/%d')
            else:
                cdays = re.search('([1-9][0-9]{3}/[0-9]{2}/[0-9]{2}).*', sclock).group(1)

            #HH:MM:SSが無いかチェック
            if re.match('.*[0-9]{2}:[0-9]{2}:[0-9]{2}', sclock) is None:
                #HH:MMは一致するかチェック
                if re.match('.*[0-9]{2}:[0-9]{2}', sclock) is None:
                    #一致しないなら0時0分0秒
                    ctime = '00:00:00'
                else:
                    ctime = re.search('.*([0-9]{2}:[0-9]{2})', sclock).group(1) + ':00'
            else:
                ctime = re.search('.*([0-9]{2}:[0-9]{2}:[0-9]{2})', sclock).group(1)

            #年月日と時間を繋げる
            tclock = cdays + ' ' + ctime
        else:
            #合っているならそのまま
            tclock = sclock

        #'-'を取り除いて返す
        return tclock.replace('-',' ')

    #時間書式の統一
    def unityFormat(self, year, month, day, times, isdiff):
        #モジュール定義
        from datetime import datetime, timedelta

        #月の編集
        dict_m = {
            'Jan':'01','Feb':'02','Mar':'03','Apr':'04',
            'May':'05','Jun':'06','Jul':'07','Aug':'08',
            'Sep':'09','Oct':'10','Nov':'11','Dec':'12'
        }

        #月のチェック。辞書のキーか値に一致するかどうか。
        #ここで引っかからない場合は情報なし
        if month in dict_m or month in dict_m.values():
            if month in dict_m:
                work_m = int(dict_m[month])
            else:
                work_m = int(month)

            work_d = int(day)
            work_H = int(times.split(':')[0])
            work_M = int(times.split(':')[1])
            work_S = int(times.split(':')[2])

            #年について(引数が空白か否かでチェック)。月の情報を使う為、このタイミング
            #CMTSから得られる時刻に年の情報が無い。
            #仕方ないので最新の年で固定。現在時刻より未来となる場合は、去年の年を設定。
            if year == '':
                if int(datetime(int(datetime.now().year),work_m,work_d,work_H,work_M,work_S).strftime('%s')) > int(datetime.now().strftime('%s')):
                    work_Y = int(datetime.now().year) - 1
                else:
                    work_Y = int(datetime.now().year)
            else:
                work_Y = int(year)

            #差分計算フラグ(isdiff)に何か値が入っていたら、:で分解して時刻を減算するので、
            #isdiffは、????:??:?? の形で渡す事。Noneの場合は減算無し
            if isdiff is None:
                ctime = datetime(work_Y, work_m, work_d, work_H, work_M, work_S)
            else:
                diff_H = int(isdiff.split(':')[0]) * -1
                diff_M = int(isdiff.split(':')[1]) * -1
                diff_S = int(isdiff.split(':')[2]) * -1
                ctime = datetime(work_Y, work_m, work_d, work_H, work_M, work_S) + timedelta(hours=diff_H, minutes=diff_M, seconds=diff_S)

            #時刻を返す
            if year == '':
                return ctime.strftime('%m/%d %H:%M:%S')
            else:
                return ctime.strftime('%Y/%m/%d %H:%M:%S')
        else:
            return '----/--/-- --:--:--'


############################################
#オプション解析
############################################
def func_get_options():
    #モジュール定義
    from optparse import OptionParser

    #パーサー呼び出し
    parser = OptionParser()

    #オプション追加
    parser.add_option('-H', '--host', action='store', dest='host', type='string', help='ホスト名')
    parser.add_option('-c', '--cableif', action='store', dest='cif', type='string', help='ケーブルIF')
    parser.add_option('-u', '--upstream', action='store', dest='us', type='string', help='US')
    parser.add_option('-S', '--StartTime', action='store', dest='stime', type='string', help='起動時刻(開始)')
    parser.add_option('-E', '--EndTime', action='store', dest='etime', type='string', help='起動時刻(終了)')
    parser.add_option('-T', '--Trigger', action='store', dest='trigger', type='string', help='トリガー名')
    parser.add_option('-A', '--Alert', action='store', dest='alert', type='string', help='アラート名(ホスト/トリガー)')
    parser.add_option('-r', '--Reboot', action='store_true', dest='reboot', help='再起動チェックフラグ')
    parser.add_option('-q', '--quitproc', action='store_true', dest='quitproc', help='処理中断フラグ')

    #追加したオプションに指定している格納先変数のデフォルト値を設定
    parser.set_defaults(
        host=None,
        cif=None,
        us=None,
        stime=None,
        etime=None,
        trigger=None,
        alert=None,
        reboot=False,
        quitproc=False
        )

    #オプション解析
    (options, args) = parser.parse_args()

    #オプションの値を返す(options.<変数>)
    return options.host, options.cif, options.us, options.stime, options.etime, options.trigger, options.alert, options.reboot, options.quitproc


def main():
    ############################################
    #                  メイン
    ############################################
    #コマンドライン引数チェック
    host, cif, us, stime, etime, trigger, alert, reboot, quitproc = func_get_options()

    #ホストが空白の場合は終わり
    if host is None and alert is None:
        print('usage: -H hostname [-c cableinterface] -u upstream [-S [YYYY/MM/DD-]HH:MM[:SS]] [-E [YYYY/MM/DD-]HH:MM[:SS]] [-r|-q|-A|-T]')
        print('ex1: -H cbr1-aoba -c 7/0/0 -u 0,1,2,3 -S 09:56 -E 12:34')
        print('ex2: -H c4tudu11 -u 1/0,1/1,1/2,1/3')
        print('ex3: -H eoc1011-tama')
        print('--------------------------------------------------------------------')
        print('追加オプション')
        print('-r: オフラインの変わりに再起動モデムの物件情報を出力する')
        print('    出力時刻は起動時刻になる')
        print('-q: CMTSへのモデム情報取得及び住所情報検索処理を行わない')
        print('-A: アラート名(ホスト/トリガー)を指定すると')
        print('    -H、-c、-u をスクリプト側で解析し、実行する')
        print('    -Aを使用する場合は、アラート名をクォーテーションで囲む事')
        print('-T: トリガーを指定すると、-c、-u をスクリプト側で解析し、実行する')
        print('    -Tを使用する場合は、アラート名をクォーテーションで囲む事')
        print('--------------------------------------------------------------------')
    else:
        #インスタンス作成
        a = ClsExecInfo(host, cif, us, stime, etime, trigger, alert, reboot, quitproc)

        #表示のみかチェック
        if a.quitproc == True:
            print('-q(--quitproc) オプション確認。処理終了します')
        else:
            #モデム情報取得
            a.cminfo.getModemInfo()

            #情報元に住所情報表示
            if len(a.cminfo.scm) == 0:
                print('------------------------------')
                print('Not Modem Data ... End')
                print('------------------------------')
            else:
                a.addrinfo = ClsSshTools().getStreetAddressFromMac(a.host, a.cminfo.scm, a.type)
                a.showAddress()

if __name__ == '__main__':
    main()
