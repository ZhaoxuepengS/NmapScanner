#-*- coding:utf-8 -*-
__author__ = 'Zhaoxuepeng'

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.header import Header
from logging.handlers import RotatingFileHandler
import nmap
import time
import xlsxwriter as wx
import xlrd
import logging
import sys
import traceback

reload(sys)

sys.setdefaultencoding('utf8')

#logging.basicConfig(filename='nmapScan.log',format='%(asctime)s - %(levelname)s - %(message)s', level=logging.DEBUG)

mylog = logging.getLogger()
point=0
Rthandler = RotatingFileHandler(filename='nampScanTest.log', maxBytes=2*1024*1024,backupCount=2)
mylog.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
Rthandler.setFormatter(formatter)
mylog.addHandler(Rthandler)
#定义扫描的全部网络ip
def getHostList():
    ipList = ['x.x.x.x','x.x.x.x']


    return ipList

#把excel的数据转化为List
def dumpDataToList():
    dataList = []
    data = xlrd.open_workbook('resultTest.xlsx')
    table = data.sheets()[0]
    nrows = table.nrows
    for i in range(nrows ):
        dataList.append(table.row_values(i))
    return dataList

def NmScan(ipList,portRange):

    starttime = time.strftime(u"%Y年%m月%d日 %H:%M:%S".encode('utf-8'))
    nm = nmap.PortScanner()
    workbook = wx.Workbook('resultTest.xlsx')
    worksheet = workbook.add_worksheet()
    centerStyle = workbook.add_format(properties={'align':'center'}) #居中格式
    downStyle = workbook.add_format(properties={'align':'center','font_color':'#FF0000'}) #down机时标红
    upStyle = workbook.add_format(properties={'align':'center','font_color':'#00FF00'}) #up绿色
    worksheet.set_column('A:A', 16)
    worksheet.write(0, 0,'Host',centerStyle)
    worksheet.write(0, 1,'Status',centerStyle)
    worksheet.write(0, 2,'Protocal',centerStyle)
    port_tuple = eval(portRange)
    for i in range(len(port_tuple)):
        worksheet.write(0, 2+i+1,port_tuple[i],centerStyle)

    #行的初始位置
    row = 1
    for ipaddr in ipList:
        nm.scan(ipaddr,portRange)
        worksheet.write(row, 0 ,ipaddr,centerStyle)
        mylog.info('----------------------------------------------------')
        print('----------------------------------------------------')
        if nm.all_hosts() == []:
            print 'connect %s failed.'%ipaddr
            mylog.warn('connect %s failed.'%ipaddr)
            worksheet.write(row, 1 ,'Down',downStyle)
            row = row + 1
            continue
        mylog.info('Host : %s (%s)' % (ipaddr, nm[ipaddr].hostname()))
        mylog.info('State : %s' % nm[ipaddr].state())
        print('Host : %s (%s)' % (ipaddr, nm[ipaddr].hostname()))
        print('State : %s' % nm[ipaddr].state())
        worksheet.write(row, 1 ,'Up',upStyle)
        for proto in nm[ipaddr].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
            worksheet.write(row, 2 ,proto,centerStyle)
            lport = nm[ipaddr][proto].keys()
            lport.sort()
            col = 3
            for port in lport:
                portState = nm[ipaddr][proto][port]['state']
                print ('port : %s\tstate : %s' % (port,portState))
                if portState in ['filtered','closed']:
                    worksheet.write(row, col ,'closed',downStyle)
                elif portState == 'open':
                    worksheet.write(row, col ,'open',upStyle)
                else:
                    worksheet.write(row, col ,portState,centerStyle)

                col = col + 1
        row = row + 1

    endtime = time.strftime(u"%Y年%m月%d日 %H:%M:%S".encode('utf-8'))
    mylog.info('-------------------------------------------')
    mylog.info('Nmap扫描结束')
    workbook.close()

    return starttime,endtime

def comPareList(preList,postList):
    rowNum = len(preList)
    colNum = len(preList[0])
    preStatus = ''
    postStatus = ''
    msg = ''
    for row in range(rowNum):
        for col in range(colNum):
            if type(preList[row][col]) == float:
                preList[row][col] = int(preList[row][col])
            if type(postList[row][col]) == float:
                postList[row][col] = int(postList[row][col])
            if preList[row][col] != postList[row][col]:
                if row == 0:
                    continue
                else:
                    if preList[row][col] == '':
                        preStatus = 'None'
                    else:
                        preStatus = preList[row][col]

                    if postList[row][col] == '':
                        postStatus = 'None'
                    else:
                        postStatus = postList[row][col]

                    print "host:%s"%preList[row][0] + ' port:%s'%preList[0][col] + ' ' + preStatus + ' to ' + postStatus + '\n'
                    msg += "host:%s"%preList[row][0] + ' port:%s'%preList[0][col] + ' ' + preStatus + ' to ' + postStatus + '\n'

    return msg


def sendemail(sender,receiver,subject,smtpserver,smtpuser,smtppass,t1,t2,content):
    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = ";".join(receiver)
    global point
    # 下面是文字部分，也就是纯文本
    puretext = MIMEText('开始时间：%s      结束时间：%s\n'%(t1,t2) + content.encode('utf-8'),_charset='utf-8')
    msg.attach(puretext)
    #puretext = MIMEText('开始时间：%s      结束时间：%s\n'%(t1,t2),_charset='utf-8')
    #msg.attach(puretext)
    #txtpart = MIMEApplication(open('result.txt','rb').read())
    #txtpart.add_header('Content-Disposition', 'attachment', filename='result.txt')
    #msg.attach(txtpart)
    # xlsx类型的附件
    xlsxpart = MIMEApplication(open('resultTest.xlsx', 'rb').read())
    xlsxpart.add_header('Content-Disposition', 'attachment', filename='resultTest.xlsx')
    msg.attach(xlsxpart)

    try:
        #smtp = smtplib.SMTP()
        smtp = smtplib.SMTP_SSL("smtp.qq.com", 465)
        ret = smtp.connect(smtpserver)
        ret = smtp.login(smtpuser, smtppass)
        smtp.sendmail(sender, receiver, msg.as_string())
        smtp.quit()
        mylog.info('发送邮件成功')

    except Exception,e:
        point+=1
        mylog.error('e.message:第%d次异常'%point)
        #mylog.error('e.message')
        mylog.error(traceback.format_exc())
        if(point<3):
            sendemail(sender,receiver,subject,smtpserver,smtpuser,smtppass,t1,t2,content)




if __name__ == '__main__':
    mylog.info('--------------------------------------------------开始扫描-----------------------------------------------------------------')

    #获取已经定义好的IP列表
    hostList = getHostList()
    mylog.info('组合IP列表')
    #确定每个端口的作用
    port_dict = {21:'FTP',22:'SSH',23:'TELNET',53:'DNS',80:'HTTP',110:'POP3',119:'NNTP',\
                 123:'NTP',143:'IMAP2',179:'BGP',135:'loc-srv',136:'profile',137:'netbios-ns',\
                 138:'netbios-dgm',139:'netbios-ssn',443:'HTTPS',445:'microsoft-ds',1433:'SQL Servel',\
                 1521:'oracle',3306:'mysql',3389:'mstsc',5060:'sip',5432:'pgsql',5800:'VNC',5900:'VNC'}

    portRange = '21,22,23,25,53,80,110,119,123,137,138,139,143,179,443,445,1433,1521,3306,3389,5060,5432,5800,5900'

    preDataList = dumpDataToList() #获取前一次扫描的数据
    if preDataList.__len__()!=0:
        mylog.info('读取前一次扫描数据')
    else:
        mylog.warn('读取前一次扫描数据失败')
    mylog.info('启动Nmap扫描。。')
    try:
        t1,t2 = NmScan(hostList,portRange)
    except Exception,e:
        mylog.error('端口扫描失败')
        mylog.error('e.message:')
        mylog.error(traceback.format_exc())
        pass

    postDataList = dumpDataToList() #获取前一次扫描的数据
    if postDataList.__len__()!=0:
        mylog.info('读取本次扫描数据')
    else:
        mylog.warn('读取本次扫描数据失败')
    try:
        content = comPareList(preDataList,postDataList)
        mylog.info('比对数据长度为：')
        mylog.info(content.__len__())
    except Exception,e:
        mylog.error(traceback.format_exc())
        mylog.error('结果数据比对失败：')
    # fobj=open('result.txt','w')
    # fobj.write(content)
    # fobj.close()
    #mylog.info('比对结果content的长度为：'%content.__len__())
    # smtpserver = 'smtp.126.com'
    # smtpUser = 'univiewScan'
    # smtpPasswd = 'zxp2165809'
    #sender = 'UniviewScan@126.com'
    smtpserver = 'smtp.qq.com'
    smtpUser = '1543913085@qq.com'
    smtpPasswd = 'hvlpnzqtkmqrhbbg'
    sender = '1543913085@qq.com'
    receiver = ['zhaoxuepeng@uniview.com','zhaozihua@uniview.com','zhaohui@uniview.com','lijian02681@uniview.com']
    #receiver = ["UniviewScan@126.com","495149700@qq.com",'zhaoxuepeng@uniview.com']
    subject = 'Port scanner\'s mail'
    sendemail(sender, receiver, subject, smtpserver, smtpUser,
             smtpPasswd,t1,t2,content)
