#!/usr/bin/python
#coding=utf-8
import commands
import os
import hashlib
import sys
import time
import psutil
from flask import json

upgrade_url = "https://pprouter.online:9001/v1/upgrade/CheckUpgrade"
#upgrade_url = "https://47.244.138.61:9001/v1/upgrade/CheckUpgrade"
updateinfo_url = "https://pprouter.online:9001/v1/upgrade/ModuleRstausUpdate"
#updateinfo_url = "https://47.244.138.61:9001/v1/upgrade/ModuleRstausUpdate"
update_log = "/tmp/qlc_update.log"
update_json = "/tmp/qlc_update.json"
cur_version = "0.1.9"
gqlcnode_enable_cmd = "nohup /root/gqlcnode/gqlc-confidant --configParams=\"rpc.rpcEnabled=true\" --config=/sata/home/gqlcnode/qlc.json >/dev/null 2>&1 &"
gqlcnode_enable_cmd1 = "nohup /root/gqlcnode/gqlc-confidant --configParams=\"rpc.rpcEnabled=true\" --config=/root/gqlcnode/qlc.json >/dev/null 2>&1 &"
gqlcmode_get_cmd = "cat /root/gqlcnode/gqlcflag"
get_disknum_cmd = "cat /tmp/disk.info |grep name |wc -l"
get_freevalumn_cmd = "df -h -m|grep overlayfs| sed 1d|awk '{print $4}'"

def log(type,content):
    try:
        with open(update_log, 'a+') as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S ", time.localtime()))
            
            if type == 1:
                f.write("[SUCCESS]")
            else:
                f.write("[FAIL]")

            f.write(content)
            f.write("\n")
            f.close()
    except Exception, e:
        return

def get_file_content(file):
    try:
        with open(file, 'r') as f:
            ret = f.read()
            f.close()
            return ret
    except Exception, e:
        return

def md5(file):
    md5_value = hashlib.md5()
    with open(file,'rb') as f:
        while True:
            data = f.read(2048)
            if not data:
                break
            md5_value.update(data)
    return md5_value.hexdigest()

def getpidbyprocessname(pname):
    pid = -1
    if pname == "":
        log(2,"bad null pname")
        return pid
    cmd = "ps aux |grep " + pname + " | grep -v grep | awk '{print $2}'"
    #log(1,"get pid cmd(%s)" % cmd)
    try:
        f = os.popen(cmd)
        pid = int(filter(str.isdigit,f.read()))
        f.close()
    except Exception, e:
        return 0
    return pid

def judgeprocess(processname):
    pid = getpidbyprocessname(processname)
    if pid > 0:
        return 1
    else:
        return 0

def freedisk_check():
    diskok=0
    f = os.popen(get_disknum_cmd)
    disknum=int(filter(str.isdigit,f.read()))
    f.close()
    if disknum == 0:
        f2 = os.popen(get_freevalumn_cmd)
        volumn=int(filter(str.isdigit,f2.read()))
        f2.close()
        log(1,"get free capacity(%d)" % volumn)
        if volumn > 800:
            diskok = 1
        else:
            return diskok
    else:
        diskok = 2
    return diskok

def gqlcmode_get():
    if os.access("/root/gqlcnode/gqlcflag", os.F_OK) == True:
        f = os.popen(gqlcmode_get_cmd)
        gqlcmode = int(filter(str.isdigit,f.read()))
        f.close()
    else:
        gqlcmode = -1
    return gqlcmode

def gqlcmode_set(mode):
    if mode != 0 and mode != 1 :
        log(2,"bad mode(%d)",mode)
        return
    setcmd = "echo " + str(mode) + " > /root/gqlcnode/gqlcflag"
    if os.access("/root/gqlcnode/gqlcflag", os.F_OK) == True:
        f = os.popen(gqlcmode_get_cmd)
        gqlcmode = int(filter(str.isdigit,f.read()))
        f.close()
        if gqlcmode != mode:
            os.system("rm -f /root/gqlcnode/gqlcflag")
            os.system(setcmd)
    else:
        os.system(setcmd)
    return 

def gqlcnode_enable(enable):
    #检测程序是否运行
    pid = getpidbyprocessname('gqlc-confidant')
    #检测运行模式
    gqlcmode = gqlcmode_get()
    #使能
    if enable == 1:
        if pid > 0:
            log(1,"gqlcnode already running")
            return
        elif gqlcmode == 0:
            log(1,"gqlcnode switch off")
            return
        #检测是不是有足够的磁盘空间
        diskcheck = freedisk_check()
        #检测目录
        if diskcheck == 2:
            if os.access("/sata/home/gqlcnode/", os.F_OK) != True:
                os.system("mkdir -p /sata/home/gqlcnode/")
            #使能
            os.system(gqlcnode_enable_cmd)
            log(1,"enable gqlcnode ok")
        elif diskcheck == 1:
             #使能
            os.system(gqlcnode_enable_cmd1)
            log(1,"enable gqlcnode1 ok")
        else:
            log(2,"enable gqlcnode failed: no disk")

    #关闭
    elif enable == 0:
        if pid <= 0:
            return
        gqlcnode_disalbe_cmd = "kill -9 " + str(pid)
        os.system(gqlcnode_disalbe_cmd)
        log(1,"disable gqlcnode cmd(%s)" % gqlcnode_disalbe_cmd)
        return
    else:
        log(2,"bad enable flag(%d)" % enable)

def gqlc_capacity_get(disktype):
    if disktype == 2:
        if os.access("/sata/home/gqlcnode/", os.F_OK):
            f = os.popen("du -h -s -m /sata/home/gqlcnode/")
            capacity = int(filter(str.isdigit,f.read()))
            f.close()
        else:
            os.system("mkdir -p /sata/home/gqlcnode/")
            capacity=0    
    elif disktype == 1:
        f = os.popen("du -h -s -m /root/gqlcnode/")
        capacity = int(filter(str.isdigit,f.read()))
        f.close()
    else:
        capacity=0
    return capacity

def gqlc_status_check():
    rstatus = -1
    count = 0
    unchecked = 0

    #检测程序是否运行
    rstatus = judgeprocess("gqlc-confidant")
    gqlcmode = gqlcmode_get()
    diskcheck = freedisk_check()
    if rstatus == 0:
        if diskcheck > 0:
            if gqlcmode == 1:
                gqlcnode_enable(1)
                rstatus = 1
            else:
                rstatus = 3
        else:
            rstatus = 2 #这里是没有足够的磁盘空间
    #log(1,"get running status(%d)" % rstatus)
    if rstatus == 1:
        f2 = os.popen("curl --request POST --url http://127.0.0.1:9735/ -s --header 'content-type: application/json'   --data '{\"jsonrpc\": \"2.0\",\"id\": 3,\"method\": \"ledger_blocksCount\", \"params\": []}'")
        result = f2.read()
        f2.close()
        #log(1,"get post result(%s)" % result)
        #print result

        try:
            jret = json.loads(result)
        except Exception, e:
            log(2,"gqlc_status_checkload json err(%s)" % result)
            rstatus = 2
            return rstatus,count,unchecked
        if not jret:
            log(2,"parse json err(%s)" % result)
            rstatus = 2
            return rstatus,count,unchecked
        if "result" not in jret:
            log(2,"no result found")
            rstatus = 2
            return rstatus,count,unchecked
        count = jret["result"]["count"]
        unchecked = jret["result"]["unchecked"]
    return rstatus,count,unchecked

def get_sysmac():
    f = os.popen("cat /sys/class/net/eth0/address")
    mac = f.read()
    f.close()
    mac = mac.upper()
    mac =''.join(mac.split(':'))
    return mac.strip()

def running_status_update(module):
    if module==3:
        diskcheck = freedisk_check()
        status,count,unchecked = gqlc_status_check()
        capacity = gqlc_capacity_get(diskcheck)
        mac = get_sysmac()
        post = "dev=2\&status=" + str(status) + "\&module=" + str(module)  + "\&count=" + str(count) + "\&unchecked=" + str(unchecked) + "\&capacity=" + str(capacity) + "\&mac=" + mac       
    else:
        log(2,"running_status_update:bad module(%s)" % module)
        return
    posturl="wget "+updateinfo_url+"?"+post+" -q -O "+update_json+" --no-check-certificate"
    os.system(posturl)
    result = get_file_content(update_json)
    log(1,"get post(%s) result(%s)" % (posturl,result))
    try:
        jret = json.loads(result)
    except Exception, e:
        log(2,"load json err1(%s)" % result)
        return

    if not jret:
        log(2,"parse json err2(%s)" % result)
        return

    if "Ret" not in jret:
        log(2,"no Ret found")
        return

    if jret["Ret"] != 0:
        if "Info" in jret:
            log(2,jret["Info"])
        return
    gqclmode = gqlcmode_get()
    newmode = jret["GqlcMode"]
    if newmode ==0 or newmode ==1:
        if newmode != gqclmode:
            gqlcmode_set(newmode)
            gqlcnode_enable(newmode)
    return

def upgrade_module(module):
    mac = get_sysmac()
    if module == 1:
        last_upgradepkg = "/tmp/ppr_*.tar.bz2"
        upgrade_path = "/tmp/upgrade" 
        ver = commands.getoutput("pnr_server --version|grep version|awk -F':' '{print $2}'")
        post = "dev=2\&module=1\&version=" + ver +"\&mac="+mac
    elif module ==3:
        last_upgradepkg = "/tmp/gqlcnode_*.tar.bz2"
        upgrade_path = "/tmp/gqlcnode_upgrade" 
        if os.access("/root/gqlcnode/gqlc-confidant", os.F_OK):
            f = os.popen("/root/gqlcnode/gqlc-confidant version|grep version|awk -F':' '{print $2}'")
            ver = f.read()
            f.close()
            ver  = ver.strip()
        else:
            log(2,"gqlcnode not exsit")
            ver = "0.0.0"
        post = "dev=2\&module=3\&version=" + ver+"\&mac="+mac
    else:
        log(2,"load module type(%d)" % module)
        return 

    #print("wget %s?%s -O %s --no-check-certificate" % (upgrade_url, post, update_json))
    upgrade_request = "wget "+upgrade_url+"?"+post+" -q -O "+update_json+" --no-check-certificate"
    os.system(upgrade_request)
    #os.system("wget %s?%s -q -O %s --no-check-certificate" % (upgrade_url, post, update_json))
    result = get_file_content(update_json)
    log(1,"upgrade_module(%d %s)" %(module,upgrade_request))
    #print result

    try:
        jret = json.loads(result)
    except Exception, e:
        log(2,"upgrade load json err(%s)" % result)
        return

    if not jret:
        log(2,"parse json err" + result)
        return

    if "Ret" not in jret:
        log(2,"no Ret found")
        return

    if jret["Ret"] != 0:
        if "Info" in jret:
            log(2,jret["Info"])
        return

    if "NeedUpgrade" not in jret:
        log(2,"no NeedUpgrade found")
        return

    if jret["NeedUpgrade"] == 0:
        log(2,"no need to upgrade")
        return

    if "FileUrl" not in jret:
        log(2,"no fileurl")
        return

    if "FileMd5" not in jret:
        log(2,"no filemd5")
        return

    if "FileName" not in jret:
        log(2,"no filename")
        return
    
    if "NewVersion" not in jret:
        log(2,"no newversion")
        return

    os.system("cd /tmp/;rm -fr %s %s" % (last_upgradepkg,upgrade_path))
    os.system("cd /tmp/;wget %s -q --no-check-certificate" % jret["FileUrl"])
    
    if not os.path.exists("/tmp/" + jret["FileName"]):
        log(2,"download pkg %s err" % jret["FileName"])
        return

    if cmp(md5("/tmp/" + jret["FileName"]), jret["FileMd5"]) == 0:
        os.system("cd /tmp/;tar -xf " + jret["FileName"])
        if os.path.exists("%s/preinstall.sh" %(upgrade_path)):
            os.system("chmod a+x %s/preinstall.sh" %(upgrade_path))
            os.system("%s/preinstall.sh" %(upgrade_path))
        else:
            log(2,"there is no preinstall script")
            return            
        if os.path.exists("%s/install.sh" %(upgrade_path)):
            os.system("chmod a+x %s/install.sh" %(upgrade_path))
            os.system("%s/install.sh" %(upgrade_path))
        else:
            log(2,"there is no install script")
            return            
        if os.path.exists("%s/postinstall.sh" %(upgrade_path)):
            os.system("chmod a+x %s/postinstall.sh" %(upgrade_path))
            os.system("%s/postinstall.sh" %(upgrade_path))
        else:
            log(2,"there is no postinstall script")
            return                       
        log(1,"upgrade to %s success" % jret["NewVersion"])
    else:
        log(2,"md5 not match %s" % jret["FileMd5"])
    return

if len(sys.argv) > 1:
    if cmp(sys.argv[1], "ppr") == 0:
        os.system("mount -o remount,rw /")
        upgrade_module(1)          #ppr upgrade
        upgrade_module(3)          #gqlc upgrade
        running_status_update(3)        #gqlc status upload
        os.system("mount -o remount,ro /")
    elif cmp(sys.argv[1], "gqlc") == 0:
        #log(1,"gqlc upgrade")
        os.system("mount -o remount,rw /")
        upgrade_module(3)          #gqlc upgrade
        os.system("mount -o remount,ro /")
    elif cmp(sys.argv[1], "update_gqlcinfo") == 0:
        #log(1,"gqlc update info")
        running_status_update(3)
    elif cmp(sys.argv[1], "gqlc_enable") == 0:
        gqlcnode_enable(1)
    elif cmp(sys.argv[1], "gqlc_disable") == 0:
        gqlcnode_enable(0)
    elif cmp(sys.argv[1],"ver") == 0:
        print "version:"+cur_version
else:
    print "invalid params"



