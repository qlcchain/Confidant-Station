#！/bin/sh
gqlcnodepath=/root/gqlcnode/

if [ ! -d $gqlcnodepath ]; then 
	mkdir -p $gqlcnodepath
fi
 
killall gqlc-confidant
#check qlc_update.py
diff /tmp/gqlcnode_upgrade/qlc_update.py /root/qlc_update.py >/dev/null
if  [ $0 != 0 ];then
	cp -f /tmp/gqlcnode_upgrade/qlc_update.py /root/qlc_update.py
fi

#删除原有账本目录
rm -f nohup.out
rm -rf /sata/home/gqlcnode/*  
