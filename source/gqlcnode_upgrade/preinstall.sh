#！/bin/sh
gqlcnodepath=/root/gqlcnode/
#delete last upgrade file
rm -rf /tmp/gqlcnode_upgrade/
rm -rf gqlcnode_*.tar.bz2

if [ ! -d $gqlcnodepath ]; then 
	mkdir -p $gqlcnodepath
fi
 
killall gqlc-confidant
#check qlc_update.py
if [ -f /tmp/gqlcnode_upgrade/qlc_update.py ];then
	diff /tmp/gqlcnode_upgrade/qlc_update.py /root/qlc_update.py >/dev/null
	if  [ $0 != 0 ];then
		cp -f /tmp/gqlcnode_upgrade/qlc_update.py /root/qlc_update.py
	fi
fi

#删除原有账本目录
if [ -f /root/nohup.out ];then
	rm -f nohup.out
fi
#if [ -d /sata/home/gqlcnode ];then
#	rm -rf /sata/home/gqlcnode/*
#fi
