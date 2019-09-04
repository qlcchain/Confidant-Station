#！/bin/sh
#delete last upgrade file
rm -rf /tmp/upgrade/
rm -rf ppr_*.tar.bz2

killall process_monitor.sh pnr_server
#check qlc_update.py
if [ -f /tmp/upgrade/qlc_update.py ];then
	diff /tmp/upgrade/qlc_update.py /root/qlc_update.py >/dev/null
	if  [ $0 != 0 ];then
		cp -f /tmp/upgrade/qlc_update.py /root/qlc_update.py
	fi
fi
