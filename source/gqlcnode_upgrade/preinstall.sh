#！/bin/sh
gqlcnodepath = /root/gqlcnode/

if [ ! -d "$gqlcnodepath"]; then 
	mkdir -p "$gqlcnodepath"
fi
 
killall gqlc-confidant
