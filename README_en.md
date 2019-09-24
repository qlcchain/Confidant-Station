# Confidant Station

Confidant Station-decentralized privacy management and protection platform Confidant Station communication with app workflow 

![系统架构](files/system.png)s

Confidant product suite includes the Confidant Station and Confidant app, Confidant app serves as the operation interface and the end to communicate to the Confidant station. Confidan user communicates with the Confidant station via the TLS encrypted connection. All the data are transmitted through decentralized p2p connection between Confidant Stations without any decentralized nodes. **This way the whole Confidant network serves as a completely decentralized, private and secure cyber communication tunnel.**

 **Data security**

 **All user data including user account data, chat history, and uploaded files are saved in Confidant stations with encryption. Confidant mobile client also stores some of the data encrypted.  This double encryption mechanism Confidant adopts guarantees the ultimate data security.** 

**The firmware is now supported in X86 hardware and** Building-in Equipments Such as **rasberry pie and Onespace server)**

## **With Confidant,**

## Stay in touch with the ones who matter

One-stop decentralized privacy management and protection platform with a focus on securing digital social relationships.

### **Key Features**

**Blockchain-like Account SystemP2P** 

**Encrypted Messaging & Peer-to-peer File Transfer**

**On-premise Storage & Private Cloud for Emergency Recovery** 

**Encrypted email aggregator**

## **Dependencies** **will support Linux OS**, 
currently Mac or Windows OS is not supported 

#### **Dependencies include**

​	Dewebsockets

​	sqlite3

​	sodium

​	qrencode

​	libpng

#### **Build and Run****

To get the master version** 

git clone https://github.com/confidantstation/Confidant-Station.git 

cd Confidant-Station

##### **Directory**

Confidant-Station 

​	----doc 项目API接口文档目录 

​	----files 项目配套资源文件目录 

​	----pack.sh Onespace设备上打包脚本 

​	----ppr 升级脚本目录 

​	----source 项目代码源目录

##### **Compiler**

​	**X86**
​		cp Makefile_x86 Makefile
​	**makeOnespace**
​		依赖交叉编译环境
​		cp Makefile_onespace Makefile
​	**makeopenwrt**
​		Confidant集成到openwrt/package
​		cp Makefile_openwrt Makefile
​		make package/Confidant/{clean,compile} V=s

##### **Debug Log**

第一次运行起来需要

mkdir /tmp/logdisk

然后可以通过

tail -f /tmp/logdisk/pnrouter_debug.log

查看相应日志

### **Contributions**

Confidant项目配套使用项目，有相关问题可以邮件与开发者联系

### **Links & Resources**