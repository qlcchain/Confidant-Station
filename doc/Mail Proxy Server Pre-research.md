# Mail Proxy Server Pre-research

## 1.mail proxy server的设计目标

app用户选择托管自己的邮箱登陆账号密码到mail proxy server，该server应用在后台长期运行，定期去用户配置邮件服务器查询是否有新邮件，可以配置自动拉取新邮件到server后台加密存储，也可以app用户通过mail proxy server收发邮件。

支持POP3/SMTP/IMAP Gmail邮件。

## 2.协议说明

### POP3

POP3是Post Office Protocol 3的简称，即邮局协议的第3个版本,它规定怎样将个人计算机连接到Internet的邮件服务器和下载电子邮件的电子协议。它是因特网电子邮件的第一个离线协议标准,POP3允许用户从服务器上把邮件存储到本地主机（即自己的计算机）上,同时删除保存在邮件服务器上的邮件，而POP3服务器则是遵循POP3协议的接收邮件服务器，用来接收电子邮件的。

### SMTP

SMTP 的全称是“Simple Mail Transfer Protocol”，即简单邮件传输协议。它是一组用于从源地址到目的地址传输邮件的规范，通过它来控制邮件的中转方式。SMTP 协议属于 TCP/IP 协议簇，它帮助每台计算机在发送或中转信件时找到下一个目的地。SMTP 服务器就是遵循 SMTP 协议的发送邮件服务器。
SMTP 认证，简单地说就是要求必须在提供了账户名和密码之后才可以登录 SMTP 服务器，这就使得那些垃圾邮件的散播者无可乘之机。
增加 SMTP 认证的目的是为了使用户避免受到垃圾邮件的侵扰。

### IMAP

IMAP全称是Internet Mail Access Protocol，即交互式邮件存取协议，它是跟POP3类似邮件访问标准协议之一。不同的是，开启了IMAP后，您在电子邮件客户端收取的邮件仍然保留在服务器上，同时在客户端上的操作都会反馈到服务器上，如：删除邮件，标记已读等，服务器上的邮件也会做相应的动作。所以无论从浏览器登录邮箱或者客户端软件登录邮箱，看到的邮件以及状态都是一致的。

### PoP3与IMAP有什么区别

POP3协议允许电子邮件客户端下载服务器上的邮件，但是在客户端的操作（如移动邮件、标记已读等），不会反馈到服务器上，比如通过客户端收取了邮箱中的3封邮件并移动到其他文件夹，邮箱服务器上的这些邮件是没有同时被移动的 。

而IMAP提供webmail 与电子邮件客户端之间的双向通信，客户端的操作都会反馈到服务器上，对邮件进行的操作，服务器上的邮件也会做相应的动作。

同时，IMAP像POP3那样提供了方便的邮件下载服务，让用户能进行离线阅读。IMAP提供的摘要浏览功能可以让你在阅读完所有的邮件到达时间、主题、发件人、大小等信息后才作出是否下载的决定。此外，IMAP 更好地支持了从多个不同设备中随时访问新邮件。

![IMAP及POP3有什么区别?](http://img4.cache.netease.com/help/2011/1/11/2011011118014265ebf.gif)

### Gmail

Google  的免费网络邮件服务。它随付内置的 Google 搜索技术并提供15G以上的存储空间。可以永久保留重要的邮件、文件和图片，使用搜索快速、轻松地查找任何需要的内容，让这种作为对话的一部分查看邮件的全新方式更加顺理成章。

Gmail虽然也支持传统POP3/IMAP等协议，但是更通用的是其提供了一套REST API接口

https://developers.google.cn/gmail/api/v1/reference

## 3.实现方案

mail-proxy-server分为三部分

### 1.与终端app交互的REST接口。

提供邮件代理基础功能。

邮箱账户配置（代理托管用户邮箱账户，密钥，邮件服务器地址，端口，协议类型等）

邮件基础操作（拉取邮件，发送邮件，删除邮件等）

### 2.邮件代理后台

作为一个常驻server程序后台运行。

根据用户的托管邮箱配置，定期去用户指定邮箱服务器拉取新邮件

根据api接口调用去拉取/发送/删除邮件等操作

这里按照协议类型需要分为两个模块运行，其中常规POP3/SMTP/IMAP协议邮箱，可以采用开源**[inbucket](https://github.com/inbucket/inbucket)**方案

https://github.com/inbucket/inbucket

该项目集成了常用POP3/SMTP/IMAP协议，并且有一个视图管理页面如下

![image-20200619120833067](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20200619120833067.png)

这部分需要整合提供一套配置api接口

另一部分gmail邮箱，需要依据google开放的一套api接口标准封装

gmail api 接口文档

https://developers.google.cn/gmail/api/v1/reference

https://godoc.org/google.golang.org/api/gmail/v1

### 3.与推送后台联动推送新邮件提醒。

在后台检测到用户有新收取的新邮件时，调用推送后台接口，向相关用户发送新邮件提醒推送。

