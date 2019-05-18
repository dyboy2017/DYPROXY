# DYPROXY
一个基于socks5的简单代理服务器python3实现


> 信息安全课程的一个作业，让我们实现一个基于Sock5协议的代理服务器，看完整个实验要求，这不就是让我写一个“`VPN`”嘛？

之前的实验都是使用的 `python3`来实现，所以此次还是基于 `Python` 来实现这个简单的“VPN”吧。

[![socks5协议实现VPN](https://upload-images.jianshu.io/upload_images/6661013-9ff842f2c8b9bb40.jpg "socks5协议实现VPN")](https://upload-images.jianshu.io/upload_images/6661013-9ff842f2c8b9bb40.jpg "socks5协议实现VPN")

## 0x00 SOCKS5

> `SOCKS` 是一种网络传输协议，主要用于客户端与外网服务器之间通讯的中间传递。`SOCKS`
 是" `SOCKetS` "的缩写。
>
> 当防火墙后的客户端要访问外部的服务器时，就跟 `SOCKS` 代理服务器连接。这个代理服务器控制客户端访问外网的资格，允许的话，就将客户端的请求发往外部的服务器。这个协议最初由 `David Koblas` 开发，而后由
 `NEC` 的 `Ying-Da Lee` 将其扩展到版本 `4` 。最新协议是版本 `5`，与前一版本相比，增加支持 `UDP`、`验证`，以及 `IPv6`。根据 `OSI` 模型，`SOCKS` 是会话层的协议，位于表示层与传输层之间。

`SOCKS`工作在比`HTTP`代理更低的层次：`SOCKS`使用握手协议来通知代理软件其客户端试图进行的连接`SOCKS`，然后尽可能透明地进行操作，而常规代理可能会解释和重写报头（例如，使用另一种底层协议，例如`FTP`；然而，`HTTP`代理只是将`HTTP`请求转发到所需的`HTTP`服务器）。

虽然`HTTP`代理有不同的使用模式，`CONNECT`方法允许转发`TCP`连接；然而，`SOCKS`代理还可以转发`UDP`流量和反向代理，而`HTTP`代理不能。

`HTTP`代理通常更了解`HTTP`协议，执行更高层次的过滤（虽然通常只用于`GET`和`POST`方法，而不用于`CONNECT`方法）。

***

## 0x01 SOCKS建立连接

`VPN` 就是一个正向代理，反向代理一般用作用户不可直接访问内网，但通过代理服务器访问内网资源的方式，代理服务器就是一个反向代理。

反向代理，对于用户的感知几乎没有，正向代理却需要我们手动设置，比如常见的代理 `IP` 及端口

客户端使用 `SOCKS5` 协议与代理服务器在建立连接，是如下步骤

``` shell
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    一、客户端认证请求
        +----+----------+----------+
        |VER | NMETHODS | METHODS  |
        +----+----------+----------+
        | 1  |    1     |  1~255   |
        +----+----------+----------+
    二、服务端回应认证
        +----+--------+
        |VER | METHOD |
        +----+--------+
        | 1  |   1    |
        +----+--------+
    三、客户端连接请求(连接目的网络)
        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  |   1   |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
    四、服务端回应连接
        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  |   1   |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

*数字代表字节数
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
```

*符号含义，可以参考：[《HTTP协议和SOCKS5协议》](https://www.cnblogs.com/yinzhengjie/p/7357860.html) 一文

在建立连接过程中，要确保每步都是正确完成的，如果错误就要抛出异常。

***

## 0x02 代理服务端代码实现

基于 `ThreadingTCPServer` 创建一个多线程服务，同时自己写一个 `DYProxy`的类，来实现SOCKS5的连接建立和数据传递。

具体代码和步骤都写在注释里啦！

``` python
# -*- coding: utf-8 -*-

import select
import socket
import struct
from socketserver import StreamRequestHandler as Tcp, ThreadingTCPServer

SOCKS_VERSION = 5                           # socks版本

"""
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    一、客户端认证请求
        +----+----------+----------+
        |VER | NMETHODS | METHODS  |
        +----+----------+----------+
        | 1  |    1     |  1~255   |
        +----+----------+----------+
    二、服务端回应认证
        +----+--------+
        |VER | METHOD |
        +----+--------+
        | 1  |   1    |
        +----+--------+
    三、客户端连接请求(连接目的网络)
        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  |   1   |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
    四、服务端回应连接
        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  |   1   |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
"""

class DYProxy(Tcp):
    # 用户认证 用户名/密码
    username = 'dyboy'
    password = '123456'

    def handle(self):
        print("客户端：", self.client_address, " 请求连接！")
        """
        一、客户端认证请求
            +----+----------+----------+
            |VER | NMETHODS | METHODS  |
            +----+----------+----------+
            | 1  |    1     |  1~255   |
            +----+----------+----------+
        """
        # 从客户端读取并解包两个字节的数据
        header = self.connection.recv(2)
        VER, NMETHODS = struct.unpack("!BB", header)
        # 设置socks5协议，METHODS字段的数目大于0
        assert VER == SOCKS_VERSION, 'SOCKS版本错误'

        # 接受支持的方法
        # 无需认证：0x00    用户名密码认证：0x02
        # assert NMETHODS > 0
        methods = self.IsAvailable(NMETHODS)
        # 检查是否支持该方式，不支持则断开连接
        if 0 not in set(methods):
            self.server.close_request(self.request)


        """
        二、服务端回应认证
            +----+--------+
            |VER | METHOD |
            +----+--------+
            | 1  |   1    |
            +----+--------+
        """
        # 发送协商响应数据包 
        self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 0))

        # 校验用户名和密码
        # if not self.VerifyAuth():
        #    return


        """
        三、客户端连接请求(连接目的网络)
            +----+-----+-------+------+----------+----------+
            |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            +----+-----+-------+------+----------+----------+
            | 1  |  1  |   1   |  1   | Variable |    2     |
            +----+-----+-------+------+----------+----------+
        """
        version, cmd, _, address_type = struct.unpack("!BBBB", self.connection.recv(4))
        assert version == SOCKS_VERSION, 'socks版本错误'
        if address_type == 1:       # IPv4
            # 转换IPV4地址字符串（xxx.xxx.xxx.xxx）成为32位打包的二进制格式（长度为4个字节的二进制字符串）
            address = socket.inet_ntoa(self.connection.recv(4))
        elif address_type == 3:     # Domain
            domain_length = ord(self.connection.recv(1)[0])
            address = self.connection.recv(domain_length)
        port = struct.unpack('!H', self.connection.recv(2))[0]

        """
        四、服务端回应连接
            +----+-----+-------+------+----------+----------+
            |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
            +----+-----+-------+------+----------+----------+
            | 1  |  1  |   1   |  1   | Variable |    2     |
            +----+-----+-------+------+----------+----------+
        """
        # 响应，只支持CONNECT请求
        try:
            if cmd == 1:  # CONNECT
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((address, port))
                bind_address = remote.getsockname()
                print('已建立连接：', address, port)
            else:
                self.server.close_request(self.request)
            addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            port = bind_address[1]
            reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, address_type, addr, port)
        except Exception as err:
            print(err)
            # 响应拒绝连接的错误
            reply = self.ReplyFaild(address_type, 5)
        self.connection.sendall(reply)      # 发送回复包

        # 建立连接成功，开始交换数据
        if reply[1] == 0 and cmd == 1:
            self.ExchangeData(self.connection, remote)
        self.server.close_request(self.request)


    def IsAvailable(self, n):
        """ 
        检查是否支持该验证方式 
        """
        methods = []
        for i in range(n):
            methods.append(ord(self.connection.recv(1)))
        return methods


    def VerifyAuth(self):
        """
        校验用户名和密码
        """
        version = ord(self.connection.recv(1))
        assert version == 1
        username_len = ord(self.connection.recv(1))
        username = self.connection.recv(username_len).decode('utf-8')
        password_len = ord(self.connection.recv(1))
        password = self.connection.recv(password_len).decode('utf-8')
        if username == self.username and password == self.password:
            # 验证成功, status = 0
            response = struct.pack("!BB", version, 0)
            self.connection.sendall(response)
            return True
        # 验证失败, status != 0
        response = struct.pack("!BB", version, 0xFF)
        self.connection.sendall(response)
        self.server.close_request(self.request)
        return False


    def ReplyFaild(self, address_type, error_number):
        """ 
        生成连接失败的回复包 
        """
        return struct.pack("!BBBBIH", SOCKS_VERSION, error_number, 0, address_type, 0, 0)


    def ExchangeData(self, client, remote):
        """ 
        交换数据 
        """
        while True:
            # 等待数据
            rs, ws, es = select.select([client, remote], [], [])
            if client in rs:
                data = client.recv(4096)
                if remote.send(data) <= 0:
                    break
            if remote in rs:
                data = remote.recv(4096)
                if client.send(data) <= 0:
                    break


if __name__ == '__main__':
    # 服务器上创建一个TCP多线程服务，监听2019端口
    Server = ThreadingTCPServer(('0.0.0.0', 2019), DYProxy)
    print("**********************************************************")
    print("************************* DYPROXY ************************")
    print("*************************   1.0   ************************")
    print("********************  IP:xxx.xxx.xxx.xxx  ******************")
    print("***********************  PORT:2019  **********************")
    print("**********************************************************")
    Server.serve_forever();

```

这个是服务端，基本不需要改动，这个直接在服务器上跑起来即可，缺什么就安装什么模块。

服务器会监听所有连接到服务器`IP`端口`2019`的`TCP`请求。

这个文件并没有接入用户账号密码认证的，其中给注释了，因为认证方法不一样，涉及的其后返回数据包的方法参数不一样，所以写了两个，大家可以在文末 `Github` 地址参考。

***

### 0x03 如何使用

一个简单的VPN在服务器上跑起来了，我们该怎么使用呐？

由于需要客户端，一个简单使用 `socks` 代理的 `python` 客户端还是比较好测试的

``` python
# -*- coding: utf-8 -*-
# author: DYBOY
# time: 2019-5-18 17:27:49
# desc: 测试使用socks5代理访问

import socket
import socks
import requests

# 设置代理
socks.set_default_proxy(socks.SOCKS5, "服务器IP", 2019)
# 如果使用账号密码验证，那么使用下面这行连接方式
# socks.set_default_proxy(socks.SOCKS5, "服务器IP", 2019,username='dyboy', password='123456')
socket.socket = socks.socksocket

# 测试访问 重庆大学
test_url = 'http://cqu.edu.cn'
html = requests.get(test_url,timeout=8)
html.encoding = 'utf-8'
print(html.text)
```

运行是可以直接访问，在命令行下输出 重庆大学 首页的 `HTML` 源码


[![带登录口令的代理方式](https://upload-images.jianshu.io/upload_images/6661013-c624da32ff280b63.jpg "带登录口令的代理方式")](https://upload-images.jianshu.io/upload_images/6661013-c624da32ff280b63.jpg "带登录口令的代理方式")

但这不应该是我们想要的，我们想看到花花绿绿的东西，对不对？

***

## 0x04 接入浏览器

缺少客户端，`Python` 本身并没有什么可以将 `HTML` 源码渲染的模块，那么就可以借助浏览器。自己可以写一个本地客户端，转发浏览器的流量，似乎过于麻烦，又是一个代理。

借助 火狐浏览器，自带可以设置 代理服务器的功能，即可实现我们的目的，所以没必要去写个客户端，站在巨人肩膀上浏览网页，哈哈~

设置 基于 `SOCKS5` 的代理


[![火狐浏览器代理设置socks5](https://upload-images.jianshu.io/upload_images/6661013-ba705263166f42de.png "火狐浏览器代理设置socks5")](https://upload-images.jianshu.io/upload_images/6661013-ba705263166f42de.png "火狐浏览器代理设置socks5")

开始使用前，服务端的 `server.py` 得先运！（不运行，客户端怎么访问？？？）

设置完成即可以代理服务器的身份浏览网页

测试访问重庆大学（`cqu.edu.cn`）

[![访问重庆大学官网](https://upload-images.jianshu.io/upload_images/6661013-8bdd863b97e1478b.png "访问重庆大学官网")](https://upload-images.jianshu.io/upload_images/6661013-8bdd863b97e1478b.png "访问重庆大学官网")

百度看看，咱的IP是不是代理服务器的IP呐？


[![查看IP情况](https://upload-images.jianshu.io/upload_images/6661013-a65fde36591c0572.png "查看IP情况")](https://upload-images.jianshu.io/upload_images/6661013-a65fde36591c0572.png "查看IP情况")


OK，大功告成！回家吃饭？

似乎...

***

## 0x05 一些思考

虽然小东写的比较简单，其背后还是需要去了解各个模块的使用，当然最主要还是要知道 `SOCKS5` 协议连接过程，以及各参数的大致含义。其中留了一些坑，在口令校验中，浏览器不会自动帮我们输入账号密码，所以需要一个插件`autoproxy`，这个插件内提前设置好，账号密码即可，这样安全性似乎提高了一些。

在比较 `ShadowSocks` 这个软件中，我们发现还有一些加密的方式，进一步提高了安全性，这都是需要改进的，小东负责挖坑，代码上传 `Github`。各位路过的大佬，不妨填一填坑？


[![走开啦，死基佬](https://upload-images.jianshu.io/upload_images/6661013-6da58443ead7506f.gif "走开啦，死基佬")](https://upload-images.jianshu.io/upload_images/6661013-6da58443ead7506f.gif "走开啦，死基佬")

最后，欢迎各位大佬、爱学习的同学关注 小东博客

> 博客：https://blog.dyboy.cn
>
> Github代码托放：https://github.com/dyboy2017/DYPROXY （欢迎 `star`）

