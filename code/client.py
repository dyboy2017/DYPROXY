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