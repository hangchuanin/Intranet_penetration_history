# Intranet_penetration_history
内网渗透学习历程

## 0x00 kerberos协议
kerberos协议官方文档：https://www.ietf.org/rfc/rfc1510.txt
## 0x01 ntlm协议
ntlm协议文档：http://davenport.sourceforge.net/ntlm.html

文档翻译项目：https://rootclay.gitbook.io/ntlm/
## 0x02 管道
管道官方文档：https://learn.microsoft.com/zh-cn/windows/win32/ipc/pipes
## 0x03 smb协议
smb协议文档1：https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-cifs/d416ff7c-c536-406e-a951-4f04b2fd1d2b

smb协议文档2：https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962

smb协议文档3：https://learn.microsoft.com/zh-cn/windows/win32/fileio/microsoft-smb-protocol-and-cifs-protocol-overview

文章：https://xz.aliyun.com/t/11971
## 0x04 windows访问控制
windows访问控制文档：https://learn.microsoft.com/zh-cn/windows/win32/secauthz/access-control-model

文章：https://hangchuanin.github.io/2022/12/23/%E5%86%85%E7%BD%91%E6%B8%97%E9%80%8F%E4%BB%8E%E9%9B%B6%E5%88%B0%E4%B8%80%E4%B9%8BWindows%E8%AE%BF%E9%97%AE%E6%8E%A7%E5%88%B6/
## 0x05 令牌窃取
文章：https://xz.aliyun.com/t/11981

思路：获取计算机上的所有访问令牌，根据需要伪造的用户过滤出对应的访问令牌，把访问令牌的`TokenSessionId`值更改为当前进程令牌的`TokenSessionId`，调用`CreateProcessAsUserA`函数来使用特定令牌执行命令。

注意一：由于更改令牌的TokenSessionId值需要SeTcbPrivilege特权，CreateProcessAsUserA函数的调用需要SE_ASSIGNPRIMARYTOKEN_NAME特权。而NT AUTHORITY\SYSTEM账户拥有这两个特权，所以在更改令牌的TokenSessionId值和调用CreateProcessAsUserA函数之前先调用ImpersonateLoggedOnUser函数模拟NT AUTHORITY\SYSTEM账户，模拟NT AUTHORITY\SYSTEM账户需要先获取到所有者是NT AUTHORITY\SYSTEM账户的访问令牌。

注意二：普通用户无法通过令牌窃取执行命令，原因是普通用户无法获取到System、Administrator等账户的令牌，账户能获取到多少令牌，取决于令牌的安全描述符和完整性级别是否允许账户对令牌的请求。

注意三：需要先对windows访问控制有一定了解再看令牌窃取，可阅读令牌窃取的实现来理解其原理：https://github.com/FSecureLABS/incognito

## 0x06 SPN扫描&kerberoast
SPN官方文档：https://learn.microsoft.com/zh-cn/windows/win32/ad/service-principal-names

文章：https://hangchuanin.github.io/2022/12/25/%E5%86%85%E7%BD%91%E6%B8%97%E9%80%8F%E4%BB%8E%E9%9B%B6%E5%88%B0%E4%B8%80%E4%B9%8BSPN%E6%89%AB%E6%8F%8F&kerberoast/

注意一：SPN扫描是通过LDAP查询活动目录中的域用户对象或计算机对象的servicePrincipalName属性来实现的。

注意二：kerberos协议认证过程中KRB_TGS_REP消息返回的`KRB_TGS_REP::Ticket::EncryptedData`是使用服务账户（域用户或计算机账户，取决于SPN设置在域用户对象还是计算机对象）哈希加密的，通过爆破该字段获取服务账户哈希。

## 0x07 黄金票据
原理：`KRB_AS_REP::Ticket::EncryptedData`是通过域控的krbtgt账户哈希加密的，当我们拥有域控的krbtgt账户哈希时，可以自己制作`KRB_AS_REP::Ticket::EncryptedData`用于后续的身份认证，黄金票据其实指的就是`KRB_AS_REP::Ticket`

注意一：`KRB_AS_REP::Ticket::EncryptedData::EncryptionKey`字段等于`KRB_AS_REP::EncryptedData::EncryptionKey`字段，`KRB_AS_REP::EncryptedData`字段是用客户端哈希进行加密的。在正常的身份认证过程当中客户端使用自己的哈希解密`KRB_AS_REP::EncryptedData`值以获得`KRB_AS_REP::Ticket::EncryptedData::EncryptionKey`值，用于解密后续身份认证过程中产生的`KRB_TGS_REP::EncryptedData`字段，在黄金票据制作中自己伪造一个`EncryptionKey`放进`KRB_AS_REP::Ticket::EncryptedData::EncryptionKey`即可。

注意二：mimikatz工具制作黄金票据需要域SID，这是因为`KRB_AS_REP::Ticket::AuthorizationData`字段是微软设计的PAC，PAC结构里面需要域组SID，而域组SID由域SID+组标识组成，比如域SID+500表示域管组。

## 0x08 白银票据
原理：kerberos协议认证过程中KRB_TGS_REP消息返回的`KRB_TGS_REP::Ticket::EncryptedData`是使用服务账户（域用户或计算机账户，取决于SPN设置在域用户对象还是计算机对象）哈希加密的，当我们拥有服务账户的哈希之后，可以自己制作`KRB_TGS_REP::Ticket::EncryptedData`用于后续的身份认证，白银票据其实指的就是`KRB_TGS_REP::Ticket`。

注意一：白银票据能利用成功的前提是服务不验证PAC，当服务验证PAC时白银票据是无法利用成功的。

## 0x09 MS14068
PAC结构：https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/21181737-74fd-492c-bfbd-0322993a9061

文章：https://daiker.gitbook.io/windows-protocol/kerberos/3#0x00-qian-yan

原理：PAC中的校验和生成如果使用HMAC系列的算法是需要服务账户哈希和krbtgt哈希作为算法的key的，但由于PAC中的服务器校验和与KDC校验和可以使用MD5算法，这就导致没有服务账户哈希和krbtgt账户哈希用户也可以自己制作PAC。

注意一：PAC是放置在`KRB_AS_REP::Ticket::AuthorizationData`字段中的，而`KRB_AS_REP::Ticket`字段是经过krbtgt哈希加密的，我们没有krbtgt哈希，构造出的PAC按理说无法填充到被krbtgt加密的Ticket的AuthorizationData字段中，但是很巧妙可以利用`KRB_TGS_REP`消息的生成的逻辑构造出来。`KRB_TGS_REP::Ticket::EncryptedData`的生成会把`KRB_TGS_REQ::enc-authorization-data`填充进去，`KRB_TGS_REQ::enc-authorization-data`是我们客户端可控的，而`KRB_TGS_REP::Ticket`是用服务账户的哈希进行加密的，所以我们需要把`KRB_TGS_REQ::sname`设置为krbtgt账户，这样我们就可以把构造好的PAC填充到被krbtgt加密的Ticket的AuthorizationData字段中了。

## 0x10 NTDS.DIT && sam
每个域控都存在NTDS.DIT文件，该文件存储着域内所有用户的哈希，而每台计算机又有一个sam文件存储本地计算机所有用户的哈希。
卷影拷贝提取文件：
```
vssadmin create shadow /for=C: #创建卷影
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\NTDS #提取NTDS.dit文件
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\SAM #提取SAM文件
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\SYSTEM #提取SYSTEM文件
vssadmin Delete Shadows /For=C: /quiet #删除卷影
python3 secretsdump.py -ntds NTDS -system SYSTEM LOCAL #提取NTDS.DIT中的哈希
```

## 0x11 NTLM Relay
NTLM Relay攻击能成功的前提是NTLM镶嵌的协议没有开启签名，默认情况下SMB签名只在域控机器上要求，而域内机器不要求。默认情况下LDAP签名通过协商决定，即客户端可控。


## 0x12 MS08-068
在工作组环境中，由于没有域信任这时候拿到NTLM请求去Relay到其它机器并没有作用，除非Relay到的机器密码相同，但是密码相同可以直接PTH了。在工作组环境中可以Relay回机器本身，这就是MS08-068。

## 0x13 CVE-2019-1384
是MS08-068漏洞补丁的一个绕过，补丁是通过缓存进行修补漏洞的，但是缓存在300s之后就会自己清除，利用这个特性可以绕过MS08-068。
