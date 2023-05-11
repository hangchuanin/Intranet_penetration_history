

学习的一份记录

占坑

涉及比较多的文档内容，一开始看比较抽象并且抓不住重点，可以先搜索引擎上搜索一下文章看一看有什么内容，哪些是重点，了解一些基础知识，再去看官方文档。



* [0x00 kerberos协议](#0x00-kerberos协议)
* [0x01 ntlm协议](#0x01-ntlm协议)
* [0x02 看两个项目](#0x02-看两个项目)
* [0x03 管道](#0x03-管道)
* [0x04 smb协议](#0x04-smb协议)
* [0x05 windows访问控制](#0x05-windows访问控制)
* [0x06 令牌窃取](#0x06-令牌窃取)
* [0x07 SPN扫描&amp;kerberoast](#0x07-spn扫描kerberoast)
* [0x08 黄金票据](#0x08-黄金票据)
* [0x09 白银票据](#0x09-白银票据)
* [0x10 MS14068](#0x10-ms14068)
* [0x11 RPC 协议](#0x11-rpc-协议)
* [0x12 DCOM 协议](#0x12-dcom-协议)
* [0x13 各类 potato 提权原理](#0x13-各类-potato-提权原理)
* [0x14 WinRM 协议](#0x14-winrm-协议)
* [0x15 WMI 协议](#0x15-wmi-协议)
* [0x16 Zerologon](#0x16-zerologon)
* [0x17 sAMAccountName spoofing](#0x17-samaccountname-spoofing)
* [0x18 CVE-2022-26923](#0x18-cve-2022-26923)
* [0x19 bypassUAC](#0x19-bypassuac)
* [0x20 各类exec原理](#0x20-各类exec原理)
* [0x21 bypassApplocker](#0x21-bypassapplocker)
* [0x22 看一些MicroSoft kerberos协议的文档](#0x22-看一些MicroSoft kerberos协议的文档)
* [0x23 非约束委派](#0x23-非约束委派)
* [0x24 约束委派](#0x24-约束委派)
* [0x25 基于资源的约束委派](#0x25-基于资源的约束委派)
* [0x26 ](#0x26)



# 0x00 kerberos协议

kerberos协议官方文档：https://www.ietf.org/rfc/rfc1510.txt

通过伪协议部分（A. Pseudo-code for protocol processing）理解整个认证过程

MicroSoft 对 kerberos 的扩展 S4U2：https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94

# 0x01 ntlm协议

ntlm协议文档：http://davenport.sourceforge.net/ntlm.html

文档翻译项目：https://rootclay.gitbook.io/ntlm/

比较好理解，文档有大量的例子

# 0x02 看两个项目

仔细看：https://github.com/daikerSec/windows_protocol

当一个字典目录：https://github.com/Ridter/Intranet_Penetration_Tips

# 0x03 管道

管道官方文档：https://learn.microsoft.com/zh-cn/windows/win32/ipc/pipes

# 0x04 smb协议

smb协议文档1：https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-cifs/d416ff7c-c536-406e-a951-4f04b2fd1d2b

smb协议文档2：https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962

smb协议文档3：https://learn.microsoft.com/zh-cn/windows/win32/fileio/microsoft-smb-protocol-and-cifs-protocol-overview

文章：https://xz.aliyun.com/t/11971

# 0x05 windows访问控制

windows访问控制文档：https://learn.microsoft.com/zh-cn/windows/win32/secauthz/access-control-model

# 0x06 令牌窃取

文章：https://xz.aliyun.com/t/11981

窃取到令牌后的利用：https://github.com/hatRiot/token-priv

最常使用的是 SeImpersonatePrivilege、SeAssignPrimaryPrivilege 这两个特权

# 0x07 SPN扫描&kerberoast

SPN官方文档：https://learn.microsoft.com/zh-cn/windows/win32/ad/service-principal-names

文章：https://hangchuanin.github.io/2022/12/25/%E5%86%85%E7%BD%91%E6%B8%97%E9%80%8F%E4%BB%8E%E9%9B%B6%E5%88%B0%E4%B8%80%E4%B9%8BSPN%E6%89%AB%E6%8F%8F&kerberoast/

（1）SPN扫描是通过LDAP查询活动目录中的域用户对象或计算机对象的servicePrincipalName属性来实现的。

（2）kerberos协议认证过程中KRB_TGS_REP消息返回的`KRB_TGS_REP::Ticket::EncryptedData`结构是使用服务账户（域用户或计算机账户，取决于SPN设置在域用户对象还是计算机对象）哈希加密的，通过爆破该字段获取服务账户哈希。

# 0x08 黄金票据

原理：`KRB_AS_REP::Ticket::EncryptedData`是通过域控的krbtgt账户哈希加密的，当我们拥有域控的krbtgt账户哈希时，可以自己制作`KRB_AS_REP::Ticket::EncryptedData`用于后续的身份认证，黄金票据其实指的就是`KRB_AS_REP::Ticket`

注意一：`KRB_AS_REP::Ticket::EncryptedData::EncryptionKey`字段等于`KRB_AS_REP::EncryptedData::EncryptionKey`字段，`KRB_AS_REP::EncryptedData`字段是用客户端哈希进行加密的。在正常的身份认证过程当中客户端使用自己的哈希解密`KRB_AS_REP::EncryptedData`值以获得`KRB_AS_REP::Ticket::EncryptedData::EncryptionKey`值，用于解密后续身份认证过程中产生的`KRB_TGS_REP::EncryptedData`字段，在黄金票据制作中自己伪造一个`EncryptionKey`放进`KRB_AS_REP::Ticket::EncryptedData::EncryptionKey`即可。

注意二：mimikatz工具制作黄金票据需要域SID，这是因为`KRB_AS_REP::Ticket::AuthorizationData`字段是微软设计的PAC，PAC结构里面需要域组SID，而域组SID由域SID+组标识组成，比如域SID+500表示域管组。

# 0x09 白银票据

原理：kerberos协议认证过程中KRB_TGS_REP消息返回的`KRB_TGS_REP::Ticket::EncryptedData`是使用服务账户（域用户或计算机账户，取决于SPN设置在域用户对象还是计算机对象）哈希加密的，当我们拥有服务账户的哈希之后，可以自己制作`KRB_TGS_REP::Ticket::EncryptedData`用于后续的身份认证，白银票据其实指的就是`KRB_TGS_REP::Ticket`。

注意一：白银票据能利用成功的前提是服务不验证PAC，当服务验证PAC时白银票据是无法利用成功的。

# 0x10 MS14068

PAC结构：https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/21181737-74fd-492c-bfbd-0322993a9061

文章：https://daiker.gitbook.io/windows-protocol/kerberos/3#0x00-qian-yan

原理：PAC中的校验和生成如果使用HMAC系列的算法是需要服务账户哈希和krbtgt哈希作为算法的key的，但由于PAC中的服务器校验和与KDC校验和可以使用MD5算法，这就导致没有服务账户哈希和krbtgt账户哈希用户也可以自己制作PAC。

注意一：PAC是放置在`KRB_AS_REP::Ticket::AuthorizationData`字段中的，而`KRB_AS_REP::Ticket`字段是经过krbtgt哈希加密的，我们没有krbtgt哈希，构造出的PAC按理说无法填充到被krbtgt加密的Ticket的AuthorizationData字段中，但是很巧妙可以利用`KRB_TGS_REP`消息的生成的逻辑构造出来。`KRB_TGS_REP::Ticket::EncryptedData`的生成会把`KRB_TGS_REQ::enc-authorization-data`填充进去，`KRB_TGS_REQ::enc-authorization-data`是我们客户端可控的，而`KRB_TGS_REP::Ticket`是用服务账户的哈希进行加密的，所以我们需要把`KRB_TGS_REQ::sname`设置为krbtgt账户，这样我们就可以把构造好的PAC填充到被krbtgt加密的Ticket的AuthorizationData字段中了。

# 0x11 RPC 协议

（1）RPC 编程文档：https://learn.microsoft.com/zh-cn/windows/win32/rpc/rpc-start-page

（2）RPC 协议文档：https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/290c38b1-92fe-4229-91e6-4fc376610c15?redirectedfrom=MSDN

# 0x12 DCOM 协议

（1）COM 使用：https://github.com/gh0stkey/Binary-Learning/blob/master/DiShui/0-Beginner/8-COM%E7%BB%84%E4%BB%B6.pdf

（2）DCOM 协议：https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/4a893f3d-bd29-48cd-9f43-d9777a4415b0

# 0x13 各类 potato 提权原理

https://jlajara.gitlab.io/Potatoes_Windows_Privesc

# 0x14 WinRM 协议

（1）WinRM 协议文档：https://learn.microsoft.com/zh-cn/windows/win32/winrm/portal

# 0x15 WMI 协议

（1）WMI 协议文档：https://learn.microsoft.com/zh-cn/windows/win32/wmisdk/wmi-start-page

# 0x16 Zerologon

（1）[概念验证](https://github.com/dirkjanm/CVE-2020-1472)

（2）Zerologon 漏洞原理

   Netlogon 协议是一种 RPC 接口，Netlogon 协议提供的方法有两类，一类是需要经过 Netlogon 协议身份认证过后才可调用的方法，一类是不需要经过 Netlogon 协议身份认证即可调用的方法。而 Netlogon 协议身份认证可以根据协商标志选择身份认证过程中计算凭证时使用的算法，而其中的算法之一  AES_CFB8 存在缺陷，结合 Netlogon 协议的认证过程可以绕过 Netlogon 协议的身份认证，导致可以在没有凭据的情况下调用 Netlogon 协议的所有方法。

（3）攻击路径

1. 利用 AES_CFB8 算法缺陷绕过 Netlogon 协议的身份认证
2. 身份认证后调用 Netlogon 协议的 `NetrServerPasswordSet2` 方法重置域控机器账户的密码为空
3. 使用空密码进行 Dcsync
4. 恢复域控的密码防止域控脱离域

（4）注意到的细节

1. 在完成 Netlogon 协议的身份认证之后，调用 `NetrServerPasswordSet2` 方法需要传递 `Authenticator` 参数， `Authenticator` 参数在服务器即域控还会进行一个验证，这个验证也是通过 AES_CFB8 缺陷进行绕过。
2. 调用 `NetrServerPasswordSet2` 方法需要在 `ClearNewPassword` 参数传递加密的新密码，加密使用 AES_CFB8 算法导致可以在不知道加密密钥的情况下构造空密码的密文。
3. Netlogon 协议身份认证后的通信默认是经过签名的，通过协商标志可以使身份认证后的通信不需要经过签名，所以概念验证设置协商标志为 `0x212fffff`
4. AES_CFB8 算法缺陷利用成功有概率性，尝试两千次可以达到99.96%概率

（5）重置域控机器账户密码为空后需要及时恢复域控密码以避免域控脱离域，原因是活动目录存储的域控机器密码和本机lsass进程存储的域控机器密码不一样导致的。

（6）恢复域控密码的手法

（7）[Zerologon漏洞的Relay利用手法](https://dirkjanm.io/a-different-way-of-abusing-zerologon/)

（8）修复方案

（9）日志特征

（10）链接博文/文档

1. https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-nrpc/ff8f970f-3e37-40f7-bd4b-af7336e4792f
2. https://www.anquanke.com/post/id/219374
3. https://blog.csdn.net/systemino/article/details/109017593

# 0x17 sAMAccountName spoofing

（1）[概念验证](https://github.com/cube0x0/noPac)

（2）[CVE-2021-42278](https://support.microsoft.com/en-us/topic/kb5008102-active-directory-security-accounts-manager-hardening-changes-cve-2021-42278-5975b463-4c95-45e1-831a-d120004e258e)

   漏洞允许机器账户的名称（名称由sAMAccountName属性标识）不以 `$` 符号结尾

（3）[CVE-2021-42287](https://support.microsoft.com/en-us/topic/kb5008380-authentication-updates-cve-2021-42287-9dafac11-e0d0-4cb8-959a-143bd0201041)

   在进行 S4U2self 请求时如果没找到 TGT 票据标识的机器账户，则会在机器账户后加上 `$` 符号再进行查找

（4）sAMAccountName spoofing 漏洞原理

   sAMAccountName spoofing 漏洞是由 CVE-2021-42278 和 CVE-2021-42287 漏洞组成的一条攻击路径。使用 CVE-2021-42278 漏洞我们可以创建一个机器账户且对这个机器账户的`sAMAccountName`属性和`serviceprincipalname`属性有写权限。通过对机器账户的`sAMAccountName`属性修改为域控机器账户去除`$`符号然后使用修改过后的机器账户通过 AS_REQ 请求 TGT 票据。请求完 TGT 票据后再修改机器账户的`sAMAccountName`属性为任意值之后使用 S4U2self 请求 ST 票据。在KDC处理 S4U2self 请求时根据 TGT 票据标识的机器账户进行查找用户，此时由于我们的机器账户已经更改掉`sAMAccountName`属性了导致没查找到对应用户，这时候KDC会在机器账户后加上 `$` 再进行查找，此时查找到的是域控的机器账户，然后KDC用域控的机器账户哈希生成 ST 票据，此时这个 ST 票据是可以用于模拟特定客户端针对域控特定服务进行请求的。

（5）攻击路径

1. 使用 CVE-2021-42278 漏洞我们可以创建一个机器账户
2. 清除新创建的机器账户的`serviceprincipalname`属性（这是由于在修改`sAMAccountName`属性时会同步更新`serviceprincipalname`属性导致和域控的`serviceprincipalname`属性冲突，通过清除机器账户的`serviceprincipalname`属性来避免）
3. 通过 LDAP 协议修改创建的机器账户的`sAMAccountName`属性值为域控机器账户的`sAMAccountName`属性去掉 `$` 符号
4. 通过 AS_REQ 请求 TGT 票据
5. 通过 LDAP 协议修改创建的机器账户的`sAMAccountName`属性为任意值
6. 通过 S4U2self 请求域控的机器账户哈希生成的 ST 票据

（6）概念验证中的扫描漏洞是否存在模块是如何工作的呢

   通过能否成功请求不携带 PAC 的 TGT 票据来判断，在 CVE-2021-42287 漏洞的修复中可以知道它的原理。在安装 CVE-2021-42287 补丁后不允许请求不携带 PAC 的 TGT 票据。

![image-20230425221000787](https://github.com/hangchuanin/Intranet_penetration_history/blob/main/images/sAMAccountName%20spoofing2.png)

这里的扫描只是判断了是否安装 CVE-2021-42287 补丁而没有判断是否安装 CVE-2021-42278 补丁

（7）修复方案

1. 安装 CVE-2021-42287 补丁和 CVE-2021-42278 补丁，在安装了 CVE-2021-42278 补丁之后由普通域用户创建的机器账户的`sAMAccountName`属性需要以`$`结尾

   ![image-20230425221415042](https://github.com/hangchuanin/Intranet_penetration_history/blob/main/images/sAMAccountName%20spoofing.png)

2. 将 Machine Account Quota 设置为0以阻止普通域用户创建机器账户或者修改SeMachineAccountPrivilege特权的权限（从SeMachineAccountPrivilege中删除Authenticated Users并添加Domain Admins或另一组允许的帐户）

（8）日志特征

（9）链接博文/文档

1. https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html

# 0x18 CVE-2022-26923

（1）[概念验证](https://github.com/ly4k/Certipy)

（2）CVE-2022-26923 漏洞原理

   使用 Machine 模板向 AC 申请证书时 AC 会把请求者的 `dNSHostName` 属性嵌入到生成的证书中，使用生成的证书请求 TGT 票据时 KDC 会从证书取出镶嵌的 `dNSHostName` 属性值并查找 `sAMAccountName` 属性值和取出值匹配的账户，最后使用查找到的账户完成 TGT 票据生成。通过把机器账户的 `dNSHostName` 属性设置为 DC 的 `dNSHostName` 属性值可以达到伪造 DC 的效果。

（3）攻击路径

1. 使用普通域账户创建一个机器账户，普通域用户对创建的机器账户有`dNSHostName` 属性和`serviceprincipalname`属性的写权限
2. 通过 LDAP 协议修改机器账户的`dNSHostName` 属性为 DC 的`dNSHostName` 属性值，修改`dNSHostName` 属性时会同时修改`serviceprincipalname`属性值，因为`serviceprincipalname`属性值引用了`dNSHostName` 属性值，所以需要清除`serviceprincipalname`属性值或者删去`serviceprincipalname`属性值中引用`dNSHostName` 属性的部分
3. 使用 Machine 模板向 AC 申请证书
4. 使用申请的证书请求 TGT 票据，生成的票据标识的是 DC 机器账户

（4）为什么在攻击路径的第四步中不需要先更改`dNSHostName` 属性值再请求 TGT 票据？这是因为在使用证书申请 TGT 票据时 KDC 会从证书取出镶嵌的 `dNSHostName` 属性值并查找 `sAMAccountName` 属性值和取出值匹配的账户，最后使用查找到的账户完成 TGT 票据生成，所以机器账户的`dNSHostName` 属性值对 TGT 票据生成并没有影响，机器账户的`dNSHostName` 属性值只在证书请求阶段产生作用。

（5）修复方案

1. 在 ADCS 和 域控 上安装 [CVE-2022-26923](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16) 补丁，补丁通过在证书中添加 对象标识符 (OID) (1.3.6.1.4.1.311.25.2) 进一步对用户进行识别，防止通过`dNSHostName` 属性值进行欺骗。

   ![image-20230426212538073](https://github.com/hangchuanin/Intranet_penetration_history/blob/main/images/CVE-2022-26923.png)

2. 通过将 Machine Account Quota 设置为0或者修改SeMachineAccountPrivilege特权的权限禁止普通域账户创建机器账户来阻断攻击路径，但这会有一定的绕过风险。

（6）日志特征

（7）链接博文/文档

1. https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4
2. https://posts.specterops.io/certified-pre-owned-d95910965cd2

# 0x19 bypassUAC

https://www.anquanke.com/post/id/216808

https://github.com/hfiref0x/UACME

无文件bypassUAC：https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/

# 0x20 各类exec原理

（1）[PsExec 概念验证](https://github.com/zesiar0/MyPsExec)

（2）PsExec 攻击路径

1. 连接服务器 SMB 服务
2. 通过 SMB 服务上传 PSEXESVC.exe 文件到服务器
3. 连接服务器的[服务控制管理器](https://learn.microsoft.com/zh-cn/windows/win32/services/service-control-manager)
4. 通过服务控制管理器创建一个执行文件为 PSEXESVC.exe 的服务并启动服务
5. 客户端通过管道/其它方式和服务器上新创建的服务通信来管理远程计算机
6. 删除服务器上新创建的服务
7. 删除服务器上的 PSEXESVC.exe 文件

（3）[PsExec 通信数据包](https://github.com/hangchuanin/Intranet_penetration_history/blob/main/pcapng/psexec.pcapng)

（4）特征日志

（5）[AtExec 概念验证](https://github.com/fortra/impacket/blob/master/examples/atexec.py)

（6）AtExec 攻击路径

1. 通过 [COM接口](https://learn.microsoft.com/en-us/windows/win32/taskschd/time-trigger-example--c---)/[MS-TSCH协议](https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-tsch/d1058a28-7e02-4948-8b8d-4a347fa64931) 在远程服务器上创建计划任务来执行命令并把命令结果重定向到文件中
2. 删除创建的计划任务
3. 通过 SMB 协议从远程服务器上读取命令执行结果
4. 删除保存命令结果的文件

（7）[AtExec 通信数据包](https://github.com/hangchuanin/Intranet_penetration_history/blob/main/pcapng/atexec.pcapng)

（8）特征日志

（9）[SmbExec 概念验证](https://github.com/fortra/impacket/blob/master/examples/smbexec.py)

（10）SmbExec 攻击路径

1. 通过 [MS-TSCH协议](https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-tsch/d1058a28-7e02-4948-8b8d-4a347fa64931) 协议在远程服务器上创建计划任务并执行，计划任务内容为 `C:\Windows\system32\cmd.exe /Q /c echo notepad.exe ^> \\127.0.0.1\C$\__output 2^>^&1 > C:\Windows\TEMP\execute.bat & C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat & del C:\Windows\TEMP\execute.bat`，计划任务的作用是创建一个 execute.bat 批处理文件并执行它，execute.bat 文件的内容为 `notepad.exe > \\127.0.0.1\C$\__output 2>&1  `
2. 删除创建的计划任务
3. 通过 SMB 协议读取 `C$\__output` 文件获取命令执行结果
4. 删除 `C$\__output` 文件

（11）[SmbExec 通信数据包](https://github.com/hangchuanin/Intranet_penetration_history/blob/main/pcapng/smbexec.pcapng)

（12）特征日志

（13）[DcomExec 概念验证](https://github.com/fortra/impacket/blob/master/examples/dcomexec.py)

（14）DcomExec 攻击路径

1. 获取远程服务器 ShellWindows/ShellBrowserWindow/MMC20 DCOM对象
2. 调用 ShellWindows::ShellExecute、ShellBrowserWindow::ShellExecute、MMC20::ExecuteShellCommand 方法执行系统命令并把命令结果重定向到文件中
3. 通过 SMB 服务读取文件内容获取命令执行结果
4. 删除文件

（15）[DcomExec 通信数据包](https://github.com/hangchuanin/Intranet_penetration_history/blob/main/pcapng/dcomexec.pcapng)

（16）特征日志

（17）[WmiExec 概念验证](https://github.com/fortra/impacket/blob/master/examples/wmiexec.py)

（18）WmiExec 攻击路径

1. 连接远程服务器上的 WMI 服务并获取远程服务器的 `Win32_Process` 对象
2. 调用远程服务器上 `Win32_Process` 对象的 `Create` 方法执行命令，命令内容为 `cmd.exe /Q /c whoami 1> \\127.0.0.1\ADMIN$\__1683292860.218341 2>&1`
3. 通过 SMB 服务读取文件内容获取命令执行结果
4. 删除保存命令结果的文件

（19）[WmiExec 通信数据包](https://github.com/hangchuanin/Intranet_penetration_history/blob/main/pcapng/wmiexec.pcapng)

（20）特征日志

# 0x21 bypassApplocker

https://github.com/api0cradle/UltimateAppLockerByPassList

https://www.anquanke.com/post/id/159892

# 0x22 看一些MicroSoft kerberos协议的文档

- [Microsoft Kerberos (Windows)](https://learn.microsoft.com/zh-cn/windows/win32/secauthn/microsoft-kerberos)
- [[MS-KILE\]： Kerberos 协议扩展](https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-kile/2a32282e-dd48-4ad9-a542-609804b02cc9)
- [[MS-SFU\]：Kerberos 协议扩展：用户服务和约束委派协议规范](https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94)
- [Kerberos SSP/AP (Windows)](https://learn.microsoft.com/zh-cn/windows/win32/secauthn/kerberos-ssp-ap)
- 适用于 Windows Vista 的 [Kerberos 增强功能](https://learn.microsoft.com/zh-cn/previous-versions/windows/it-pro/windows-vista/cc749438(v=ws.10))
- Windows 7 [的 Kerberos 身份验证更改](https://learn.microsoft.com/zh-cn/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd560670(v=ws.10))
- [Kerberos 身份验证技术参考](https://learn.microsoft.com/zh-cn/previous-versions/windows/it-pro/windows-server-2003/cc739058(v=ws.10))

详细看 用户服务和约束委派协议规范，细节比较多（反复翻阅

# 0x23 非约束委派

关于委派类攻击参考这篇[文章](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)，比较全面的

微软在非约束委派的实现上使用的是 **带有转发的票证授予票证 (TGT)的 Kerberos 委派** 机制，流程图在[这里](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/1fb9caca-449f-4183-8f7a-1a5fc7e7290a)的图一

# 0x24 约束委派

约束委派委派的哪个服务不重要，因为服务在整个 Ticket 结构中位于未加密部分，直接修改即可

S4U2-Self 协议也就是协议转换

# 0x25 基于资源的约束委派

寻找以机器账户发起认证的原语以拼接资源委派攻击链

- [微软不认的“0day”之域内本地提权-烂番茄（Rotten Tomato）](https://mp.weixin.qq.com/s?__biz=MzI2NDk0MTM5MQ==&mid=2247483689&idx=1&sn=1d83538cebbe2197c44b9e5cc9a7997f&chksm=eaa5bb09ddd2321fc6bc838bc5e996add511eb7875faec2a7fde133c13a5f0107e699d47840c&scene=126&sessionid=1584603915&key=cf63f0cc499df801cce7995aeda59fae16a26f18d48f6a138cf60f02d27a89b7cfe0eab764ee36c6208343e0c235450a6bd202bf7520f6368cf361466baf9785a1bcb8f1965ac9359581d1eee9c6c1b6&ascene=1&uin=NTgyNDEzOTc%3D&devicetype=Windows+10&version=62080079&lang=zh_CN&exportkey=A8KlWjR%2F8GBWKaJZTJ2e5Fg%3D&pass_ticket=B2fG6ICJb5vVp1dbPCh3AOMIfoBgH2TXNSxmnLYPig8%3D)
- NTLM反射添加 msDS-AllowedToActOnBehalfOfOtherIdentity

遇到问题查阅 用户服务和约束委派协议规范，反复翻阅

# 0x26

