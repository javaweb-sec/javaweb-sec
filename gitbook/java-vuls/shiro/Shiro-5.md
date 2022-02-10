# 前言

本文继续漏洞原理系列文章，这次简单的学习和分析了权限校验框架 Shiro 在历史上爆出的共 11 个带有 CVE 编号的漏洞，根据每个 CVE 漏洞的原理，版本更新的代码来分析安全漏洞产生的原理、利用方式、特性、坑。

主要还是对基础洞的学习，用来积累思路和姿势，目前对于 Java 安全来讲，单一的基础洞只能打打垃圾站，能够普遍适用的漏洞还需要组合拳来搞定，因此对思路、姿势的积累愈发重要，任何一个小 tricks 都能成为日后组链的关键点。

个人能力有限，如文章中有描述不清、有偏差甚至是错误的情况，希望师傅们不吝赐教。

# 目录

点击左边连接可以直接跳到对应漏洞的调试记录。

|   链接   |   描述   |
| :---------------- | :------------------------- |
|   [简介](https://su18.org/post/shiro-1/#%E7%AE%80%E4%BB%8B)   |   Apache Shiro 简介   |
|   [初识](https://su18.org/post/shiro-1/#%E5%88%9D%E8%AF%86)   |   几个关键类的介绍   |
|   [使用](https://su18.org/post/shiro-1/#%E4%BD%BF%E7%94%A8)   |   在 Servlet 项目和 Spring 项目中的简单使用   |
|   [CVE-2010-3863](https://su18.org/post/shiro-1/#cve-2010-3863)   |   由于未标准化路径导致的绕过   |
|   [CVE-2014-0074](https://su18.org/post/shiro-1/#cve-2014-0074)   |   使用 ldap 服务器认证时两个场景的绕过   |
|   [CVE-2016-4437](https://su18.org/post/shiro-2/#cve-2016-4437)   |   RememberMe 反序列化漏洞   |
|   [CVE-2016-6802](https://su18.org/post/shiro-2/#cve-2016-6802)   |   Context Path 路径标准化导致绕过   |
|   [CVE-2019-12422](https://su18.org/post/shiro-2/#cve-2019-12422)    |   Padding Oracle Attack & CBC Byte-Flipping Attack   |
|   [CVE-2020-1957](https://su18.org/post/shiro-3/#cve-2020-1957)   |   Spring 与 Shiro 对于 "/" 和 ";" 处理差异导致绕过   |
|   [CVE-2020-11989](https://su18.org/post/shiro-3/#cve-2020-11989)    |   Shiro 二次解码导致的绕过以及 ContextPath 使用 ";" 的绕过  |
|   [CVE-2020-13933](https://su18.org/post/shiro-3/#cve-2020-13933)   |   由于 Shiro 与 Spring 处理路径时 URL 解码和路径标准化顺序不一致<br>导致的使用 "%3b" 的绕过   |
|   [CVE-2020-17510](https://su18.org/post/shiro-4/#cve-2020-17510)   |   由于 Shiro 与 Spring 处理路径时 URL 解码和路径标准化顺序不一致<br>导致的使用 "%2e" 的绕过   |
|   [CVE-2020-17523](https://su18.org/post/shiro-4/#cve-2020-17523)   |   Shiro 匹配鉴权路径时会对分隔的 token 进行 trim 操作<br>导致的使用 "%20" 的绕过   |
|   [CVE-2021-41303](https://su18.org/post/shiro-4/#cve-2021-41303)   |   由于 Shiro 的 BUG 导致特定场景的绕过（不确定）   |


# 总结

通过对 Shiro 漏洞的学习和调试，我们对 Shiro 的一些技术的实现和安全部署有了一定的了解。除了 SHIRO-550 和 SHIRO-721 的反序列化以及 CVE-2014-0074 的 ldap 绕过之外，其他的绕过都是在路径处理过程中产生问题导致的绕过。

这些绕过多数是由于 shiro 的处理逻辑有误，或和中间件、其他框架的处理逻辑不一致导致的安全问题，通常会依赖场景。

更多时候，在真实的环境中，开发人员自己的配置也会导致鉴权的绕过，例如配置顺序、配置中是否有空格、配置中一些特殊符号的使用、Ant 表达式使用差异、开发人员鉴权代码逻辑有误等等，这部分目前在文章中没有涉及，后续会考虑补上。

另外，随着一些转发中间件、API 中间件等等中间层的介入，会扰乱 shiro 的鉴权配置，也会导致很多的安全问题。

可以预见的是，在特定场景下的绕过还是会出现的。

在 Shiro 的修复过程中还能看到的是，shiro 会提供解决方案，但有时不是升级版本就可以的，也有时修复的也并不全面，所以实现 shiro 安全还是需要安全知识和经验的加持。

# 杂记汇总

在整个的学习和调试过程中，有一些觉得有趣的杂记，放在这里供大家查看。

## Spring 版本

Spring 的版本会完全的影响漏洞的触发，在某些 CVE 中，低版本生效，高版本不生效，在某些 CVE 中则相反，还有时由于 Spring 版本高可以绕过 Shiro 的更新补丁。

这些在具体的漏洞分析都提到了，实际上是因为 `alwaysUseFullPath` 导致的，详细的内容可以自行了解。

## Ant 表达式中的 “*”

在 Ant 表达式中的 “*” 撑起了 shiro bypass 的大旗。其中关键点用一句话解释就是：
> `/audit/*` 不能匹配 `/audit/` 也不能匹配 `/audit/a/`

## 彩蛋

在翻 Shiro 的 ISSUES 时，发现李三师傅提交的 [SHIRO-760](https://issues.apache.org/jira/browse/SHIRO-760) 提到了在使用 Tomcat AJP 时会导致的绕过问题。

但是官方认为其不算漏洞，就没下文了。可以预想到，关于不同协议下对请求路径的处理差异、或能够控制 Attribute 的场景下也可能导致绕过的产生。


## Tips

这里分享几个分析时的小技巧。

第一，通过如下链接就可以查看这个版本修复了哪些 ISSUES ，方便定位。

> https://issues.apache.org/jira/issues/?jql=project%20%3D%20SHIRO%20AND%20fixVersion%20%3D%201.5.2

第二，通过 diff 版本来查看差异代码分析漏洞，语法如下。

> https://github.com/用户名/项目/compare/TAG名...TAG名

例如：https://github.com/apache/shiro/compare/shiro-root-1.7.0...shiro-root-1.7.1


# 反序列化

目前针对 Shiro 讨论最多的，还是 RememberMe 反序列化漏洞的延伸和姿势，我大概过了一下全网的文章，主要包括以下几个点：
- Shiro 组件的检测：检测站点是否包含 shiro 组件，cookie 关键字不是 rememberMe 等情况；
- Shiro AES 弱密钥的检测：检测 Shiro 是否内置或配置了常见的弱密钥；
- Shiro 内置链的利用：无 CC 依赖的 CB 链反序列化利用；
- 配合 RMI 利用：处理由于插入反序列化链导致的 Header 长度的问题，以及 Transformer 数组加载不到报错问题；
- 其他绕过 Tomcat Header 长度的姿势：反射修改 AbstractHttp11Protocol 的 maxHeaderSize、gzip + base64压缩编码、从外部或从 HTTP 请求 body 中加载类字节码；
- Ysoserial 改造：由于 shiro RememberMe 反序列化流程中加载类方式不同导致需要对 ysoserial 中 CC 等链的改造；
- 组合攻击：在 weblogic/Tomcat 等中间件上完成 shiro 的攻击、gadget 的利用、内存马的写入等组合操作；
- 改 Key：对于弱加密密钥，在攻击后将其修改，让目标仅为自己所用。

这部分内容算是进阶内容，没有放在本篇用于入门学习的笔记类文章中。感兴趣的同学可以在先知和 Seebug Paper 中搜索关键字 Shiro 来了解。
