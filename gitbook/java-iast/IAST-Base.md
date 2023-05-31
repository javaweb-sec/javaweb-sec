# 浅谈被动式IAST产品与技术实现-基础篇

> 笔者因为之前有过参与RASP研究&研发的一些经验，而且看近两年IAST看着发展势头挺足，所以一直有时间想研究下IAST相关的技术，但是苦于国内外对于IAST具体实现的细节的一些文章并不是很多，唯一开源的IAST也就是洞态了，所以想自己对IAST原理进行简单的技术实现。正好最近有时候有点时间，所以抽空研究了下IAST相关的技术实现，笔者因为工作原因，已经将近2年多没有碰Java了，对于本文章中的一些疏漏点，且本文仅代表个人的一些观点，还望大家多多包涵，笔者目前就职于墨云科技，欢迎大家一起来交流、学习。

## 什么是IAST

IAST是AST其中的一个类别，AST是Application Security Testing的简称，翻译过来就是应用安全测试，在他之下衍生出来以下几种类型:
- SAST（Static Application Security Testing）静态应用安全测试
- DSAT（Dynamic Application Security Testing）动态应用安全测试
- MAST（Mobile Application Security Testing）移动应用安全测试
- IAST (Interactive Application Security Testing)交互式应用安全测试

对于IAST的定义我并没有在Gartner找到其相关的术语表，但是在Gartner推荐的服务商中找到了一些关于IAST的定义，我总结了下，核心如下：

> IAST使用运行时代理方法在测试阶段分析&监控应用程序的行为。这种类型的测试也不测试整个应用程序或代码，而只测试执行功能的部分。


比较有意思的一点是，大家好像都在说IAST是Gartner2012年提出来的术语，但是我查了Gartner的术语表，并没有找到IAST相关的定义，但是在Gartner推荐的服务商找到了IAST相关的标签和简单的介绍（可能由于Gartner之前改版，导致这个术语丢失？）
![](https://oss.javasec.org/images/16393856801258.jpg)

好了，回到正题，IAST呢，又细分为好几种，大家可以看下 https://www.freebuf.com/sectool/290671.html 这篇文章，对IAST的分类有比较清晰的描述。本文以及后面的文章主要是介绍其中的被动式IAST.


## 国内外IAST产品
笔者对国内外的IAST相关的产品公司进行了一些规整，大概如下(该数据不代表所有的IAST厂商,仅是笔者搜索到的部分厂商)

| 厂商 | 产品名 | 产品介绍 | 相关网址 | 
|------|--------|----------|:---------|
| Checkmarx | CxIAST | Checkmarx CxIAST解决方案提供了一个应用程序安全自测试模型，其中安全测试由自动或手动执行的任何应用程序功能测试(通常是QA)驱动。它还以零时间(即时检测)和零运营开销交付结果，这使其非常适合CI/CD环境。 | https://checkmarx.atlassian.net/wiki/spaces/CCD/pages/253657926/Checkmarx+CxIAST |
| Contrast | Contrast ASSESS | Contrast Assess是一种革命性的交互式应用程序安全测试(IAST)解决方案，它将安全专业知识融入应用程序本身。Contrast agent使用智能传感器检测应用程序，以便从应用程序内部实时分析代码。Contrast Assess然后使用代理收集的情报来识别和确认代码中的漏洞。这包括已知(CVE)和未知漏洞。 |  https://www.contrastsecurity.com/interactive-application-security-testing-iast        |    /  |
| synopsys | Seeker IAST | Seeker 易于在 CI/CD 开发工作流程中进行部署和扩展。本机集成、Web API 和插件能够无缝集成到用于本地、基于云、基于微服务和基于容器的开发的工具。无需大量配置、自定义服务或调整，即可获得直接可用的准确结果。Seeker 在正常测试期间监视后台的 Web 应用交互，并能快速处理数十万个 HTTP 请求，在几秒钟内为您提供结果，误报率几乎为零，而且无需运行手动安全扫描。 |   https://www.synopsys.com/software-integrity/security-testing/interactive-application-security-testing.html       | 
| HCL Software |  AppScan IAST |一个可扩展的应用程序安全测试工具，提供SAST、DAST、IAST和风险管理功能，帮助企业在整个应用程序开发生命周期中管理风险和合规性。  | https://help.hcltechsw.com/appscan/Enterprise/zh_CN/10.0.2/topics/c_ase_iast_scanning.html |
| 北京酷德啄木鸟信息技术有限公司 | CodePecker Finder | Finder 是 北京酷德啄木鸟信息技术有限公司提供的一款基于敏感数据追踪分析的交互式应用程序安全测试（IAST）软件，通过 Finder 可深入观察应用系统的的安全状况并发现基于各种合规性标准（例如 OWASP Top 10、CWE/SANS、Cert）的缺陷定义，并能够提供可视化的视图。 | http://www.codepecker.com.cn/  | 
|  北京安普诺信息技术有限公司 | 悬镜灵脉IAST |  悬镜灵脉IAST灰盒安全测试平台作为一款次世代智慧交互式应用安全测试产品，采用前沿的深度学习技术，融合领先的IAST产品架构，使安全能力左移前置，将精准化的应用安全测试高效无感地应用于从开发到测试的DevSecOps全流程之中。|   https://iast.xmirror.cn/       | 
|  OpenRasp    |      IAST 灰盒扫描工具  | 基于 OpenRASP 的一款灰盒扫描工具。     | https://github.com/baidu-security/openrasp-iast  |      |
|  默安科技  |  雳鉴IAST  | 默安科技雳鉴交互式应用安全检测系统（以下简称“雳鉴IAST”）,专注解决软件安全开发流程（SDL）中测试阶段的应用安全问题。雳鉴IAST使用基于请求和基于代码数据流两种技术的融合架构，采用被 Gartner 评为十大信息安全技术之一的IAST技术，结合SAST和DAST的优点，做到检出率极高且误报率极低，同时可定位到API接口和代码片段，在测试阶段无缝集成，可高准确性的检测应用自身安全风险，帮助梳理软件成分及其漏洞，为客户系统上线前做强有力的安全保障。  | https://www.moresec.cn/product/sdl-iast | 
| 北京安全共识科技有限公司 |   洞态IAST  | 洞态IAST是全球首家开源的IAST，支持SaaS访问及本地部署，助力企业在上线前解决应用的安全风险  | https://dongtai.io/   |
| 杭州孝道科技有限公司 | 安全玻璃盒 | 安全玻璃盒自主研发了国内第一款运行时非执行态的交互式应用安全测试系统，通过安全与软件高度耦合的安全检测技术，对应用系统漏洞及所引用的三方组件，实现在线无风险、高效自动化、全面精确可视化的漏洞检测和问题定位。  | https://www.tcsec.com.cn/product/iast   |

## 国内外IAST技术实现现状

### 洞态

洞态是目前国内&业界开源的一款被动式IAST产品，对于洞态的一些技术细节，网上已经有一些文章对其进行了分析，在这里笔者简单的用自己的理解对于洞态实现的IAST进行一个总结阐述：

- 依靠JVM-Sandbox的AOP能力对关键类进行埋点处理
- 依靠预定义好的规则，对上下文请求、埋点数据进行跟踪反馈

洞态对于IAST规则的定义分了以下几个类别:

- Http（这个类别没有在规则中体现出来，代码中有这部分的实现，主要是对Servlet数据进行克隆存储）
- Source (如getParameter、getParameterValues等获取http请求包中数据的一些方法)
- Propagator（污点传播，一堆复杂的逻辑对上下文进行判断，根据判断结果去决定是否保存该传播点的信息）
- Sink（最终漏洞触发点）

我本地搭建了个洞态的服务，在后台看到了不少规则信息，
![](https://oss.javasec.org/images/16393856801282.jpg)

可以看到预定义的各种规则覆盖了不少，因此可以对于在展示漏洞的时候，将其相关的调用传播堆栈信息展示出来。
![](https://oss.javasec.org/images/16393856801294.jpg)

但是洞态对于整条链路中所涉及到的souce的传播以及到最后危险函数到达的部分，是没直观的看到其在传播中变量的整个传播变化结果，仅有一个source获取攻击参数的展示，这样可能对后续报告中的体现，以及推动研发修改这个漏洞有一些暗坑。

经洞态的研发确认我知道了如果是通过私有化部署的方式下载的 Agent，可升级至 洞态 1.1.3 级以上版本或增加 JVM 参数：-Diast.server.mode=local ，即可收集到链路上的具体数据，这部分就需要大家自己去研究看看了。

### Contrast

Contrast提供免费的使用，因为对agent的代码进行了混淆，所以我没有对其到底如何实现进行深入的了解，有兴趣的朋友可以了解看看。
通过对agent的使用以及控制台的展示内容来看，我个人感觉Contrast的IAST更像RASP（Contrast也提供RASP功能，可能我没玩明白..）,所以到底是IAST，还是RASP换一种方式去展现，这个就需要大家自己去深入了解了。

![](https://oss.javasec.org/images/16393856801306.jpg)

![](https://oss.javasec.org/images/16393856801323.jpg)
![](https://oss.javasec.org/images/16393856801349.jpg)


### Checkmarx

Checkmarx是基于AspectJ对关键的类进行切片埋点，因为我拿到Checkmarx的Agent是没办法直接运行起来的，只有jar，所以只是简单的看了下逻辑，在Checkmarx的代码中，可以看到其埋点的数据都在`com.checkmarx.iast.agent.aspects.original`包里面，
![](https://oss.javasec.org/images/16393856801371.jpg)

而且是完全依赖AspectJ对关键的类以及方法进行处理,从而达到埋点的效果。对于真正运行起来的效果，笔者这边环境有限，暂未深入研究。

### 安全玻璃盒

机缘巧合的情况下，某匿名好心人听说我在研究IAST,所以将他们购买的一套IAST让我远程看了下。
![](https://oss.javasec.org/images/16393856801399.jpg)
![](https://oss.javasec.org/images/16393856801426.jpg)
通过对系统的查看，我发现这个系统和我上面说到的Contrast有点类似，并没有对于中间的传播点进行覆盖，仅仅是对于source以及sink点进行了埋点。
由于安全玻璃盒也对agent进行了混淆处理，所以没有办法直观的看到其内部运行的逻辑。
抛开其IAST的技术实现逻辑，在整体界面上，以及使用情况下，安全玻璃盒可能更符合国人的习惯。

## 总结

本篇笔者就个人对被动式IAST的理解进行了阐述，也对市场上的部分IAST进行了收集整理，并且提取了其中部分可以拿到agent的IAST进行了原理性总结，可以看到这些Agent都是对字节码进行编辑增强，从而达到一种被动式IAST的效果。
看到这里我有点潜意识的认为，被动式IAST要想实现，那么其实和RASP差不太多，可能多出来的点就是多了一些中间的埋点检测，从而达到对调用链的精准跟踪，在这一细小部分，我个人的理解是，就是对所有有可能导致source获取到的参数进行改变的方法进行埋点，包括但不限于类似以下几种情况（下面仅是伪代码，并不代表真实逻辑中的代码,仅用于更方面的向大家传达我个人的一些理解）
```
new String(....)
"aa".replace(...)
StringBuilder sb = new StringBuilder();
Base64.decode(...)
```
等等等等，这个链路是需要根据自己的实际业务情况进行完善的，比如自己实现了个加解密的类等等，又或者是加入对souce进行安全过滤处理的方法，然后将所有经过预埋点的堆栈信息进行拼接，在这个过程中，可以去判断这条链路经过了安全过滤处理方法，那么或许可以粗暴的不上报这条调用链信息，认为这是一个安全的请求（当然这种情况还是要谨慎，毕竟研发中难免会犯一些错误，所以在情况允许的环境下，还是全部上报，交给人工进行复验、排除是更为妥当的解决方式），然后将数据上报到服务端，到此完成一个IAST的技术理念逻辑。

那么其实是不是可以使用一些APM的开源技术，对它进行一些改造，从而实现IAST的部分功能。如果想深度控制IAST的流程，更好的方式就是自己实现一套IAST埋点、检测逻辑。


## 参考
- https://www.freebuf.com/sectool/290671.html
- https://www.gartner.com/reviews/market/application-security-testing
- https://doc.dongtai.io/
- http://rui0.cn/archives/1175
- https://dzone.com/refcardz/introduction-to-iast
- https://blog.secodis.com/2015/11/26/the-emerge-of-iast/-of-iast/-of-iast/
