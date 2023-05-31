# RASP技术

运行时应用程序自我保护（`Runtime application self-protection`，简称`RASP`）使用Java Agent技术在应用程序运行时候动态编辑类字节码，将自身防御逻辑注入到Java底层API和Web应用程序当中，从而与应用程序融为一体，能实时分析和检测Web攻击，使应用程序具备自我保护能力。

RASP技术作为新兴的WEB防御方案，不但能够有效的防御传统WAF无法实现的攻击类型，更能够大幅提升对攻击者攻击行为的检测精准度。RASP是传统WAF的坚实后盾，能够弥补WAF无法获取Web应用`运行时`环境的缺陷，同时也是传统Web应用服务最重要的不可或缺的一道安全防线。

RASP通过注入自身到开发语言底层API中，从而完全的融入于Web服务中，拥有了得天独厚的漏洞检测和防御条件，RASP技术相较于传统的WAF拥有了更加精准、深层次的防御。RASP采用`基于攻击行为分析`的`主动防御`机制，严防`文件读写`、`数据访问`、`命令执行`等Web应用系统命脉，为Web应用安全筑建出“万丈高墙”。



## RASP技术原理

`JDK1.5`开始，`Java`新增了`Instrumentation（Java Agent API）`和`JVMTI（JVM Tool Interface）`功能，允许`JVM`在加载某个`class文件`之前对其字节码进行修改，同时也支持对已加载的`class（类字节码）`进行重新加载（`Retransform`）。

利用`Java Agent`这一特性衍生出了`APM（Application Performance Management，应用性能管理）`、`RASP（Runtime application self-protection，运行时应用自我保护）`、`IAST（Interactive Application Security Testing，交互式应用程序安全测试）`等相关产品，它们都无一例外的使用了`Instrumentation/JVMTI`的`API`来实现动态修改`Java类字节码`并插入监控或检测代码。

RASP防御的核心就是在Web应用程序执行关键的Java API之前插入防御逻辑，从而控制原类方法执行的业务逻辑。如果没有RASP的防御，攻击者可以利用Web容器/应用的漏洞攻击应用服务器。

**示例 - Web攻击原理：**

![img](https://oss.javasec.org/images/image-20201115214755444.png)

当Web应用接入RASP防御后，RASP会在Java语言底层重要的API（如：文件读写、命令执行等API）中设置防御点（API Hook方式），攻击者一旦发送Web攻击请求就会被RASP监控并拦截，从而有效的防御Web攻击。

**示例 - RASP防御原理：**

![img](https://oss.javasec.org/images/image-20201104172033466.png)



RASP的防御能力是基于“行为实现”的，RASP会根据Hook点触发的攻击事件（如：文件读取事件、命令执行事件）调用对应的防御模块，而不需要像传统的WAF一样，一次性调用所有的防御模块。



## 灵蜥Agent架构

灵蜥Agent由两大核心机制（`Agent机制`、`Hook机制`）、三大核心模块（`RASP Loader`、`RASP Context`、`RASP 防御模块`）组成。

**RASP Agent架构图：**

![image-20201121235014247](https://oss.javasec.org/images/image-20201121235014247.png)

Agent机制和Hook机制是RASP实现防御的必要条件，RASP会使用Hook机制防御容易被攻击的Java类（如：Java SE、Web应用），当被防御的类方法被调用时会自动触发RASP的防御代码。