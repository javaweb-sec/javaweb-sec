# Java 序列化和反序列化

在很多语言中都提供了对象反序列化支持，Java在JDK1.1(`1997年`)时就内置了对象反序列化(`java.io.ObjectInputStream`)支持。Java对象序列化指的是`将一个Java类实例序列化成字节数组`，用于存储对象实例化信息：类成员变量和属性值。 Java反序列化可以`将序列化后的二进制数组转换为对应的Java类实例`。

Java序列化对象因其可以方便的将对象转换成字节数组，又可以方便快速的将字节数组反序列化成Java对象而被非常频繁的被用于`Socket`传输。 在`RMI(Java远程方法调用-Java Remote Method Invocation)`和`JMX(Java管理扩展-Java Management Extensions)`服务中对象反序列化机制被强制性使用。在Http请求中也时常会被用到反序列化机制，如：直接接收序列化请求的后端服务、使用Base编码序列化字节字符串的方式传递等。

## Java反序列化漏洞

自从2015年[Apache Commons Collections反序列化漏洞](https://issues.apache.org/jira/browse/COLLECTIONS-580)([ysoserial](https://github.com/frohoff/ysoserial)的最早的commit记录是2015年1月29日,说明这个漏洞可能早在2014年甚至更早就已经被人所利用)利用方式被人公开后直接引发了Java生态系统的大地震，与此同时Java反序列化漏洞仿佛掀起了燎原之势，无数的使用了反序列化机制的Java应用系统惨遭黑客疯狂的攻击，为企业安全甚至是国家安全带来了沉重的打击！

直至今日(2019年12月)已经燃烧了Java平台四年之久的反序列化漏洞之火还仍未熄灭。如今的反序列化机制在Java中几乎成为了致命的存在，反序列化漏洞带来的巨大危害也逐渐被我们熟知。2018年1月Oracle安全更新了237个漏洞，而反序列化漏洞就占了28.5%，由此可见Oracle对反序列化机制的深恶痛绝。2012年`JEP 154`提出了移除反序列化机制：[JEP 154: Remove Serialization](https://openjdk.java.net/jeps/154)、[JDK-8046144](https://bugs.openjdk.java.net/browse/JDK-8046144)，但似乎并未通过，移除反序列化是一个持久性的工作，短期内我们还是需要靠自身去解决反序列化机制带来的安全问题。

