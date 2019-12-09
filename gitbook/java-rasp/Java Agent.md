# Java Agent 机制

> JDK1.5开始引入了Agent机制(即启动java程序时添加`-javaagent`参数”,如`java -javaagent:/data/test.jar LingXeTest`)，`Java Agent`机制允许用户在JVM加载class文件的时候先加载自己编写的Agent文件，通过修改JVM传入的字节码来实现注入`RASP`防御逻辑。这种方式因为必须是在容器启动时添加jvm参数,所以需要重启Web容器。JDK1.6新增了`attach`方式(`agentmain`)，可以对运行中的java进程附加agent。使用附加的方式可以在容器运行时动态的注入`RASP`防御逻辑。

使用在应用启动时加入`-javaagent`参数的方式适用于`RASP`常驻用户应用的防御方式,也是我们目前最常用的安装集成方式。但是正因为必须在应用程序启动时加上我们自定义的`-javaagent`参数所以也就会不得不要求用户重启Web容器，一些生产环境的服务是不允许停止的，所以重启问题成了其重大阻碍。

为了解决应用重启问题，我使用了`attach`灵蜥Agent到Java进程的方式来实现防御，当然`attach`和`agent`方式并无太大的差异，只是实现方式会有细微的差别，麻烦的是`attach`需要考虑如何避免重复加载、如何完整的卸载等问题。