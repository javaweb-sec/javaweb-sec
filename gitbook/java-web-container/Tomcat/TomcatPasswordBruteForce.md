# Tomcat 口令爆破

Tomcat在默认情况下提供了一些管理后台，不同的管理后台提供了不同的功能，这些管理后台使用了**Basic认证**的方式进行权限校验，如果暴露在互联网上，将存在遭到暴力破解的安全风险。

其中主要包含两种：**Manager**以及**Host Manager**。



## Manager APP

在生产环境中，为了实现部署新的Web应用程序或取消部署现有的程序而不必重启容器、动态更新程序代码、列出一些JVM或操作系统的属性值、列出应用程序或会话等等基础功能，Tomcat默认包括了一个Web应用程序，通常位于`$CATALINA_BASE/webapps/manager`目录下：

![img](https://oss.javasec.org/images/image-20200924160215953.png)

并且这个应用程序默认的context path也为`/manager`，访问应用的方式为`/manager/html`。

对于这个APP的详细介绍，可以在官方文档找到，以Tomcat 7.0为例，文档的位置为：https://tomcat.apache.org/tomcat-7.0-doc/manager-howto.html

我们查看manager应用下的web.xml，发现其中配置了如下`servlet-mapping`:

![image-20200924163251524](https://oss.javasec.org/images/image-20200924163251524.png)

由此我们可以知道：

- /manager/html/：提供HTML格式的管理页面
- /manager/status/：提供服务器状态（Server Status）页面
- /manager/jmxproxy/：提供JMX proxy 接口
- /manager/text/：提供纯文本页面

由于Tomcat Manager提供的这些功能是需要管理人员才能使用和查看的，因此如果默认开启的话将会存在很高的安全问题，所以Tomcat并没有直接提供这些功能。

如果想要使用这些功能，则需要在`$CATALINA_BASE/conf/tomcat-users.xml`中配置相关的用户信息，包括用户名、密码、用户角色，来对使用这些功能的用户进行身份鉴别和权限验证。

![img](https://oss.javasec.org/images/image-20200924164035213.png)

在 manager 项目中的web.xml中我们可以看到能够使用的这些角色：

![image-20200924164629373](https://oss.javasec.org/images/image-20200924164629373.png)

他们对应的权限分别为：

- manager-gui：能够访问`/manager/html/`的管理界面。
- manager-script：能够访问 `/manager/text/` 以及`/manager/status/`界面。
- manager-jmx：能够访问`/manager/jmxproxy/` 以及`/manager/status/`界面。
- manager-status：能够访问 `/manager/status/`的Server Status界面。

在正确的配置了用户身份信息和角色后，就能够访问相应的页面了。以本篇作者的环境为例，演示如下：

**Server Status页面：**

![image-20200924173046922](https://oss.javasec.org/images/image-20200924173046922.png)

**html管理后台：**

![image-20200924173214026](https://oss.javasec.org/images/image-20200924173214026.png)

**纯文本页面-使用指令list：**

![image-20200924173454058](https://oss.javasec.org/images/image-20200924173454058.png)

**JMX Proxy页面：**

![image-20200924173652947](https://oss.javasec.org/images/image-20200924173652947.png)

对于这几个Servlet功能的实现如果感兴趣，可以查看在`org.apache.catalina.manager` 目录下的代码，在此章节将不过多关注。

![image-20200924174502237](https://oss.javasec.org/images/image-20200924174502237.png)



## Host Manager

顾名思义，此管理后台用于管理运行在Tomcat上的虚拟主机，文件路径位置为`$CATALINA_BASE/webapps/host-manager`，context path为`/host-manager`。

详细介绍可以在官方文档找到，以Tomcat 7.0为例，文档的位置为：https://tomcat.apache.org/tomcat-7.0-doc/host-manager-howto.html

servlet-mapping以及用户权限均有两个：

![img](https://oss.javasec.org/images/image-20200924175829141.png)

配置方式同 manager，不再重复，以下为页面示例：

**html页面管理后台：**

![image-20200924180115463](https://oss.javasec.org/images/image-20200924180115463.png)

**纯文本页面-使用指令list：**

![image-20200924180243681](https://oss.javasec.org/images/image-20200924180243681.png)

## 暴力破解

刚才提到的这些应用之所以采用Basic认证进行身份验证，原因是在应用配置、Tomcat配置等文件中进行了如下配置：

- 认证的方式（BASIC、DIGEST、FORM、SSL等）

![image-20200924181221421](https://oss.javasec.org/images/image-20200924181221421.png)

- 通过 `security-constraint` 配置需要鉴权的访问路径

![img](https://oss.javasec.org/images/image-20200924183406405.png)

- 用户的身份信息（账户、密码）、权限（角色）

![img](https://oss.javasec.org/images/image-20200924183627781.png)

- 默认的域（Realm）配置，Tomcat的`server.xml`中默认配置 `UserDatabaseRealm`，它从配置的全局资源 `conf/tomcat-users.xml` 中提取用户信息，在Tomcat 7.0及以上版本中，还提供了`LockOutRealm` 的组合域，用来阻止短时间内多次登录失败的情况。

![img](https://oss.javasec.org/images/image-20200924183800370.png)

在经过了如上配置后，再访问这些管理后台将需要进行Basic认证。

### 弱口令

虽然Tomcat没有提供默认用户，但是在配置文件中含有注释了的配置样例，其中包括的用户名密码：

```txt
tomcat:tomcat
both:tomcat
role1:tomcat
```

有的管理员可能会取消注释直接使用这些默认配置的账户密码，因此可以将其当做Tomcat的默认口令

除此之外，还有的管理员习惯于使用常用的用户名及密码，如：

```txt
admin:admin
admin:123456
root:root
manager:manager:
admin:admin888
...
```

以上仅仅是列出一小部分作为示例，实际上还有很多种类的弱口令。一旦弱口令被攻击者猜解到，攻击者能够轻易的获取一些用户的权限，大大降低了攻击成本。



### 暴破

Basic认证是一种较为简单的HTTP认证方式，客户端通过明文（Base64编码格式）传输用户名和密码到服务端进行认证。

客户端携带数据格式为：

```http
Authorization: Basic dG9tY2F0OjEyMzEyMw==
```

服务端会根据用户是否登陆成功返回 200 或 401 等不同的状态码，攻击者可以自行组织字典进行暴力破解攻击。

暴力破解携带的账户密码可能是弱口令，也可能是撞库攻击，还可能是根据站点、管理员自身信息生成的字典等，具有更高的成功率。

如下，使用 Burpsuite的 Intruder 模块对 Tomcat 6.0 的 `/manager/html` 路径的基础认证进行爆破：

![image-20200925105747025](https://oss.javasec.org/images/image-20200925105747025.png)



### 限制

刚才提到了，在Tomcat 7以上配置文件默认添加了`LockOutRealm`，首先我们看一下 `LockOutRealm`的逻辑，代码位于`org.apache.catalina.realm.LockOutRealm`。类里的字段很明了，无需解释。

![img](https://oss.javasec.org/images/image-20200924190438021.png)

在 `authenticate` 方法中进行身份验证，如果用户登陆失败，将调用 `registerAuthFailure` 方法标记用户的登录失败状态

![img](https://oss.javasec.org/images/image-20200924190057039.png)

这段代码我贴一下：

```java
    private void registerAuthFailure(String username) {
        LockOutRealm.LockRecord lockRecord = null;
        synchronized(this) {
            if (!this.failedUsers.containsKey(username)) {
                lockRecord = new LockOutRealm.LockRecord();
                this.failedUsers.put(username, lockRecord);
            } else {
                lockRecord = (LockOutRealm.LockRecord)this.failedUsers.get(username);
                if (lockRecord.getFailures() >= this.failureCount && (System.currentTimeMillis() - lockRecord.getLastFailureTime()) / 1000L > (long)this.lockOutTime) {
                    lockRecord.setFailures(0);
                }
            }
        }

        lockRecord.registerFailure();
    }
```

重点的判断逻辑是：

如果用户的登录失败次数>=5次，并且，（当前时间-上次登录失败的时间）>300s，将会将用户登录失败的次数重新设置为0。

函数最后一行是内部类的方法，将 failures += 1，并将 lastFailureTime置为当前时间：

![img](https://oss.javasec.org/images/image-20200924190259639.png)

由此可知，在5分钟之内同一账户登陆失败5次以上，`LockOutRealm` 将会封锁用户，在未来5分钟之内没有新的登陆失败的情况，会从0开始重新计数，因此这种方式是能够一定程度缓解系统受到的暴力破解攻击的。
