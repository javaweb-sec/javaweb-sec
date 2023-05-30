# Web Service

`Web Service`是一种基于`SOAP协议`实现的跨语言Web服务调用，在Java中`Web Service`有如下技术实现:`Oracle JWS`、`Apache Axis1、2`、`XFire`、`Apache CXF`、`JBossWS`。

## Axis1.4 配置

`web.xml`配置`Axis1.4`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">

    <servlet>
        <display-name>Apache-Axis Servlet</display-name>
        <servlet-name>AxisServlet</servlet-name>
        <servlet-class>org.apache.axis.transport.http.AxisServlet</servlet-class>
    </servlet>

    <servlet>
        <display-name>Axis Admin Servlet</display-name>
        <servlet-name>AdminServlet</servlet-name>
        <servlet-class>org.apache.axis.transport.http.AdminServlet</servlet-class>
        <load-on-startup>100</load-on-startup>
    </servlet>

    <servlet>
        <display-name>SOAPMonitorService</display-name>
        <servlet-name>SOAPMonitorService</servlet-name>
        <servlet-class>org.apache.axis.monitor.SOAPMonitorService</servlet-class>
        <init-param>
            <param-name>SOAPMonitorPort</param-name>
            <param-value>5101</param-value>
        </init-param>
        <load-on-startup>100</load-on-startup>
    </servlet>

    <servlet-mapping>
        <servlet-name>AxisServlet</servlet-name>
        <url-pattern>/servlet/AxisServlet</url-pattern>
    </servlet-mapping>

    <servlet-mapping>
        <servlet-name>AxisServlet</servlet-name>
        <url-pattern>*.jws</url-pattern>
    </servlet-mapping>

    <servlet-mapping>
        <servlet-name>AxisServlet</servlet-name>
        <url-pattern>/services/*</url-pattern>
    </servlet-mapping>

    <servlet-mapping>
        <servlet-name>SOAPMonitorService</servlet-name>
        <url-pattern>/SOAPMonitor</url-pattern>
    </servlet-mapping>

    <servlet-mapping>
        <servlet-name>AdminServlet</servlet-name>
        <url-pattern>/servlet/AdminServlet</url-pattern>
    </servlet-mapping>

    <mime-mapping>
        <extension>wsdl</extension>
        <mime-type>text/xml</mime-type>
    </mime-mapping>
</web-app>
```

配置`WEB-INF/server-config.wsdd`文件注册`Web Service`服务类和方法：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<deployment xmlns="http://xml.apache.org/axis/wsdd/" xmlns:java="http://xml.apache.org/axis/wsdd/providers/java">
    <globalConfiguration>
        <parameter name="sendMultiRefs" value="true"/>
        <parameter name="disablePrettyXML" value="true"/>
        <parameter name="adminPassword" value="admin"/>
        <parameter name="dotNetSoapEncFix" value="true"/>
        <parameter name="enableNamespacePrefixOptimization" value="false"/>
        <parameter name="sendXMLDeclaration" value="true"/>
        <parameter name="sendXsiTypes" value="true"/>
        <parameter name="attachments.implementation" value="org.apache.axis.attachments.AttachmentsImpl"/>

        <requestFlow>
            <handler type="java:org.apache.axis.handlers.JWSHandler">
                <parameter name="scope" value="session"/>
            </handler>
            <handler type="java:org.apache.axis.handlers.JWSHandler">
                <parameter name="scope" value="request"/>
                <parameter name="extension" value=".jwr"/>
            </handler>
        </requestFlow>
    </globalConfiguration>

    <handler name="LocalResponder" type="java:org.apache.axis.transport.local.LocalResponder"/>
    <handler name="URLMapper" type="java:org.apache.axis.handlers.http.URLMapper"/>
    <handler name="Authenticate" type="java:org.apache.axis.handlers.SimpleAuthenticationHandler"/>

    <service name="AdminService" provider="java:MSG">
        <parameter name="allowedMethods" value="AdminService"/>
        <parameter name="enableRemoteAdmin" value="true"/>
        <parameter name="className" value="org.apache.axis.utils.Admin"/>
        <namespace>http://xml.apache.org/axis/wsdd/</namespace>
    </service>

    <service name="Version" provider="java:RPC">
        <parameter name="allowedMethods" value="getVersion"/>
        <parameter name="className" value="org.apache.axis.Version"/>
    </service>

    <service name="SOAPMonitorService" provider="java:RPC">
        <parameter name="allowedMethods" value="publishMessage"/>
        <parameter name="scope" value="Application"/>
        <parameter name="className" value="org.apache.axis.monitor.SOAPMonitorService"/>
    </service>

    <service name="TestService" provider="java:RPC">
        <parameter name="className" value="com.anbai.sec.axis.TestService"/>
        <parameter name="allowedMethods" value="*"/>
    </service>

    <service name="FileService" provider="java:RPC">
        <parameter name="className" value="com.anbai.sec.axis.FileService"/>
        <parameter name="allowedMethods" value="readFile,writeFile"/>
    </service>

    <handler name="soapmonitor" type="java:org.apache.axis.handlers.SOAPMonitorHandler">
        <parameter name="wsdlURL" value="/axis/SOAPMonitorService-impl.wsdl"/>
        <parameter name="serviceName" value="SOAPMonitorService"/>
        <parameter name="namespace" value="http://tempuri.org/wsdl/2001/12/SOAPMonitorService-impl.wsdl"/>
        <parameter name="portName" value="Demo"/>
    </handler>

    <transport name="http">
        <requestFlow>
            <handler type="URLMapper"/>
            <handler type="java:org.apache.axis.handlers.http.HTTPAuthHandler"/>
            <!--comment following line for REMOVING wsdl spying via SOAPMonitor-->
            <handler type="soapmonitor"/>
        </requestFlow>
        <responseFlow>
            <!--comment following line for REMOVING wsdl spying via SOAPMonitor-->
            <handler type="soapmonitor"/>
        </responseFlow>

        <parameter name="qs:list" value="org.apache.axis.transport.http.QSListHandler"/>
        <parameter name="qs:wsdl" value="org.apache.axis.transport.http.QSWSDLHandler"/>
        <parameter name="qs.list" value="org.apache.axis.transport.http.QSListHandler"/>
        <parameter name="qs.method" value="org.apache.axis.transport.http.QSMethodHandler"/>
        <parameter name="qs:method" value="org.apache.axis.transport.http.QSMethodHandler"/>
        <parameter name="qs.wsdl" value="org.apache.axis.transport.http.QSWSDLHandler"/>
    </transport>

    <transport name="local">
        <responseFlow>
            <handler type="LocalResponder"/>
        </responseFlow>
    </transport>
</deployment>
```

`FileService`类，提供了文件读写接口：

```java
package com.anbai.sec.axis;

import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;

/**
 * @author yz
 */
public class FileService {

    public String readFile(String path) {
        if (path != null && !"".equals(path)) {
            File file = new File(path);

            if (file.exists()) {
                try {
                    return FileUtils.readFileToString(file, "UTF-8");
                } catch (IOException e) {
                    return "读取文件:" + file + "异常:" + e;
                }
            } else {
                return "文件:" + file + "不存在!";
            }
        } else {
            return "path不能为空!";
        }
    }

    public String writeFile(String path, String content) {
        if (path != null && !"".equals(path)) {
            File file = new File(path);

            try {
                FileUtils.writeStringToFile(file, content, "UTF-8");

                return file.getAbsolutePath();
            } catch (IOException e) {
                return "写文件:" + file + "异常:" + e;
            }
        }

        return "path不能为空!";
    }

    public String test() {
        return "文件WebService测试~";
    }

}
```

使用IDEA创建`Web Service`项目默认会创建管理`Web Service`的API:`/servlet/AxisServlet`、`/services`、`SOAPMonitor`、`/servlet/AdminServlet`，`*.jws`以及用监控`Web Service`的端口`5001`或`5101`。

![img](https://oss.javasec.org/images/image-20201112113542471.png)

访问`Web Service`的`FileService`服务加上`?wsdl`参数可以看到`FileService`提供的服务方法和具体的参数信息。

![img](https://oss.javasec.org/images/image-20201112113717152.png)

使用SOAP-UI调用`Web Service`接口示例：

![img](https://oss.javasec.org/images/24.png)

需要注意的是`Web Service`也是可以设置授权认证的,如实现了`WS-Security`的`WSS4J`。

![img](https://oss.javasec.org/images/29.png)

使用IDEA根据wsdl生成`Web Service`客户端代码：

![img](https://oss.javasec.org/images/image-20201112114841669.png)

设置wsdl地址、包名:

![img](https://oss.javasec.org/images/image-20201112114951164.png)

新建`FileServiceTest`类测试接口调用:

```java
package com.anbai.sec.axis.client;

import java.net.URL;

/**
 * 文件Web Service服务测试
 *
 * @author yz
 */
public class FileServiceTest {

    public static void main(String[] args) {
        try {
            FileServiceService         fileService   = new FileServiceServiceLocator();
            URL                        webServiceUrl = new URL("http://localhost:8080/services/FileService");
            FileServiceSoapBindingStub soapService   = new FileServiceSoapBindingStub(webServiceUrl, fileService);

            String content = soapService.readFile("/etc/passwd");

            System.out.println(content);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
```

参考:

1. [axis2 利用小工具cat.aar](http://javaweb.org/?p=1548)
2. [Axis1.4框架 实现webservice服务器和客户端](https://www.cnblogs.com/dls-java/p/5038128.html)
3. [使用IDEA根据wsdl生成WebServices客户端代码-Java](https://blog.csdn.net/vfsdfdsf/article/details/80426276)
