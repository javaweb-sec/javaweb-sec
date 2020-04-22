<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>扫描器特征拦截</title>
</head>
<body>
请修改扫描器常用 User-Agent 后访问此页面。
例如：<br>
Mozilla/5.0 (Linux; U; Android 7.0; zh-CN; PRO 7-S Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0
Chrome/57.0.2987.108 UCBrowser/11.9.4.974 UWS/2.13.2.46 Mobile Safari/537.36 AliApp(DingTalk/4.6.29)
com.alibaba.android.rimet/11388461 Channel/10002068 language/zh-CN<br>
acunetix_wvs_security_test<br>
sqlmap/1.0-dev (http://sqlmap.org)<br>
<%
    out.write("当前浏览器UA:");
    out.write(request.getHeader("User-Agent"));
%>
</body>
</html>
