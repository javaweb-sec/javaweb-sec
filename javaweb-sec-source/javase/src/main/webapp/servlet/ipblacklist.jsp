<%@ page contentType="text/html;charset=UTF-8" language="java" %>

<html>
<head>
    <title>黑名单 IP 测试</title>
</head>
<body>
请在配置文件配置"黑名单IP"，并使用此 IP 对（任意）页面进行访问。
当前访问者 IP 为：<%= request.getRemoteAddr()%>
</body>
</html>
