<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>header XSS 测试</title>
</head>
<body>
获取 header 中的键值，此例使用了User-Agent
<br>
<%= request.getHeader("User-Agent") == null ? "" : request.getHeader("User-Agent")%>
</body>
</html>
