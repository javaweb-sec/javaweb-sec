<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>getQueryString XSS 测试</title>
</head>
<body>
<%= request.getQueryString()%>
</body>
</html>
