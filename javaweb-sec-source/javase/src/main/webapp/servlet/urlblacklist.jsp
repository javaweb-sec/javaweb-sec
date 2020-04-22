<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>URL 黑名单测试</title>
</head>
<body>
请将此页面设为黑名单后，再进行访问。当前 URL 为: <%= javax.servlet.http.HttpUtils.getRequestURL(request) %>

</body>
</html>
