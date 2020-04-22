<%@ page import="java.util.Arrays" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.util.Set" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>getParameterMap XSS 测试</title>
</head>
<body>
<%
    Map<String, String[]> paramMap = request.getParameterMap();
    Set<?> set = paramMap.entrySet();
    for (Object o : set) {
        Map.Entry<?, ?> mapEntry = (Map.Entry<?, ?>) o;
        out.write(mapEntry.getKey().toString());
        out.write(Arrays.toString((String[]) mapEntry.getValue()));
    }
%>
</body>
</html>
