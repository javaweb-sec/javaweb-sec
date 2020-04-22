<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="com.alibaba.fastjson.JSON" %>
<%@ page import="com.alibaba.fastjson.TypeReference" %>
<%@ page import="java.nio.file.Files" %>
<%@ page import="java.nio.file.Paths" %>
<%@ page import="java.util.Map" %>
<pre>
<%
    Map<String, Object> json = JSON.parseObject(
            request.getInputStream(), new TypeReference<Map<String, Object>>() {
            }.getType()
    );

    String path = (String) json.get("path");

    byte[] bytes = Files.readAllBytes(Paths.get(path));
    out.println(new String(bytes));
%>
</pre>