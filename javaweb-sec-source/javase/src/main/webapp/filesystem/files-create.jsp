<%@ page import="java.io.IOException" %>
<%@ page import="java.nio.file.Files" %>
<%@ page import="java.nio.file.Paths" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%
    try {

        Files.createFile(Paths.get(request.getParameter("path")));
    } catch (IOException e) {
        e.printStackTrace();
    }
%>