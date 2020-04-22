<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="com.alibaba.fastjson.JSON" %>
<%@ page import="com.alibaba.fastjson.parser.ParserConfig" %>

<%
    System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase", "true");
    ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
    String jsonStr = request.getParameter("json");

    Object obj = JSON.parseObject(jsonStr);

    out.println("Json String:" + jsonStr + "<br/>");
    out.println("Json Object:" + obj.toString() + "<br/>");


%>