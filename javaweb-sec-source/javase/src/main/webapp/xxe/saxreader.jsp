<%@ page import="org.dom4j.Document" %>
<%@ page import="org.dom4j.Element" %>
<%@ page import="org.dom4j.io.SAXReader" %>
<%@ page import="java.util.List" %>
<%
    try {
        SAXReader reader = new SAXReader();
        Document document = reader.read(request.getInputStream());
        Element root = document.getRootElement();
        System.out.println(root.getDocument());
    } catch (Exception e) {
        e.printStackTrace();
    }
%>