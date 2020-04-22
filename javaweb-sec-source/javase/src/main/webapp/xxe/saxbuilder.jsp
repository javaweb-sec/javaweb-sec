<%@ page import="org.jdom.Content" %>
<%@ page import="org.jdom.Document" %>
<%@ page import="org.jdom.Element" %>
<%@ page import="org.jdom.input.SAXBuilder" %>
<%@ page import="java.util.List" %>
<%
    SAXBuilder saxBuilder = new SAXBuilder();

    Document document = saxBuilder.build(request.getInputStream());
    Element element = document.getRootElement();
    List<Content> contents = element.getContent();
    for (Content content : contents) {
        out.write(content.getValue());
    }
%>