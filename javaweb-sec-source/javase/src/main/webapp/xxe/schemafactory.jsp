<%@ page import="javax.xml.transform.stream.StreamSource" %>
<%@ page import="javax.xml.validation.Schema" %>
<%@ page import="javax.xml.validation.SchemaFactory" %>
<%
    SchemaFactory factory = SchemaFactory.newInstance("http://www.w3.org/2001/XMLSchema");

    StreamSource source = new StreamSource(request.getInputStream());
    Schema schema = factory.newSchema(source);
%>