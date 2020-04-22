<%@ page import="javax.xml.transform.stream.StreamSource" %>
<%@ page import="javax.xml.validation.Schema" %>
<%@ page import="javax.xml.validation.SchemaFactory" %>
<%@ page import="javax.xml.validation.Validator" %>
<%
    SchemaFactory factory = SchemaFactory.newInstance("http://www.w3.org/2001/XMLSchema");
    Schema schema = factory.newSchema();
    Validator validator = schema.newValidator();

    StreamSource source = new StreamSource(request.getInputStream());
    validator.validate(source);
%>