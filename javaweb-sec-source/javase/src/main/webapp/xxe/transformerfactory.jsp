<%@ page import="javax.xml.transform.TransformerFactory" %>
<%@ page import="javax.xml.transform.dom.DOMResult" %>
<%@ page import="javax.xml.transform.stream.StreamSource" %>
<%
    TransformerFactory tf = TransformerFactory.newInstance();

    StreamSource source = new StreamSource(request.getInputStream());
    DOMResult domResult = new DOMResult();
    tf.newTransformer().transform(source, domResult);
%>