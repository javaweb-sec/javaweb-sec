<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="org.dom4j.Document" %>
<%@ page import="org.dom4j.io.OutputFormat" %>
<%@ page import="org.dom4j.io.SAXReader" %>
<%@ page import="org.dom4j.io.XMLWriter" %>
<%@ page import="java.io.StringReader" %>
<%
    //    String str = "<data xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"/etc/passwd\"></xi:include></data>";
//        String str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE test [<!ELEMENT test ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><root><name>&xxe;</name></root>";
//        out.print(str);
//    String str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE test [<!ELEMENT test ANY ><!ENTITY xxe SYSTEM \"file:///////Users\" >]><root><name>&xxe;</name></root>";
//
//    String str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE test [<!ELEMENT test ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><root><name>&xxe;</name></root>";

    String str = request.getParameter("str");
    if (str != null && !"".equals(str)) {
        SAXReader    reader = new SAXReader();
        StringReader in     = new StringReader(str);
        Document     doc    = reader.read(in);
        OutputFormat format = OutputFormat.createPrettyPrint();
        format.setEncoding("UTF-8");

        XMLWriter writer = new XMLWriter(out, format);
        writer.write(doc);
        writer.flush();
        writer.close();
    }
%>