<%@ page import="org.xml.sax.InputSource" %>
<%@ page import="org.xml.sax.XMLReader" %>
<%@ page import="org.xml.sax.helpers.XMLReaderFactory" %>
<%@ page import="org.xml.sax.helpers.DefaultHandler" %>
<%@ page import="org.xml.sax.SAXException" %>
<%!
    class SAXHandel extends DefaultHandler {

        public String value;

        @Override
        public void characters(char ch[], int start, int length)
                throws SAXException {
            super.characters(ch, start, length);
            String value = new String(ch, start, length).trim();
            if (!value.equals("")) {
                this.value+=value;
            }
        }
    }
%>
<%
    try {
        XMLReader        reader = XMLReaderFactory.createXMLReader();
        SAXHandel mdh    = new SAXHandel();
        reader.setContentHandler(mdh);
        reader.parse(new InputSource(request.getInputStream()));
        out.write(mdh.value);
    } catch (SAXException e) {
        e.printStackTrace();
    }
%>