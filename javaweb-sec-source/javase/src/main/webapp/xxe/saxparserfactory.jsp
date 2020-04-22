<%@ page import="org.xml.sax.SAXException" %>
<%@ page import="org.xml.sax.helpers.DefaultHandler" %>
<%@ page import="javax.xml.parsers.SAXParser" %>
<%@ page import="javax.xml.parsers.SAXParserFactory" %>
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
    SAXParserFactory factory = SAXParserFactory.newInstance();
    SAXParser saxParser = factory.newSAXParser();
    SAXHandel handel = new SAXHandel();
    saxParser.parse(request.getInputStream(), handel);
    out.write(handel.value);
%>