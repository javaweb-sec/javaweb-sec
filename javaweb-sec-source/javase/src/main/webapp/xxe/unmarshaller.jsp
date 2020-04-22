<%@ page import="javax.xml.bind.JAXBContext" %>
<%@ page import="javax.xml.bind.Unmarshaller" %>
<%!
    static class A {

        private String root;

        public String getRoot() {
            return root;
        }

        public void setRoot(String root) {
            this.root = root;
        }
    }
%>

<%
    Class tClass = A.class;
    JAXBContext context = JAXBContext.newInstance(tClass);
    Unmarshaller um = context.createUnmarshaller();

    Object o = um.unmarshal(request.getInputStream());
    tClass.cast(o);
%>