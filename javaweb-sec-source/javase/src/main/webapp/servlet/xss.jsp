<%@ page contentType="text/html; charset=UTF-8" %>

<%-- xss.jsp?input=%3cscript%3ealert(1)%3c%2fscript%3e --%>
<%
    String input = request.getParameter("input");

    if (input != null) {
        try {
            out.println(input);
        } catch (Exception e) {
            out.print(e);
        }
    }
%>

