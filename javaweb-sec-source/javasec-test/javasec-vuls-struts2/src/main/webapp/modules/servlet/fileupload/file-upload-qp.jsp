<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="javax.mail.internet.MimeUtility" %>
<%
    String qp = request.getParameter("qp");
    String encode = MimeUtility.encodeWord(qp);
    String decode = MimeUtility.decodeWord(encode);

    out.println("<pre>\nQP-Encoding: " + encode + "\nQP-Decode: " + decode);
%>