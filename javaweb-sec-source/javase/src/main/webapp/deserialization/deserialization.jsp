<%@ page import="java.io.FileInputStream" %>
<%@ page import="java.io.ObjectInputStream" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>

<html>
<head>
    <title>Java 反序列化测试合集</title>
</head>
<body>
<div align="center">
    windows
    <br>
    <a href="deserialization.jsp?file=1">使用 commons-collections5 执行命令弹出计算器</a><br>
    <a href="deserialization.jsp?file=2">使用 commons-collections6 执行命令弹出计算器</a><br>
    <a href="deserialization.jsp?file=3">使用 commons-collections7 执行命令弹出计算器</a><br>
    <a href="deserialization.jsp?file=4">使用 jdk7 执行命令弹出计算器</a><br>
    <a href="deserialization.jsp?file=5">使用 groovy 执行命令弹出计算器</a><br>
</div>

<div align="center">
    linux
    <br>
    <a href="deserialization.jsp?file=6">使用 curl 访问本地 9000 端口</a><br>
    <a href="deserialization.jsp?file=7">使用 commons-collections5 执行 whoami</a><br>
    <a href="deserialization.jsp?file=8">使用 commons-collections6 执行 whoami</a><br>
    <a href="deserialization.jsp?file=9">使用 commons-collections7 执行 whoami</a><br>
    <a href="deserialization.jsp?file=10">使用 jdk7 执行命令创建文件 /tmp/1.txt</a><br>
    <a href="deserialization.jsp?file=11">使用 groovy 执行 whoami</a><br>
</div>
</body>
</html>
<%

    String filename = request.getParameter("file");
    if (filename != null) {
        switch (filename) {
            case "1":
                filename = "winc5.txt";
                break;
            case "2":
                filename = "winc6.txt";
                break;
            case "3":
                filename = "winc7.txt";
                break;
            case "4":
                filename = "winjdk7.txt";
                break;
            case "5":
                filename = "wingroovy.txt";
                break;
            case "6":
                filename = "curl8.bin";
                break;
            case "7":
                filename = "collections5.txt";
                break;
            case "8":
                filename = "collections6.txt";
                break;
            case "9":
                filename = "collections7.txt";
                break;
            case "10":
                filename = "jdk7.txt";
                break;
            case "11":
                filename = "groovy.txt";
                break;
        }
        try {
            if (filename != null) {
                FileInputStream fis = new FileInputStream(request.getSession().getServletContext().getRealPath("/modules/deserialization/" + filename));
                Object          obj = new ObjectInputStream(fis).readObject();
                out.println(obj);
            }

        } catch (Exception e) {
            out.write(e.fillInStackTrace().toString());
        }
    }


%>