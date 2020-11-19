<%@ page import="java.io.File" %><%--
  Created by IntelliJ IDEA.
  User: yz
  Date: 2019/12/4
  Time: 6:08 下午
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%!
    // 定义限制用户遍历的文件目录常量
    private static final String IMAGE_DIR = "/Users/yz/IdeaProjects/javaweb-sec/javaweb-sec-source/java-filesystem/src/main/webapp";
%>
<%
    // 定义需要遍历的目录
    String dirStr = request.getParameter("dir");

    if (dirStr != null) {
        File dir = new File(dirStr);

        // 获取文件绝对路径，转换成标准的文件路径
        String fileDir = (dir.getAbsoluteFile().getCanonicalFile() + "/").replace("\\\\", "/").replaceAll("/+", "/");
        out.println("<h3>" + fileDir + "</h3>");

        // 检查当前用户传入的目录是否包含在系统限定的目录下
        if (fileDir.startsWith(IMAGE_DIR)) {
            File[] dirs = dir.listFiles();

            out.println("<pre>");

            for (File file : dirs) {
                out.println(file.getName());
            }

            out.println("</pre>");
        } else {
            out.println("目录不合法!");
        }
    }

%>
