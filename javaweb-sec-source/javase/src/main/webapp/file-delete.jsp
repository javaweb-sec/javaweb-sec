<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.File" %>
<%
    String fileName = request.getParameter("file");

    if (fileName != null) {
        // 创建文件对象
        File file = new File(fileName);

        if (file.exists()) {
            file.delete();// 删除文件

            out.println(fileName + "删除成功!");
        } else {
            out.println("文件不存在!");
        }
    }
%>