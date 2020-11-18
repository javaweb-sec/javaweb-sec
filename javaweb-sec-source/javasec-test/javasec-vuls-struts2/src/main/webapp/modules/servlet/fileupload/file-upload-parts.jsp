<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="org.apache.commons.io.IOUtils" %>
<%@ page import="java.util.Collection" %>
<%@ page import="java.io.File" %>
<%
    String contentType = request.getContentType();

    // 检测是否是multipart请求
    if (contentType != null && contentType.startsWith("multipart/")) {
        String dir       = request.getSession().getServletContext().getRealPath("/uploads/");
        File   uploadDir = new File(dir);

        if (!uploadDir.exists()) {
            uploadDir.mkdir();
        }

        Collection<Part> parts = request.getParts();

        for (Part part : parts) {
            String fileName = part.getSubmittedFileName();

            if (fileName != null) {
                File uploadFile = new File(uploadDir, fileName);
                out.println(part.getName() + ": " + uploadFile.getAbsolutePath() + "<br/>");
            } else {
                out.println(part.getName() + ": " + IOUtils.toString(part.getInputStream()) + "<br/>");
            }
        }
    } else {
%>
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>File upload</title>
</head>
<body>
<form action="" enctype="multipart/form-data" method="post">
    <p>
        用户名: <input name="username" type="text"/>
        文件: <input id="file" name="file" type="file"/>
    </p>
    <input name="submit" type="submit" value="Submit"/>
</form>
</body>
</html>
<%
    }
%>