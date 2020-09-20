<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="org.apache.commons.fileupload.FileItemIterator" %>
<%@ page import="org.apache.commons.fileupload.FileItemStream" %>
<%@ page import="org.apache.commons.fileupload.servlet.ServletFileUpload" %>
<%@ page import="org.apache.commons.fileupload.util.Streams" %>
<%@ page import="java.io.File" %>
<%@ page import="java.io.FileOutputStream" %>
<%
    if (ServletFileUpload.isMultipartContent(request)) {
        ServletFileUpload fileUpload       = new ServletFileUpload();
        FileItemIterator  fileItemIterator = fileUpload.getItemIterator(request);

        String dir       = request.getServletContext().getRealPath("/uploads/");
        File   uploadDir = new File(dir);

        if (!uploadDir.exists()) {
            uploadDir.mkdir();
        }

        while (fileItemIterator.hasNext()) {
            FileItemStream fileItemStream = fileItemIterator.next();
            String         fieldName      = fileItemStream.getFieldName();// 字段名称

            if (fileItemStream.isFormField()) {
                String fieldValue = Streams.asString(fileItemStream.openStream());// 字段值
                out.println(fieldName + "=" + fieldValue);
            } else {
                String fileName   = fileItemStream.getName();
                File   uploadFile = new File(uploadDir, fileName);
                out.println(fieldName + "=" + fileName);
                FileOutputStream fos = new FileOutputStream(uploadFile);

                // 写文件
                Streams.copy(fileItemStream.openStream(), fos, true);

                out.println("文件上传成功:" + uploadFile.getAbsolutePath());
            }
        }
    } else {
%>
<!DOCTYPE html>
<html lang="en">
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