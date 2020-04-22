<%@ page import="org.apache.commons.fileupload.FileItemIterator" %>
<%@ page import="org.apache.commons.fileupload.FileItemStream" %>
<%@ page import="org.apache.commons.fileupload.FileUploadException" %>
<%@ page import="org.apache.commons.fileupload.servlet.ServletFileUpload" %>
<%@ page import="org.apache.commons.fileupload.util.Streams" %>
<%@ page import="java.io.IOException" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%
    if (ServletFileUpload.isMultipartContent(request)) {
        ServletFileUpload fileUpload = new ServletFileUpload();

        try {
            FileItemIterator fileItemIterator = fileUpload.getItemIterator(request);

            while (fileItemIterator.hasNext()) {
                FileItemStream fileItemStream = fileItemIterator.next();
                String         fieldName      = fileItemStream.getFieldName();// 字段名称

                if (fileItemStream.isFormField()) {
                    String fieldValue = Streams.asString(fileItemStream.openStream());// 字段值
                    out.println(fieldName + "=" + fieldValue);
                } else {
                    out.println(fieldName + "=" + fileItemStream.getName());
                }
            }
        } catch (FileUploadException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
%>