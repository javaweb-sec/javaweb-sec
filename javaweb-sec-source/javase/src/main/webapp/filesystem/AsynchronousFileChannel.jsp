<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.nio.ByteBuffer" %>
<%@ page import="java.nio.channels.AsynchronousFileChannel" %>
<%@ page import="java.nio.file.Path" %>
<%@ page import="java.nio.file.Paths" %>
<%@ page import="java.nio.file.StandardOpenOption" %>
<%@ page import="java.util.concurrent.Future" %>
<%
    Path path = Paths.get(request.getParameter("file"));

    AsynchronousFileChannel fileChannel = AsynchronousFileChannel.open(path, StandardOpenOption.READ);

    ByteBuffer buffer = ByteBuffer.allocate(1024);
    long position = 0;

    Future<Integer> operation = fileChannel.read(buffer, position);

    while (!operation.isDone()) {
        buffer.flip();
        byte[] data = new byte[buffer.limit()];
        buffer.get(data);

        out.write(new String(data));
        buffer.clear();
    }

%>