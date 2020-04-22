<%@ page import="org.apache.commons.httpclient.HttpClient" %>
<%@ page import="org.apache.commons.httpclient.HttpMethod" %>
<%@ page import="org.apache.commons.httpclient.URIException" %>
<%@ page import="org.apache.commons.httpclient.methods.GetMethod" %>
<%@ page import="java.io.IOException" %>
<%-- _commons_httpclient.jsp?url=http://burpcollaborator.net --%>
<%

    String url = request.getParameter("url");
    HttpClient client = new HttpClient();
    HttpMethod method = new GetMethod(url);

    try {
        client.executeMethod(method);
    } catch (URIException e) {
        out.write("执行HTTP Get请求时，发生异常！");
        return;
    } catch (IOException e) {
        out.write("执行HTTP Get请求" + url + "时，发生异常！");
        return;
    } finally {
        out.write(method.getResponseBodyAsString());
        method.releaseConnection();
    }

%>