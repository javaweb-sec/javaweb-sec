<%@ page import="org.apache.http.HttpEntity" %>
<%@ page import="org.apache.http.ParseException" %>
<%@ page import="org.apache.http.client.methods.CloseableHttpResponse" %>
<%@ page import="org.apache.http.client.methods.HttpGet" %>
<%@ page import="org.apache.http.impl.client.CloseableHttpClient" %>
<%@ page import="org.apache.http.impl.client.HttpClientBuilder" %>
<%@ page import="org.apache.http.util.EntityUtils" %>
<%@ page import="java.io.IOException" %>

<%-- _httpclient.jsp?url=http://burpcollaborator.net --%>
<%

    CloseableHttpClient httpClient = HttpClientBuilder.create().build();

    // 创建Get请求
    HttpGet httpGet = new HttpGet(request.getParameter("url"));

    // 响应模型
    CloseableHttpResponse res = null;

    try {
        // 由客户端执行(发送)Get请求
        res = httpClient.execute(httpGet);
        // 从响应模型中获取响应实体
        HttpEntity responseEntity = res.getEntity();
        if (responseEntity != null) {
            out.write(EntityUtils.toString(responseEntity));
        }
    } catch (ParseException | IOException e) {
        e.printStackTrace();
    } finally {
        try {
            // 释放资源
            if (httpClient != null) {
                httpClient.close();
            }
            if (res != null) {
                res.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
%>