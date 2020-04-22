<%@ page import="com.squareup.okhttp.OkHttpClient" %>
<%@ page import="com.squareup.okhttp.Request" %>
<%@ page import="com.squareup.okhttp.Response" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>

<%-- _okhttp.jsp?url=http://burpcollaborator.net --%>
<%!
    public String httpGet(String url) {
        String       result  = "";
        OkHttpClient client  = new OkHttpClient();
        Request      request = new Request.Builder().url(url).build();

        try {
            Response response = client.newCall(request).execute();
            result = response.body().string();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return result;
    }
%>
<%
    String urlString = request.getParameter("url");

    if (urlString != null) {
        String result = httpGet(urlString);
        out.write(result);
    }
%>
