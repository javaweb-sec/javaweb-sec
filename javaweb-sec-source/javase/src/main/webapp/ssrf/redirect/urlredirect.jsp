<%@ page import="java.net.HttpURLConnection" %>
<%@ page import="java.net.URL" %>

<%
    String url = request.getParameter("url");
    URL u = new URL(url);
    HttpURLConnection connection = (HttpURLConnection) u.openConnection();
    connection.setInstanceFollowRedirects(false);
    connection.setConnectTimeout(5000);
    connection.setReadTimeout(5000);
    int code = connection.getResponseCode();

    if (code == 302) {
        String redirectUrl = connection.getHeaderField("Location");
        if (redirectUrl != null && !redirectUrl.isEmpty()) {
            url = redirectUrl;
        }
    }
%>