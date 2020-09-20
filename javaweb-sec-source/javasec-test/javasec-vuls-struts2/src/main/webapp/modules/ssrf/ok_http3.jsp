<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="okhttp3.Call" %>
<%@ page import="okhttp3.OkHttpClient" %>
<%@ page import="okhttp3.Request" %>
<%@ page import="okhttp3.Response" %>
<%@ page import="java.io.IOException" %>

<%
    String url = request.getParameter("url");
    OkHttpClient okHttpClient = new OkHttpClient();
    Request rq = new Request.Builder()
            .url(url)
            .get()
            .build();

    Call call = okHttpClient.newCall(rq);

    try {
        Response rb = call.execute();
        out.println(rb.body().string());
    } catch (IOException e) {
        e.printStackTrace();
    }
%>