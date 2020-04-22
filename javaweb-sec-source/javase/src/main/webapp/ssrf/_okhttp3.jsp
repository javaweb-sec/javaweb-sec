<%@ page import="okhttp3.Call" %>
<%@ page import="okhttp3.OkHttpClient" %>
<%@ page import="okhttp3.Request" %>
<%@ page import="okhttp3.Response" %>
<%@ page import="java.io.IOException" %>

<%-- _okhttp3.jsp?url=http://burpcollaborator.net --%>
<%
    String url = request.getParameter("url");
    OkHttpClient okHttpClient = new OkHttpClient();
    final Request rq = new Request.Builder()
            .url(url)
            .get()
            .build();

    final Call call = okHttpClient.newCall(rq);

    try {
        Response rb = call.execute();
        out.println(rb.body().string());

    } catch (IOException e) {
        e.printStackTrace();
    }

%>