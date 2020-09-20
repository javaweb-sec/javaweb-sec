<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.text.SimpleDateFormat" %>
<%@ page import="java.util.*" %>
<%
    String username = request.getParameter("username");
    String content = request.getParameter("content");

    String guestBookKey = "GUEST_BOOK";
    List<Map<String, String>> comments = new ArrayList<Map<String, String>>();

    if (content != null) {
        Object obj = application.getAttribute(guestBookKey);

        if (obj != null) {
            comments = (List<Map<String, String>>) obj;
        }

        Map<String, String> comment = new HashMap<String, String>();
        String              ip      = request.getHeader("x-real-ip");

        if (ip == null) {
            ip = request.getRemoteAddr();
        }

        comment.put("username", username);
        comment.put("content", content);
        comment.put("ip", ip);
        comment.put("date", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));

        comments.add(comment);

        application.setAttribute(guestBookKey, comments);
    }
%>
<html>
<head>
    <title>留言板</title>
</head>
<style>
    * {
        margin: 0;
        padding: 0;
    }
</style>
<body>
<div style="border: 1px solid #C6C6C6;">
    <div style="text-align: center;">
        <h2>在线留言板</h2>
    </div>
    <div>
        <dl>
            <%
                Object obj = application.getAttribute(guestBookKey);

                if (obj instanceof List) {
                    comments = (List<Map<String, String>>) obj;

                    for (Map<String, String> comment : comments) {
            %>
            <dd>
                <div style="min-height: 50px; margin: 20px; border-bottom: 1px solid #9F9F9F;">
                    <p><B><%=comment.get("username")%>
                    </B>[<%=comment.get("ip")%>] 于 <%=comment.get("date")%> 发表回复：</p>
                    <p style="margin: 15px 0 5px 0; font-size: 12px;">
                    <pre><%=comment.get("content")%></pre>
                    </p>
                </div>
            </dd>
            <%
                    }
                }
            %>
        </dl>
    </div>
    <div style="background-color: #fff; border: 1px solid #C6C6C6;">
        <form action="#" method="POST" style="margin: 20px;">
            昵称: <input type="text" name="username" style="width:250px; height: 28px;"/><br/><br/>
            <textarea name="content" style="overflow: auto;width: 100%; height: 250px;"></textarea>
            <input type="submit" value="提交留言" style="margin-top: 20px; width: 80px; height: 30px;"/>
        </form>
    </div>
</div>
</body>
</html>
