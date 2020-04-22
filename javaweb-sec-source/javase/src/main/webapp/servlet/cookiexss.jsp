<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>Title</title>
</head>
<body>
<div>
    <div>测试此页面后，请先清除 COOKIE 再进行新的测试</div>
    <input type="text" id="inputValue">
    <button onclick="btn()">提交</button>
    <br>
    例如：PHPSESSIONID=1qaz@WSX3edc
    <br>
</div>


<script>
    function btn() {
        let id = document.getElementById('inputValue');
        document.cookie = id.value;
        window.location.reload(true);
    }
</script>

<span>Cookie():<%

    Cookie[] cookie = request.getCookies();
    if (cookie != null) {
        for (Cookie cookie1 : cookie) {
            out.write("<br>");
            out.write(cookie1.getName() + ":" + cookie1.getValue());

        }
    }
%></span>
</body>
</html>
