<%--
  Created by IntelliJ IDEA.
  User: phoebe
  Date: 2020/3/26
  Time: 3:44 下午
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>File upload</title>
</head>
<body>
<form action="<%= request.getContextPath()+"/FilePartUpload" %>" enctype="multipart/form-data" method="post">
    <label for="file">Filename:</label>
    用户名: <input name="username" type="text"/>
    <input id="file" name="file" type="file"/>
    <br/>
    <input name="submit" type="submit" value="Submit"/>
</form>
</body>
</html>
