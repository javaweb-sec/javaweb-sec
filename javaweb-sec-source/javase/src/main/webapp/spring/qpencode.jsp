<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<body>

<form action="<%= request.getContextPath()+"/upload.php"%>" method="post" enctype="multipart/form-data">

    文件名：=?UTF-8?Q?=E6=B5=8B=E8=AF=95=2Ejsp?= 测试.jsp
    <br>
    <label for="file">Filename:</label>
    <input type="file" name="file" id="file"/> <br/>
    <input type="text" name="username"/>
    <input type="submit" name="submit" value="Submit"/>
</form>

</body>
</html>
