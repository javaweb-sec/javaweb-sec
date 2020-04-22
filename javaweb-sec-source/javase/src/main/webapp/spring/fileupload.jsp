<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<body>

<form action="<%= request.getContextPath()+"/upload.php"%>" method="post" enctype="multipart/form-data">

    <label for="file">Filename:</label>
    <input type="file" name="file" id="file"/> <br/>
    <input type="text" name="username"/>
    <input type="submit" name="submit" value="Submit"/>
</form>

</body>
</html>