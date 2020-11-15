<%@ page contentType="text/html;charset=UTF-8" language="java" %>
Date: <span style="color: red;"></span>
<input type="hidden" value="<%=request.getParameter("date")%>" />
<script>
    var date = document.getElementsByTagName("input")[0].value;
    document.getElementsByTagName("span")[0].innerHTML = date;
</script>