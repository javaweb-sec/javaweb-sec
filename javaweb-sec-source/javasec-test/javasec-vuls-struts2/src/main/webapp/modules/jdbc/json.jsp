<%@ page contentType="text/html;charset=UTF-8" pageEncoding="UTF-8" %>
<%@ page import="java.io.FileInputStream" %>
<%@ page import="java.sql.*" %>
<%@ page import="java.util.Properties" %>

<%! String runQuery(String id) throws SQLException {
    Connection conn = null;
    Statement  stmt = null;
    ResultSet  rset = null;
    try {
        Properties pro = new Properties();
        pro.load(new FileInputStream(this.getClass().getClassLoader().getResource("/").getPath() + "config/jdbc.properties"));
        String driver   = pro.getProperty("jdbc.driver");
        String url      = pro.getProperty("jdbc.url");
        String username = pro.getProperty("jdbc.username");
        String password = pro.getProperty("jdbc.password");

        Class.forName(driver);
        conn = DriverManager.getConnection(url, username, password);
        stmt = conn.createStatement();
        rset = stmt.executeQuery("select post_content from sys_posts where post_id =" + id);
        return (formatResult(rset));
    } catch (Exception e) {
        return ("<P> Error: <PRE> " + e + " </PRE> </P>\n");
    } finally {
        if (rset != null) rset.close();
        if (stmt != null) stmt.close();
        if (conn != null) conn.close();
    }
}

    String formatResult(ResultSet rset) throws SQLException {
        StringBuffer sb = new StringBuffer();
        if (!rset.next()) {
            sb.append("<P> No matching rows.<P>\n");
        } else {
            do {
                sb.append(rset.getString(1) + "\n");
            } while (rset.next());
        }
        return sb.toString();
    }
%>

<%
    String id = null;
    String content_type = request.getContentType();
    if (content_type != null && content_type.indexOf("application/json") != -1) {
        int    size     = request.getContentLength();
        String postdata = null;
        if (size > 0) {
            byte[] buf = new byte[size];
            try {
                request.getInputStream().read(buf);
                postdata = new String(buf);
                if (postdata != null) {
                    net.sf.json.JSONObject json = net.sf.json.JSONObject.fromObject(postdata);
                    if (json != null) {
                        id = json.getString("id");
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    } else if (request.getParameter("id") != null) {
        id = request.getParameter("id");
    } else {
        id = "1";
    }
    String escid = id.replaceAll("'", "&#39;");
%>
<script>
    function GetUrlRelativePath() {
        var url = document.location.toString();
        var arrUrl = url.split("//");
        var start = arrUrl[1].indexOf("/");
        var relUrl = arrUrl[1].substring(start);
        if (relUrl.indexOf("?") != -1) {
            relUrl = relUrl.split("?")[0];
        }
        return relUrl;
    }

    function getXMLHttpRequest() {
        var xmlhttp;
        if (window.XMLHttpRequest) {
            xmlhttp = new XMLHttpRequest();
        } else {
            xmlhttp = new ActiveXObject("Microsoft.XMLHTTP");
        }
        return xmlhttp;
    }

    function send_json() {
        var data = document.getElementById("jsoninput").value;
        var xmlhttp = getXMLHttpRequest();
        xmlhttp.onreadystatechange = function () {
            if (xmlhttp.readyState == 4 && xmlhttp.status == 200) {
                document.body.innerHTML = "";
                document.write(xmlhttp.responseText);
            }
        }
        url = GetUrlRelativePath()
        xmlhttp.open("POST", url, true);
        xmlhttp.setRequestHeader("Content-type", "application/json;charset=UTF-8");
        xmlhttp.send(data);
    }

</script>
<form>
    <div class="form-group">
        <label>JSON 方式查询</label>
        <input id="jsoninput" class="form-control" name="id" value='{"id":"<%=escid%>"}'>
    </div>
    <button type="button" onclick="send_json()" class="btn btn-primary">JSON 方式提交查询</button>
</form>

<%= runQuery(id) %>