<%@ page import="java.text.SimpleDateFormat" %>
<%@ page import="java.util.Date" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html lang="zh-cn">
<head>
    <title>AnBai Search</title>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1">
</head>
<style>
    * {margin: 0;padding: 0;}
    a {color: #29bed4;text-decoration: none;}
    a:hover {color: #42d9ef;text-decoration: none;}
    em {font-style: normal;font-weight: normal;color: #dd4b39;}
    button,input,select,textarea {font: inherit;}
    button,input[type="button"],input[type="submit"] {border: none;cursor: pointer;margin: 0;padding: 0;}
    input {outline: none;}
    html,body {color: #444;font: 13px Verdana, "Microsoft YaHei", SimSun;width: 100%;height: 100%;*overflow: auto;position: relative;}
    .search_form {position: fixed;width: 100%;}
    .logo {background: url("./logo.png") no-repeat;display: inline-block;float: left;height: 58px;width: 210px;}
    .header {background-color: #f1f1f1;background-image: -webkit-gradient(radial, 100 36, 0, 100 -40, 120, from(#fafafa), to(#f1f1f1));min-width: 960px;height: 58px;}
    .header .keyword {width: 35%;height: 20px;outline: none;margin-top: 15px;padding: 4px 0 2px 5px;}
    .header .btnBlue-s {width: 80px;-webkit-border-radius: 3px;-moz-border-radius: 3px;border-radius: 3px;}
    .result_warp {padding-top: 65px;}
    .type_tab {line-height: 36px;height: 38px;float: none;padding-left: 210px;border-bottom: 1px #f8f8f8 solid;min-width: 600px;zoom: 1;}
    .type_tab a {display: inline-block;text-decoration: none;text-align: center;color: #666;font-size: 14px;}
    .type_tab a, .type_tab b {min-width: 60px;display: inline-block;text-decoration: none;text-align: center;color: #666;font-size: 14px;}
    .type_tab a:hover {background: -webkit-linear-gradient(top, #eee, #e0e0e0);-webkit-box-shadow: inset 0 1px 2px 0 rgba(0, 0, 0, 0.1);box-shadow: inset 0 1px 2px 0 rgba(0, 0, 0, 0.1);}
    .s_bar {margin: 0 0 0 210px;height: 42px;line-height: 42px;font-size: 12px;min-width: 500px;color: #999;}
    .search_content a {line-height: 23px;color: #0000cc;text-decoration: underline;}
    .btnBlue-s {background: #29bed4;-webkit-box-shadow: 1px 1px 1px 0 rgba(190, 190, 190, 0.75);box-shadow: 1px 1px 1px 0 rgba(190, 190, 190, 0.75);color: #fff;display: inline-block;font-size: 14px;height: 28px;line-height: 28px;padding: 0 16px;}
    .search_content {padding-left: 210px;width: 600px;}
    .footer {position: fixed;bottom: 0;width: 100%;background: #f5f6f5;border-top: 1px solid #ebebeb;height: 42px;line-height: 42px;}
    .footer .copyright {text-align: center;}
    .footer .info {margin-left: 40px;}
    .footer .info a {padding-left: 10px;}
</style>
<body>
<div id="container">
    <form action="${request.contextPath}/search.jsp" id="js_search" method="GET" onsubmit="#">
        <input type="hidden" name="type" id="js_type" value=""/>
        <div class="search_form">
            <div class="header">
                <a href="${request.contextPath}/index.php" class="logo"></a>
                <div class="s_form">
                    <div class="s_form_wrapper">
                        <input type="text" class="keyword" name="q" value="" id="js_keyword" maxlength="100" autocomplete="off"/>
                        <input type="button" class="btnBlue-s" value="Search" onclick="#"/>
                    </div>
                </div>
            </div>
        </div>
        <div class="result_warp">
            <div class="type_tab">
                <a href="#">网页</a>
                <a href="#">标题</a>
                <a href="#">响应头</a>
                <a href="#">域名</a>
                <a href="#">漏洞</a>
                <a href="#">帮助</a>
                <a class="sel" href="#">语言</a>
            </div>
            <div class="s_bar">
                <div class="nums" id="js_nums">
                    ABSearch为您找到相关结果约<em>0</em>个,耗时: <em>0</em>ms
                </div>
            </div>
            <div class="search_content">

            </div>
        </div>
    </form>
    <div class="footer">
        <div class="copyright">Copyright © 2010 - <%=new SimpleDateFormat("yyyy").format(new Date())%> javaweb.org, All Rights Reserved
            <span class="info">
				<a href="#">帮助</a>
				<a href="">反馈</a>
				<a href="">用户协议</a>
				<a href="mailto:admin@javaweb.org">联系我们</a>
			</span>
        </div>
    </div>
</div>
</body>
</html>