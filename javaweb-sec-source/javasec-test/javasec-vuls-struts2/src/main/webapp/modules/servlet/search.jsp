<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html lang="zh-cn">
<head>
    <title>Search - 搜索</title>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1">
</head>
<style>
    .user_bar {color: #999;padding-top: 10px;padding-right: 10px;position: fixed;z-index: 1;right: 0;font-size: 12px;}
    .s_wrapper {width: 680px;margin: 0 auto;padding-top: 186px;}
    .s_wrapper .keyword {margin: 0;width: 521px;height: 20px;padding: 9px 7px;font: 16px arial;border: 1px solid #d8d8d8;border-bottom: 1px solid #ccc;vertical-align: top;outline: none;}
    .s_wrapper .logo {text-align: center;}
    .s_wrapper img {width: 438px;height: 130px;}
    .s_wrapper .s_btn_wr {width: 102px;height: 38px;border: 1px solid #38f;border-bottom: 1px solid #2e7ae5;background-color: #38f;position: absolute;left: 536px;margin: 0 3px 0 0;}
    .s_wrapper .s_form {text-align: left;padding-left: 50px;z-index: 300;height: 43px;position: relative;}
    .s_wrapper .btn {color: white;background-color: #38f;width: 102px;height: 38px;font-size: 16px;border: 0;}
</style>

<body>
<div class="head">
    <div class="user_bar">
        <span><a href="/">帮助</a></span>
    </div>
    <div class="s_wrapper">
        <p class="logo"><img src="./ab-logo.png" /></p>
        <div class="s_form">
            <div class="s_form_wrapper">
                <form action="${request.contextPath}/search.php" method="GET">
                    <input type="hidden" name="type" value="body" />
                    <span>
                        <input type="text" class="keyword" name="q" id="js_keyword" maxlength="100" autocomplete="off">
                    </span>
                    <span class="s_btn_wr">
                        <input type="submit" value="Search" class="btn" />
                    </span>
                </form>
            </div>
        </div>
    </div>
</div>
</body>
</html>
