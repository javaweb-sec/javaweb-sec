var javaweb = {};

javaweb.commons = {};

javaweb.commons.tabChange = function (type) {
    $('#js_type').val(type);
    $('#page').val(1);
    $('#search').attr('method', "POST");
    $('#search').submit();
};

/**
 * 数据验证
 * @returns {String}
 */
javaweb.commons.validate = function () {
    if ($('#js_ketword').val() != $('#query').val()) {
        $('#page').val(1);
    }
};

/**
 * JS正则表达式特殊字符转义
 * @returns {String}
 */
javaweb.commons.regexpQuote = function (reg) {
    return String(reg).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
};

/**
 * JS HTML实体化
 * @returns {String}
 */
javaweb.commons.htmlspecialchars = function (content) {
    content = content.replace(/&/g, '&amp;');
    content = content.replace(/</g, '&lt;');
    content = content.replace(/>/g, '&gt;');
    content = content.replace(/"/g, '&quot;');
    content = content.replace(/'/g, '&#039;');
    return content;
};

/**
 * 搜索结果内容提取
 *
 * @param {String} keyword
 * @param {String} content
 * @returns {String}
 */
javaweb.commons.searchResultExtraction = function (keyword, content, maxlen) {
    if (keyword != '' && content != '' && content.length > maxlen && maxlen > 0) {
        var regexp = new RegExp(javaweb.commons.regexpQuote(keyword), 'img');
        // 截取字符串出现位置前半部分
        var start = content.substring(0, regexp.lastIndex);
        var end = content.substring(start.length);
        start = start.indexOf("\n") != -1 ? start.substring(start.indexOf("\n") + 1) : start;
        var sb = "";
        if (start.length > maxlen) {
            sb = start.substring(start.length - (maxlen - keyword.length > -1 ? keyword.length : maxlen / 2));
        } else {
            sb = start + (end.indexOf("\n") != -1 ? end.substring(0, end.indexOf("\n")) : end);
        }
        return sb.length > maxlen ? sb.substring(0, maxlen) + "..." : sb;
    }
    return content;
};

/**
 * 简单的搜索结果关键字高亮 不做具体的语法解析处理
 * @param {String} keyword
 * @param {String} content
 * @returns {String}
 */
javaweb.commons.highlightFields = function (keyword, content, maxlen) {
    var sb = '';
    if (keyword != '' && content != '') {
        // 实体化搜索结果字符串并提取关键行
        var entity = javaweb.commons.htmlspecialchars(content);
        content = javaweb.commons.searchResultExtraction(keyword, entity, maxlen);
        var regexp = new RegExp(javaweb.commons.regexpQuote(keyword), 'img');
        var i = 0;
        while ((result = regexp.exec(content)) != null) {
            var start = result.index;
            var end = regexp.lastIndex;
            sb += content.substring(i, start) + '<em>' + result[0] + '</em>';
            i = end;
        }
        if (i != content.length) {
            sb += content.substring(i, content.length);
        }
    }
    return sb;
};

/**
 * 异步加载主机端口服务等基础信息
 * @param {String} host
 * @param {String} id
 * @returns
 */
javaweb.commons.requestHostMetaData = function (host, id) {
    $.ajax({
        url: './getHostMetaData.do',
        type: 'POST',
        async: true,
        data: {
            ip: host
        },
        success: function (data) {
            var data = data["data"];
            if (data.length > 0) {
                var content = "端口:[";
                for (var i = 0; i < data.length; i++) {
                    content += "<a href=\"#\" title=\""
                        + ($('<div/>').text(data[i]["data"]).html())
                        + "\">" + data[i]["port"] + "</a>";
                    if (i < data.length - 1) {
                        content += " ";
                    }
                }
                content += "] " + (data.length > 9 ? "<br/>" : "");
                $("#p-" + id).html(content);
            }
        },
        error: function (data) {
//        	alert('请求异常');
        }
    });
};

javaweb.commons.getMateData = function () {
    var hosts = document.getElementsByTagName("cite");
    for (var i = 0; i < hosts.length; i++) {
        var host = hosts[i].innerHTML;
        if (host.indexOf(":") != -1) {
            host = host.substring(0, host.indexOf(":"));
        }
        javaweb.commons.requestHostMetaData(host, hosts[i].attributes["id"].nodeValue);
    }
};


/**
 * 设置评论
 */
javaweb.commons.comments = function (id, status) {

    $.ajax({
        url: '/wp-admin/comment.do',
        type: 'GET',
        data: {
            id: id,
            status: status
        },
        success: function (data) {
            if (data.valid) {
                (data.code > 0) ? a = "even thread-even depth-1 approved" : a = "odd alt thread-odd thread-alt depth-1 unapproved"
                $("#comment-" + id).attr('class', "comment byuser bypostauthor " + a);
            }
        },
        error: function (data) {
            alert('设置失败,请求异常');
        }
    });
};

/**
 * 回复评论
 */
javaweb.commons.replyComments = function (id) {
    $($("#com-reply >tr").html()).insertAfter("#comment-" + id);
};


/**
 * 刷新验证码 重新加载验证码地址
 */
javaweb.commons.changeCaptcha = function () {
    $('#js_captcha_img').attr('src', './captcha.php?time=' + (new Date().getTime()));
};

/**
 * 用户登录校验
 */
javaweb.commons.login = function () {
    var username = $('#js_username').val();
    var password = $('#js_password').val();
    var captcha = $('#js_captcha').val();
    if (username == '') {
        alert('用户名不能为空!');
        return false;
    }
    if (password == '') {
        alert('密码不能为空!');
        return false;
    }
    if (captcha == '') {
        alert('验证码不能为空!');
        return false;
    }
    $.ajax({
        url: './login.php',
        type: 'POST',
        data: {
            username: username,
            password: password,
            captcha: captcha
        },
        success: function (data) {
            if (data.valid) {
                location.href = './wp-admin/index.do';
            } else {
                javaweb.commons.changeCaptcha();
                $('#js_captcha').val('');
                alert(data.description);
            }
        },
        error: function (data) {
            alert('登录失败,请求异常');
        }
    });
};

/**
 * 普通用户 通过API KEY 方式登录校验
 */
javaweb.commons.apiLogin = function () {
    var key = $('#js_key').val();
    var captcha = $('#js_captcha').val();
    if (key == '') {
        alert('KEY不能为空!');
        return false;
    }
    if (captcha == '') {
        alert('验证码不能为空!');
        return false;
    }
    $.ajax({
        url: './ucenter/api_login.do',
        type: 'POST',
        data: {
            key: key,
            captcha: captcha
        },
        success: function (data) {
            if (data.valid) {
                $.blockUI({
                    message: $('#js_loading_box'),
                    css: {
                        backgroundColor: '#eee',
                        textAlign: 'center',
                        cursor: 'default'
                    }
                });
                setInterval(function () {
                    $.getJSON("./ucenter/weiXinProcessStatus.do", function (data) {
                        if (data.valid) {
                            location.href = './ucenter/webUser.do';
                        }
                    });
                }, 1000);
            } else {
                javaweb.commons.changeCaptcha();
                $('#js_captcha').val('');
                alert(data.description);
            }
        },
        error: function (data) {
            alert('登录失败,请求异常');
        }
    });
};

javaweb.commons.addComments = function () {
    var $commentAuthor = $('#js_comment_author').val(),
        $commentAuthorEmail = $('#js_comment_author_email').val(),
        $commentAuthorUrl = $('#js_comment_author_url').val(),
        $commentContent = $('#js_comment_content').val(),
        $userId = $('#js_user_id').val();

    if ($userId == '' && $userId.length < 1) {
        if ($commentAuthor.length < 1 || $commentAuthor.length > 16) {
            alert('昵称长度必须是2-16位字符');
            return false;
        } else if ($commentAuthorEmail == '' || !/^(\w+\.)*?\w+@(\w+\.)+\w+$/.test($commentAuthorEmail)) {
            alert($commentAuthorEmail == '' ? '邮箱不能为空' : '邮箱格式不正确');
            return false;
        } else if ($commentAuthorUrl.length > 100) {
            alert('网站URL地址过长');
            return false;
        } else if ($commentContent == '') {
            alert('评论内容不能为空!');
            return;
        }
    }

    $.ajax({
        type: "POST",
        url: "/addComments.do",
        data: $('#js_add_comments_form').serialize(),
        success: function (data) {
            location.href = location.href;
        },
        error: function (data) {
            alert('请求异常!');
        }
    });

};