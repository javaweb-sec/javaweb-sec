<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.sql.Connection" %>
<%@ page import="java.sql.DriverManager" %>
<%@ page import="java.sql.ResultSet" %>
<%@ page import="java.util.HashMap" %>
<%@ page import="java.util.Map" %>

<%
    //    MYSQL sys_article示例表，测试时请先创建对应的数据库和表
//    CREATE TABLE `sys_article` (
//        `id` int(11) unsigned NOT NULL AUTO_INCREMENT COMMENT '文章ID',
//        `user_id` int(9) NOT NULL COMMENT '用户ID',
//        `title` varchar(100) NOT NULL COMMENT '标题',
//        `author` varchar(16) NOT NULL COMMENT '作者',
//        `content` longtext NOT NULL COMMENT '文章内容',
//        `publish_date` datetime NOT NULL COMMENT '发布时间',
//        `click_count` int(11) unsigned NOT NULL DEFAULT '0' COMMENT '文章点击数量',
//        PRIMARY KEY (`id`),
//        KEY `index_title` (`title`) USING BTREE
//    ) ENGINE=InnoDB AUTO_INCREMENT=100002 DEFAULT CHARSET=utf8 COMMENT='系统文章表';
//
//    INSERT INTO `sys_article` VALUES ('100000', '1', '东部战区陆军：丢掉幻想，准备打仗！', 'admin', '<p style=\"font-family:PingFangSC-Regular, 微软雅黑, STXihei, Verdana, Calibri, Helvetica, Arial, sans-serif;font-size:16px;text-indent:32px;background-color:#FFFFFF;\">\n	中国人民解放军东部战区陆军微信公众号“人民前线”4月15日发布《丢掉幻想，准备打仗！ 》，以下为文章全文：\n</p>\n<p style=\"font-family:PingFangSC-Regular, 微软雅黑, STXihei, Verdana, Calibri, Helvetica, Arial, sans-serif;font-size:16px;text-indent:32px;background-color:#FFFFFF;\">\n	文丨陈前线\n</p>\n<p style=\"font-family:PingFangSC-Regular, 微软雅黑, STXihei, Verdana, Calibri, Helvetica, Arial, sans-serif;font-size:16px;text-indent:32px;background-color:#FFFFFF;\">\n	“丢掉幻想，准备斗争！”\n</p>\n<p style=\"font-family:PingFangSC-Regular, 微软雅黑, STXihei, Verdana, Calibri, Helvetica, Arial, sans-serif;font-size:16px;text-indent:32px;background-color:#FFFFFF;\">\n	这是新中国成立前夕，毛主席发表的一篇文章标题。\n</p>\n<p style=\"font-family:PingFangSC-Regular, 微软雅黑, STXihei, Verdana, Calibri, Helvetica, Arial, sans-serif;font-size:16px;text-indent:32px;background-color:#FFFFFF;\">\n	毛主席曾说过： “我们爱好和平，但以斗争求和平则和平存，以妥协求和平则和平亡。 ”\n</p>\n<p style=\"font-family:PingFangSC-Regular, 微软雅黑, STXihei, Verdana, Calibri, Helvetica, Arial, sans-serif;font-size:16px;text-indent:32px;background-color:#FFFFFF;text-align:center;\">\n	<img src=\"/res/images/20200415203823695.jpg\" />\n</p>\n<p style=\"font-family:PingFangSC-Regular, 微软雅黑, STXihei, Verdana, Calibri, Helvetica, Arial, sans-serif;font-size:16px;text-indent:32px;background-color:#FFFFFF;\">\n	放眼今日之中国，九州大地上热潮迭涌。 在中国梦的指引下，华夏儿女投身祖国各项建设事业，追赶新时代发展的脚步。 中国在国际上的影响力显著增强，“向东看”开始成为一股潮流。\n</p>', '2020-04-19 17:35:06', '4'), ('100001', '1', '面对战争，时刻准备着！', 'admin', '<p style=\"font-family:&quot;font-size:16px;background-color:#FFFFFF;text-align:justify;\">\n	这话是20年前，我的新兵连长说的。\n</p>\n<p style=\"font-family:&quot;font-size:16px;background-color:#FFFFFF;text-align:justify;\">\n	&emsp;&emsp;那是我们授衔后的第一个晚上，班长一脸神秘地说：“按照惯例，今天晚上肯定要紧急集合的，这是你们的‘成人礼’。”于是，熄灯哨音响过之后，我们都衣不解带地躺在床上。班长为了所谓的班级荣誉，也默认了我们的做法。\n</p>\n<p style=\"font-family:&quot;font-size:16px;background-color:#FFFFFF;text-align:justify;\">\n	&emsp;&emsp;果然，深夜一阵急促的哨音响起，我们迅速打起被包，冲到指定地点集合。大个子连长看着整齐的队伍，说了句：“不错，解散!”一个皆大欢喜的局面。我们都高高兴兴地回到宿舍，紧绷的神经一下子放松下来，排房里很快就响起了呼噜声。\n</p>\n<p align=\"center\" style=\"font-family:&quot;font-size:16px;background-color:#FFFFFF;\">\n	<img src=\"/res/images/20200419133156232.jpg\" alt=\"500\" />\n</p>\n<p style=\"font-family:&quot;font-size:16px;background-color:#FFFFFF;text-align:justify;\">\n	&emsp;&emsp;可是，令人没有想到的是，睡梦中又一阵急促的哨音划破夜空的宁静——连长再次拉起了紧急集合。这一次，情况就完全不一样了，毫无准备的我们，狼狈不堪，有的被包来不及打好，不得不用手抱住;有的找不到自己的鞋子，光脚站在地上，有的甚至连裤子都穿反了……\n</p>', '2020-04-19 17:37:40', '17');
%>

<%
    String id = request.getParameter("id");
    Map<String, Object> articleInfo = new HashMap<String, Object>();
    ResultSet rs = null;
    Connection connection = null;

    if (id != null) {
        try {
            Class.forName("com.mysql.jdbc.Driver");
            connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/javaweb-bbs", "root", "root");

            String sql = "select * from sys_article where id = " + id;
            System.out.println(sql);

            rs = connection.prepareStatement(sql).executeQuery();

            while (rs.next()) {
                articleInfo.put("id", rs.getInt("id"));
                articleInfo.put("user_id", rs.getInt("user_id"));
                articleInfo.put("title", rs.getString("title"));
                articleInfo.put("author", rs.getString("author"));
                articleInfo.put("content", rs.getString("content"));
                articleInfo.put("publish_date", rs.getDate("publish_date"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            // 关闭数据库连接
            if (rs != null)
                rs.close();

            if (connection != null)
                connection.close();
        }
    }
%>
<html>
<head>
    <title><%=articleInfo.get("title")%></title>
</head>
<body>
<div style="margin: 30px;">
    <h2 style="height: 30px; text-align: center;"><%=articleInfo.get("title")%></h2>
    <p>作者：<%=articleInfo.get("author")%> - <%=articleInfo.get("publish_date")%></p>
    <div style="border: 1px solid #C6C6C6;">
        <%=articleInfo.get("content")%>
    </div>
</div>
</body>
</html>