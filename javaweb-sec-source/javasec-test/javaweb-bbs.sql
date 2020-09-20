SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
--  Table structure for `sys_article`
-- ----------------------------
DROP TABLE IF EXISTS `sys_article`;
CREATE TABLE `sys_article` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT COMMENT '文章ID',
  `user_id` int(9) NOT NULL COMMENT '用户ID',
  `title` varchar(100) NOT NULL COMMENT '标题',
  `author` varchar(16) NOT NULL COMMENT '作者',
  `content` longtext NOT NULL COMMENT '文章内容',
  `publish_date` datetime NOT NULL COMMENT '发布时间',
  `click_count` int(11) unsigned NOT NULL DEFAULT '0' COMMENT '文章点击数量',
  PRIMARY KEY (`id`),
  KEY `index_title` (`title`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=100002 DEFAULT CHARSET=utf8 COMMENT='系统文章表';

-- ----------------------------
--  Records of `sys_article`
-- ----------------------------
BEGIN;
INSERT INTO `sys_article` VALUES ('100000', '1', '东部战区陆军：丢掉幻想，准备打仗！', 'admin', '<p style=\"font-family:PingFangSC-Regular, 微软雅黑, STXihei, Verdana, Calibri, Helvetica, Arial, sans-serif;font-size:16px;text-indent:32px;background-color:#FFFFFF;\">\n	中国人民解放军东部战区陆军微信公众号“人民前线”4月15日发布《丢掉幻想，准备打仗！ 》，以下为文章全文：\n</p>\n<p style=\"font-family:PingFangSC-Regular, 微软雅黑, STXihei, Verdana, Calibri, Helvetica, Arial, sans-serif;font-size:16px;text-indent:32px;background-color:#FFFFFF;\">\n	文丨陈前线\n</p>\n<p style=\"font-family:PingFangSC-Regular, 微软雅黑, STXihei, Verdana, Calibri, Helvetica, Arial, sans-serif;font-size:16px;text-indent:32px;background-color:#FFFFFF;\">\n	“丢掉幻想，准备斗争！”\n</p>\n<p style=\"font-family:PingFangSC-Regular, 微软雅黑, STXihei, Verdana, Calibri, Helvetica, Arial, sans-serif;font-size:16px;text-indent:32px;background-color:#FFFFFF;\">\n	这是新中国成立前夕，毛主席发表的一篇文章标题。\n</p>\n<p style=\"font-family:PingFangSC-Regular, 微软雅黑, STXihei, Verdana, Calibri, Helvetica, Arial, sans-serif;font-size:16px;text-indent:32px;background-color:#FFFFFF;\">\n	毛主席曾说过： “我们爱好和平，但以斗争求和平则和平存，以妥协求和平则和平亡。 ”\n</p>\n<p style=\"font-family:PingFangSC-Regular, 微软雅黑, STXihei, Verdana, Calibri, Helvetica, Arial, sans-serif;font-size:16px;text-indent:32px;background-color:#FFFFFF;text-align:center;\">\n	<img src=\"/res/images/20200415203823695.jpg\" />\n</p>\n<p style=\"font-family:PingFangSC-Regular, 微软雅黑, STXihei, Verdana, Calibri, Helvetica, Arial, sans-serif;font-size:16px;text-indent:32px;background-color:#FFFFFF;\">\n	放眼今日之中国，九州大地上热潮迭涌。 在中国梦的指引下，华夏儿女投身祖国各项建设事业，追赶新时代发展的脚步。 中国在国际上的影响力显著增强，“向东看”开始成为一股潮流。\n</p>', '2020-04-19 17:35:06', '1'), ('100001', '1', '面对战争，时刻准备着！', 'admin', '<p style=\"font-family:&quot;font-size:16px;background-color:#FFFFFF;text-align:justify;\">\n	这话是20年前，我的新兵连长说的。\n</p>\n<p style=\"font-family:&quot;font-size:16px;background-color:#FFFFFF;text-align:justify;\">\n	&emsp;&emsp;那是我们授衔后的第一个晚上，班长一脸神秘地说：“按照惯例，今天晚上肯定要紧急集合的，这是你们的‘成人礼’。”于是，熄灯哨音响过之后，我们都衣不解带地躺在床上。班长为了所谓的班级荣誉，也默认了我们的做法。\n</p>\n<p style=\"font-family:&quot;font-size:16px;background-color:#FFFFFF;text-align:justify;\">\n	&emsp;&emsp;果然，深夜一阵急促的哨音响起，我们迅速打起被包，冲到指定地点集合。大个子连长看着整齐的队伍，说了句：“不错，解散!”一个皆大欢喜的局面。我们都高高兴兴地回到宿舍，紧绷的神经一下子放松下来，排房里很快就响起了呼噜声。\n</p>\n<p align=\"center\" style=\"font-family:&quot;font-size:16px;background-color:#FFFFFF;\">\n	<img src=\"/res/images/20200419133156232.jpg\" alt=\"500\" />\n</p>\n<p style=\"font-family:&quot;font-size:16px;background-color:#FFFFFF;text-align:justify;\">\n	&emsp;&emsp;可是，令人没有想到的是，睡梦中又一阵急促的哨音划破夜空的宁静——连长再次拉起了紧急集合。这一次，情况就完全不一样了，毫无准备的我们，狼狈不堪，有的被包来不及打好，不得不用手抱住;有的找不到自己的鞋子，光脚站在地上，有的甚至连裤子都穿反了……\n</p>', '2020-04-19 17:37:40', '3');
COMMIT;

-- ----------------------------
--  Table structure for `sys_comments`
-- ----------------------------
DROP TABLE IF EXISTS `sys_comments`;
CREATE TABLE `sys_comments` (
  `comment_id` int(9) unsigned NOT NULL AUTO_INCREMENT COMMENT '评论Id',
  `comment_article_id` int(9) unsigned NOT NULL DEFAULT '0' COMMENT '评论的文章Id',
  `comment_user_id` int(9) unsigned NOT NULL DEFAULT '0' COMMENT '评论的用户Id(未登录的用户Id为0)',
  `comment_author` varchar(16) NOT NULL COMMENT '评论者名称',
  `comment_content` text NOT NULL COMMENT '评论内容',
  `comment_status` smallint(1) NOT NULL DEFAULT '0' COMMENT '评论状态(0:待审核,1:审核通过,2:审核不通过)',
  `comment_date` datetime NOT NULL COMMENT '评论发布时间',
  PRIMARY KEY (`comment_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- ----------------------------
--  Table structure for `sys_config`
-- ----------------------------
DROP TABLE IF EXISTS `sys_config`;
CREATE TABLE `sys_config` (
  `id` int(11) NOT NULL AUTO_INCREMENT COMMENT 'ID',
  `config_key` varchar(255) NOT NULL COMMENT '键',
  `config_value` text COMMENT '值',
  PRIMARY KEY (`id`),
  UNIQUE KEY `config_key` (`config_key`)
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=utf8 COMMENT='系统配置表';

-- ----------------------------
--  Records of `sys_config`
-- ----------------------------
BEGIN;
INSERT INTO `sys_config` VALUES ('1', 'sys_website_name', 'JavaSec 漏洞测试平台'), ('2', 'sys_base_url', 'http://localhost:8000/'), ('3', 'sys_index_page', 'index.php'), ('4', 'sys_aliases_name', 'XXX'), ('6', 'sys_website_description', 'JavaSec 漏洞测试平台'), ('7', 'sys_version', 'JavaBBS 1.0'), ('8', 'sys_admin_email', 'admin@javaweb.org'), ('9', 'sys_icp_num', '京B2-20090059-1'), ('10', 'sys_website_keywords', 'Java漏洞测试靶场');
COMMIT;

-- ----------------------------
--  Table structure for `sys_user`
-- ----------------------------
DROP TABLE IF EXISTS `sys_user`;
CREATE TABLE `sys_user` (
  `id` int(9) unsigned NOT NULL AUTO_INCREMENT COMMENT '用户ID',
  `username` varchar(16) NOT NULL COMMENT '用户名',
  `password` varchar(32) NOT NULL COMMENT '用户密码',
  `user_avatar` varchar(255) DEFAULT NULL COMMENT '用户头像',
  `register_time` datetime DEFAULT NULL COMMENT '注册时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_sys_user_username` (`username`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8 COMMENT='系统用户表';

-- ----------------------------
--  Records of `sys_user`
-- ----------------------------
BEGIN;
INSERT INTO `sys_user` VALUES ('1', 'admin', '123456', '/res/images/avatar/default.png', '2020-05-05 17:21:27'), ('2', 'test', '123456', '/res/images/avatar/default.png', '2020-05-06 18:27:10'), ('3', 'root', '123456', '/res/images/avatar/default.png', '2020-05-06 18:28:27'), ('4', 'user', '123456', '/res/images/avatar/default.png', '2020-05-06 18:31:34'), ('5', 'rasp', '123456', '/res/images/avatar/default.png', '2020-05-06 18:32:08');
COMMIT;

SET FOREIGN_KEY_CHECKS = 1;