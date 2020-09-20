package com.anbai.sec.vuls.dao;

import com.anbai.sec.vuls.entity.SysArticle;
import com.anbai.sec.vuls.entity.SysComments;
import org.apache.commons.lang.math.NumberUtils;
import org.javaweb.utils.StringUtils;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.List;

@Component
public class SysArticleDAO {

	@Resource
	private JdbcTemplate jdbcTemplate;

	@Resource
	private SysUserDAO sysUserDAO;

	public List<SysComments> getSysCommentsList(String articleId) {
		String sql = "select * from sys_comments where comment_article_id='" +
				articleId + "' order by comment_date desc ";

		return jdbcTemplate.query(sql, new BeanPropertyRowMapper<SysComments>(SysComments.class));
	}

	public List<SysArticle> getSysArticleList() {
		List<SysArticle> sysArticleList = jdbcTemplate.query(
				"select * from sys_article order by publish_date desc ",
				BeanPropertyRowMapper.newInstance(SysArticle.class)
		);

		for (SysArticle article : sysArticleList) {
			article.setSysComments(getSysCommentsList(String.valueOf(article.getId())));
			article.setSysUser(sysUserDAO.getSysUserByID(String.valueOf(article.getUserId())));
		}

		return sysArticleList;
	}

	public void updateClickCount(String id) {
		if (NumberUtils.isNumber(id)) {
			String sql = "update sys_article set click_count = click_count +1 where id = " + id;
			jdbcTemplate.update(sql);
		}
	}

	public SysArticle getSysArticle(String id) {
		try {
			// 更新文章点击数
			updateClickCount(id);

			SysArticle article = jdbcTemplate.queryForObject(
					"select * from sys_article where id = " + id,
					BeanPropertyRowMapper.newInstance(SysArticle.class)
			);

			article.setSysComments(getSysCommentsList(String.valueOf(article.getId())));
			article.setSysUser(sysUserDAO.getSysUserByID(String.valueOf(article.getUserId())));

			return article;
		} catch (DataAccessException e) {
			return null;
		}
	}

	public boolean addArticle(SysArticle article) {
		try {
			String sql = "insert into sys_article (user_id,title,author,content,publish_date,comment_count) " +
					"values('" + article.getUserId() + "','" + article.getTitle() + "','" +
					article.getAuthor() + "','" + article.getContent() + "','" +
					StringUtils.getCurrentTime() + "', 0)";

			return jdbcTemplate.update(sql) == 1;
		} catch (DataAccessException e) {
			return false;
		}
	}

	public boolean addSysComments(SysComments comments) {
		try {
			String sql = "insert into sys_comments (comment_article_id,comment_user_id,comment_author," +
					"comment_content, comment_date) values('" + comments.getCommentArticleId() +
					"','" + comments.getCommentUserId() + "','" + comments.getCommentAuthor() +
					"','" + comments.getCommentContent() + "','" + StringUtils.getCurrentTime() + "')";

			return jdbcTemplate.update(sql) == 1;
		} catch (DataAccessException e) {
			return false;
		}
	}

}
