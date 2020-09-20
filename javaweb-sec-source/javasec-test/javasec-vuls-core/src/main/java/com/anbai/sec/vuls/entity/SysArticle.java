package com.anbai.sec.vuls.entity;

import java.util.Date;
import java.util.List;

/**
 * Creator: yz
 * Date: 2020-05-04
 */
public class SysArticle {

	private Long id;

	private Long userId;

	private String title;

	private String author;

	private String content;

	private Date publishDate;

	private Long ClickCount;

	private SysUser sysUser;

	private List<SysComments> sysComments;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public Long getUserId() {
		return userId;
	}

	public void setUserId(Long userId) {
		this.userId = userId;
	}

	public String getTitle() {
		return title;
	}

	public void setTitle(String title) {
		this.title = title;
	}

	public String getAuthor() {
		return author;
	}

	public void setAuthor(String author) {
		this.author = author;
	}

	public String getContent() {
		return content;
	}

	public void setContent(String content) {
		this.content = content;
	}

	public Date getPublishDate() {
		return publishDate;
	}

	public void setPublishDate(Date publishDate) {
		this.publishDate = publishDate;
	}

	public Long getClickCount() {
		return ClickCount;
	}

	public void setClickCount(Long clickCount) {
		ClickCount = clickCount;
	}

	public SysUser getSysUser() {
		return sysUser;
	}

	public void setSysUser(SysUser sysUser) {
		this.sysUser = sysUser;
	}

	public List<SysComments> getSysComments() {
		return sysComments;
	}

	public void setSysComments(List<SysComments> sysComments) {
		this.sysComments = sysComments;
	}

}
