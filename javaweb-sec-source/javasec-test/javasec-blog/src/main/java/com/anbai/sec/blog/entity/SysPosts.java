package com.anbai.sec.blog.entity;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;
import java.util.Set;

@Entity
@Table(name = "sys_posts")
public class SysPosts implements Serializable {

	private static final long serialVersionUID = -8127811636900934569L;

	/**
	 * 文档Id
	 */
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer postId = -1;

	/**
	 * 分类Id
	 */
	private Integer categoryId = -1;

	/**
	 * 用户Id
	 */
	private Integer userId = -1;

	/**
	 * 文档标题
	 */
	private String postTitle;

	/**
	 * 文档作者
	 */
	private String postAuthor;

	/**
	 * 文档内容
	 */
	private String postContent;

	/**
	 * 文档密码
	 */
	private String postPassword;

	/**
	 * 发布时间
	 */
	private Date publishDate;

	/**
	 * 发布状态(1:已发布,2:草稿,3:回收站),默认值:1
	 */
	private Integer publishStatus = -1;

	/**
	 * 文档点击数量
	 */
	private Integer postClicks = -1;

	/**
	 * 最后修改时间
	 */
	private Date lastModifiedTime;

	/**
	 * 文档标签
	 */
	private String tags;

	/**
	 * 评论数
	 */
	private Integer commentCount = -1;

	@OneToMany
	@JoinColumn(name = "categoryId")
	private Set<SysPostsCategory> category;

	@OneToMany
	@JoinColumn(name = "commentPostId")
	private Set<SysComments> comments;

	/**
	 * 获取文章ID
	 */
	public Integer getPostId() {
		return postId;
	}

	/**
	 * 设置文章ID
	 */
	public void setPostId(Integer postId) {
		this.postId = postId;
	}

	public Integer getCategoryId() {
		return categoryId;
	}

	public void setCategoryId(Integer categoryId) {
		this.categoryId = categoryId;
	}

	/**
	 * 获取用户ID
	 *
	 * @return
	 */
	public Integer getUserId() {
		return userId;
	}

	/**
	 * 设置用户ID
	 *
	 * @param userId
	 */
	public void setUserId(Integer userId) {
		this.userId = userId;
	}

	/**
	 * 获取标题
	 *
	 * @return
	 */
	public String getPostTitle() {
		return postTitle;
	}

	/**
	 * 设置标题
	 *
	 * @param postTitle
	 */
	public void setPostTitle(String postTitle) {
		this.postTitle = postTitle;
	}

	/**
	 * 获取作者
	 *
	 * @return
	 */
	public String getPostAuthor() {
		return postAuthor;
	}

	/**
	 * 设置作者
	 *
	 * @param postAuthor
	 */
	public void setPostAuthor(String postAuthor) {
		this.postAuthor = postAuthor;
	}

	/**
	 * 获取文章内容
	 *
	 * @return
	 */
	public String getPostContent() {
		return postContent;
	}

	/**
	 * 设置文章内容
	 *
	 * @param postContent
	 */
	public void setPostContent(String postContent) {
		this.postContent = postContent;
	}

	/**
	 * 获取访问密码
	 *
	 * @return
	 */
	public String getPostPassword() {
		return postPassword;
	}

	/**
	 * 设置访问密码
	 *
	 * @param postPassword
	 */
	public void setPostPassword(String postPassword) {
		this.postPassword = postPassword;
	}

	/**
	 * 获取发布时间
	 *
	 * @return
	 */
	public Date getPublishDate() {
		return publishDate;
	}

	/**
	 * 设置发布时间
	 *
	 * @param publishDate
	 */
	public void setPublishDate(Date publishDate) {
		this.publishDate = publishDate;
	}

	/**
	 * 获取文档发布状态
	 *
	 * @return
	 */
	public Integer getPublishStatus() {
		return publishStatus;
	}

	/**
	 * 设置文档发布状态
	 *
	 * @param publishStatus
	 */
	public void setPublishStatus(Integer publishStatus) {
		this.publishStatus = publishStatus;
	}

	/**
	 * 获取点击数
	 *
	 * @return
	 */
	public Integer getPostClicks() {
		return postClicks;
	}

	/**
	 * 设置点击数
	 *
	 * @param postClicks
	 */
	public void setPostClicks(Integer postClicks) {
		this.postClicks = postClicks;
	}

	/**
	 * 获取最后修改时间
	 *
	 * @return
	 */
	public Date getLastModifiedTime() {
		return lastModifiedTime;
	}

	/**
	 * 设置最后修改时间
	 *
	 * @param lastModifiedTime
	 */
	public void setLastModifiedTime(Date lastModifiedTime) {
		this.lastModifiedTime = lastModifiedTime;
	}

	/**
	 * 获取标签
	 *
	 * @return
	 */
	public String getTags() {
		return tags;
	}

	/**
	 * 设置标签
	 *
	 * @param tags
	 */
	public void setTags(String tags) {
		this.tags = tags;
	}

	/**
	 * 获取评论数量
	 *
	 * @return
	 */
	public Integer getCommentCount() {
		return commentCount;
	}

	/**
	 * 设置评论数量
	 *
	 * @param commentCount
	 */
	public void setCommentCount(Integer commentCount) {
		this.commentCount = commentCount;
	}

	public Set<SysPostsCategory> getCategory() {
		return category;
	}

	public void setCategory(Set<SysPostsCategory> category) {
		this.category = category;
	}

	public Set<SysComments> getComments() {
		return comments;
	}

	public void setComments(Set<SysComments> comments) {
		this.comments = comments;
	}

}
