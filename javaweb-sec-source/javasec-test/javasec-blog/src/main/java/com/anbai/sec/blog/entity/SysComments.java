package com.anbai.sec.blog.entity;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;

/**
 * Created by yz on 2016/12/17.
 */
@Entity
@Table(name = "sys_comments")
public class SysComments implements Serializable {

	private static final long serialVersionUID = 3122664906266640217L;

	/**
	 * 评论Id
	 */
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer commentId;

	/**
	 * 评论的文章Id
	 */
	private Integer commentPostId;

	/**
	 * 评论的用户Id(未登录的用户Id为0)
	 */
	private Integer commentUserId;

	/**
	 * 评论者昵称
	 */
	private String commentAuthor;

	/**
	 * 评论者邮箱
	 */
	private String commentAuthorEmail;

	/**
	 * 评论者个人主页
	 */
	private String commentAuthorUrl;

	/**
	 * 评论者IP地址
	 */
	private String commentAuthorIp;

	/**
	 * 评论内容
	 */
	private String commentContent;

	/**
	 * 评论状态(0:待审核,1:审核通过,2:审核不通过)
	 */
	private int commentStatus;

	/**
	 * 用户的UserAgent
	 */
	private String commentUserAgent;

	/**
	 * 评论发布时间
	 */
	private Date commentDate;

	/**
	 * 评论父级Id
	 */
	private int commentParentId;

	public Integer getCommentId() {
		return commentId;
	}

	public void setCommentId(Integer commentId) {
		this.commentId = commentId;
	}

	public Integer getCommentPostId() {
		return commentPostId;
	}

	public void setCommentPostId(Integer commentPostId) {
		this.commentPostId = commentPostId;
	}

	public Integer getCommentUserId() {
		return commentUserId;
	}

	public void setCommentUserId(Integer commentUserId) {
		this.commentUserId = commentUserId;
	}

	public String getCommentAuthor() {
		return commentAuthor;
	}

	public void setCommentAuthor(String commentAuthor) {
		this.commentAuthor = commentAuthor;
	}

	public String getCommentAuthorEmail() {
		return commentAuthorEmail;
	}

	public void setCommentAuthorEmail(String commentAuthorEmail) {
		this.commentAuthorEmail = commentAuthorEmail;
	}

	public String getCommentAuthorUrl() {
		return commentAuthorUrl;
	}

	public void setCommentAuthorUrl(String commentAuthorUrl) {
		this.commentAuthorUrl = commentAuthorUrl;
	}

	public String getCommentAuthorIp() {
		return commentAuthorIp;
	}

	public void setCommentAuthorIp(String commentAuthorIp) {
		this.commentAuthorIp = commentAuthorIp;
	}

	public String getCommentContent() {
		return commentContent;
	}

	public void setCommentContent(String commentContent) {
		this.commentContent = commentContent;
	}

	public int getCommentStatus() {
		return commentStatus;
	}

	public void setCommentStatus(int commentStatus) {
		this.commentStatus = commentStatus;
	}

	public String getCommentUserAgent() {
		return commentUserAgent;
	}

	public void setCommentUserAgent(String commentUserAgent) {
		this.commentUserAgent = commentUserAgent;
	}

	public Date getCommentDate() {
		return commentDate;
	}

	public void setCommentDate(Date commentDate) {
		this.commentDate = commentDate;
	}

	public int getCommentParentId() {
		return commentParentId;
	}

	public void setCommentParentId(int commentParentId) {
		this.commentParentId = commentParentId;
	}

}
