package com.anbai.sec.blog.entity;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;

/**
 * Created by yz on 2016/12/21.
 */
@Entity
@Table(name = "sys_links")
public class SysLinks implements Serializable {

	private static final long serialVersionUID = 1675358547408741108L;

	/**
	 * 链接Id
	 */
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer linkId;

	/**
	 * 链接地址
	 */
	private String linkUrl;

	/**
	 * 链接名称
	 */
	private String linkName;

	/**
	 * 链接图片
	 */
	private String linkImageUrl;

	/**
	 * 链接描述
	 */
	private String linkDescription;

	/**
	 * 创建时间
	 */
	private Date createTime;

	public Integer getLinkId() {
		return linkId;
	}

	public void setLinkId(Integer linkId) {
		this.linkId = linkId;
	}

	public String getLinkUrl() {
		return linkUrl;
	}

	public void setLinkUrl(String linkUrl) {
		this.linkUrl = linkUrl;
	}

	public String getLinkName() {
		return linkName;
	}

	public void setLinkName(String linkName) {
		this.linkName = linkName;
	}

	public String getLinkImageUrl() {
		return linkImageUrl;
	}

	public void setLinkImageUrl(String linkImageUrl) {
		this.linkImageUrl = linkImageUrl;
	}

	public String getLinkDescription() {
		return linkDescription;
	}

	public void setLinkDescription(String linkDescription) {
		this.linkDescription = linkDescription;
	}

	public Date getCreateTime() {
		return createTime;
	}

	public void setCreateTime(Date createTime) {
		this.createTime = createTime;
	}

}
