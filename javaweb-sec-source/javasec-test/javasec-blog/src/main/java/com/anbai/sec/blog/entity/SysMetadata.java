package com.anbai.sec.blog.entity;

import java.io.Serializable;

public class SysMetadata implements Serializable {

	/**
	 * 元数据Id
	 */
	private int id;

	/**
	 * 元数据key(键名称)
	 */
	private String key;

	/**
	 * 元数据value(键值)
	 */
	private String value;

	/**
	 * 元数据描述
	 */
	private String description;

	/**
	 * 元数据父节点Id
	 */
	private int parentId;

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public String getKey() {
		return key;
	}

	public void setKey(String key) {
		this.key = key;
	}

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public int getParentId() {
		return parentId;
	}

	public void setParentId(int parentId) {
		this.parentId = parentId;
	}

}
