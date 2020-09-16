package com.anbai.sec.blog.entity;

import javax.persistence.*;
import java.io.Serializable;

/**
 * 文章分类
 */
@Entity
@Table(name = "sys_posts_category")
public class SysPostsCategory implements Serializable {

	private static final long serialVersionUID = -6044372709882171180L;

	/**
	 * 分类Id
	 */
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer categoryId = -1;

	/**
	 * 分类名称
	 */
	private String categoryName;

	/**
	 * 分类描述
	 */
	private String categoryDescription;

	/**
	 * 分类URL地址
	 */
	private String categoryUrl;

	/**
	 * 分类排序
	 */
	private Integer categoryOrder = -1;

	/**
	 * 分类父级Id
	 */
	private Integer parentId = -1;

	/**
	 * 获取分类ID
	 *
	 * @return
	 */
	public Integer getCategoryId() {
		return categoryId;
	}

	/**
	 * 设置分类ID
	 *
	 * @param categoryId
	 */
	public void setCategoryId(Integer categoryId) {
		this.categoryId = categoryId;
	}

	/**
	 * 获取分类名称
	 *
	 * @return
	 */
	public String getCategoryName() {
		return categoryName;
	}

	/**
	 * 设置分类名称
	 *
	 * @param categoryName
	 */
	public void setCategoryName(String categoryName) {
		this.categoryName = categoryName;
	}

	/**
	 * 获取分类描述
	 *
	 * @return
	 */
	public String getCategoryDescription() {
		return categoryDescription;
	}

	/**
	 * 设置分类描述
	 *
	 * @param categoryDescription
	 */
	public void setCategoryDescription(String categoryDescription) {
		this.categoryDescription = categoryDescription;
	}

	/**
	 * 获取分类URL地址
	 *
	 * @return
	 */
	public String getCategoryUrl() {
		return categoryUrl;
	}

	/**
	 * 设置分类URL地址
	 *
	 * @param categoryUrl
	 */
	public void setCategoryUrl(String categoryUrl) {
		this.categoryUrl = categoryUrl;
	}

	/**
	 * 获取分类排序
	 *
	 * @return
	 */

	public Integer getCategoryOrder() {
		return categoryOrder;
	}

	/**
	 * 设置分类排序
	 *
	 * @param categoryOrder
	 */
	public void setCategoryOrder(Integer categoryOrder) {
		this.categoryOrder = categoryOrder;
	}

	/**
	 * 获取父节点ID
	 *
	 * @return
	 */
	public Integer getParentId() {
		return parentId;
	}

	/**
	 * 设置父节点ID
	 *
	 * @param parentId
	 */
	public void setParentId(Integer parentId) {
		this.parentId = parentId;
	}

}
