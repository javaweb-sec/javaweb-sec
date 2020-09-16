package com.anbai.sec.blog.commons;

/**
 * Created by yz on 2016/12/25.
 */
public class SearchCondition {

	/**
	 * 搜索的关键词
	 */
	private String keyword;

	/**
	 * 查询的分组字段名称
	 */
	private String groupBy;

	/**
	 * 查询的排序字段名称
	 */
	private String orderBy;

	/**
	 * 查询的排序规则:asc,desc
	 */
	private String order;

	/**
	 * 当前页
	 */
	private Integer page = 1;

	/**
	 * 每页显示的大小
	 */
	private Integer size = 10;

	/**
	 * 创建时间
	 */
	private String startTime;

	/**
	 * 结束时间
	 */
	private String endTime;

	/**
	 * 是否启用分页
	 */
	private boolean pageable = true;

	public String getKeyword() {
		return keyword;
	}

	public void setKeyword(String keyword) {
		this.keyword = keyword;
	}

	public String getGroupBy() {
		return groupBy;
	}

	public void setGroupBy(String groupBy) {
		this.groupBy = groupBy;
	}

	public String getOrderBy() {
		return orderBy;
	}

	public void setOrderBy(String orderBy) {
		this.orderBy = orderBy;
	}

	public String getOrder() {
		return order;
	}

	public void setOrder(String order) {
		this.order = order;
	}

	public Integer getPage() {
		return page;
	}

	public void setPage(Integer page) {
		this.page = page;
	}

	public Integer getSize() {
		return size;
	}

	public void setSize(Integer size) {
		this.size = size;
	}

	public String getStartTime() {
		return startTime;
	}

	public void setStartTime(String startTime) {
		this.startTime = startTime;
	}

	public String getEndTime() {
		return endTime;
	}

	public void setEndTime(String endTime) {
		this.endTime = endTime;
	}

	public boolean isPageable() {
		return pageable;
	}

	public void setPageable(boolean pageable) {
		this.pageable = pageable;
	}

}
