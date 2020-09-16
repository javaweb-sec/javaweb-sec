package com.anbai.sec.blog.commons;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;

public class JPAPage {

	/**
	 * 构建JPA分页查询对象PageRequest
	 *
	 * @param pageNumber 当前页
	 * @param pageSize   每页显示数量
	 * @return
	 */
	public static PageRequest buildPageRequest(Integer pageNumber, Integer pageSize) {
		return buildPageRequest(pageNumber, pageSize, Sort.unsorted());
	}

	/**
	 * 构建JPA分页查询对象PageRequest
	 *
	 * @param pageNumber 当前页
	 * @param pageSize   每页显示数量
	 * @param sort       排序
	 * @return
	 */
	public static PageRequest buildPageRequest(Integer pageNumber, Integer pageSize, Sort sort) {
		return PageRequest.of(pageNumber - 1, pageSize, sort);
	}

}