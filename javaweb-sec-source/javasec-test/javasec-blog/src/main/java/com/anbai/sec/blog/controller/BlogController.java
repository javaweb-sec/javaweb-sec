package com.anbai.sec.blog.controller;

import com.anbai.sec.blog.commons.SearchCondition;
import com.anbai.sec.blog.service.BlogService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;

@Controller
public class BlogController {

	@Resource
	private BlogService blogService;

	@RequestMapping("/")
	public String index(Integer p, Integer cat, Integer pid, SearchCondition condition, HttpServletRequest request) {
		request.setAttribute("categories", blogService.getSysPostsCategoryByParentId(0));
		request.setAttribute("sub_categories", blogService.getSysPostsCategoryByParentIdNotEqual(0));
		request.setAttribute("sys_config", blogService.getSysConfig());

		if (p == null) {
			request.setAttribute("links", blogService.getAllSysLinks());
			request.setAttribute("pages", blogService.searchSysPost(cat, pid, condition));
			return "/index.html";
		} else {
			request.setAttribute("post", blogService.getSysPostsById(p));
			return "/article.html";
		}
	}

}
