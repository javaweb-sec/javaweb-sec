package com.anbai.sec.test.springboot.api;

import com.anbai.sec.test.springboot.commons.ResultInfo;
import com.anbai.sec.test.springboot.commons.SearchCondition;
import com.anbai.sec.test.springboot.entity.*;
import com.anbai.sec.test.springboot.service.BlogService;
import org.javaweb.utils.EncryptUtils;
import org.javaweb.utils.HttpServletRequestUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.springframework.data.domain.Page;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import java.util.List;

@RestController
public class BlogController {

	@Resource
	private BlogService blogService;

	@RequestMapping("/searchSysComment.do")
	public ResultInfo<Page<SysComments>> searchSysComment(SysComments comment, SearchCondition condition) {
		return new ResultInfo<>(blogService.searchSysComment(comment, condition));
	}

	@RequestMapping("/searchSysPost.do")
	public ResultInfo<Page<SysPosts>> searchSysPost(SysPosts post, SysPostsCategory cat, SearchCondition condition) {
		return new ResultInfo<>(blogService.searchSysPost(post, cat, condition));
	}

	@RequestMapping("/getAllSysLinks.do")
	public ResultInfo<List<SysLinks>> getAllSysLinks() {
		return new ResultInfo<>(blogService.getAllSysLinks());
	}

	@RequestMapping("/getSysPostsCategoryByParentId.do")
	public ResultInfo<List<SysPostsCategory>> getSysPostsCategoryByParentId(int parentId) {
		return new ResultInfo<>(blogService.getSysPostsCategoryByParentId(parentId));
	}

	@RequestMapping("/getSysUserById.do")
	public ResultInfo<SysUser> getSysUserById(int userId) {
		return new ResultInfo<>(blogService.getSysUserById(userId));
	}

	@RequestMapping("/getGravatarURL.do")
	public ResultInfo<String> getGravatarURL(String email, String size) {
		String avatarURL = "https://cn.gravatar.com/avatar/" + EncryptUtils.md5(email) + "?s=" + size;
		return new ResultInfo<>(avatarURL);
	}

	@RequestMapping("/sysPostHtmlSubString.do")
	public ResultInfo<String> sysPostHtmlSubString(String content, int maxLen) {
		Document document = Jsoup.parse(content);
		content = HttpServletRequestUtils.htmlSpecialChars(document.text());

		int len = Math.min(content.length(), maxLen);

		return new ResultInfo<>(content.substring(0, len));
	}

}