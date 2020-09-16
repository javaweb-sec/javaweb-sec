package com.anbai.sec.blog.controller;

import com.anbai.sec.blog.commons.ResultInfo;
import com.anbai.sec.blog.commons.SearchCondition;
import com.anbai.sec.blog.entity.SysComments;
import com.anbai.sec.blog.entity.SysLinks;
import com.anbai.sec.blog.entity.SysPosts;
import com.anbai.sec.blog.entity.SysUser;
import com.anbai.sec.blog.service.BlogService;
import org.javaweb.utils.EncryptUtils;
import org.javaweb.utils.HttpServletRequestUtils;
import org.javaweb.utils.StringUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.springframework.data.domain.Page;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.List;

import static org.javaweb.utils.HttpServletRequestUtils.getRemoteAddr;
import static org.javaweb.utils.HttpServletRequestUtils.htmlSpecialChars;

@RestController
public class BlogAPI {

	@Resource
	private BlogService blogService;

	@RequestMapping("/searchSysPost.do")
	public ResultInfo<Page<SysPosts>> searchSysPost(Integer catId, Integer catParentId, SearchCondition condition) {
		return new ResultInfo<>(blogService.searchSysPost(catId, catParentId, condition));
	}

	@RequestMapping("/article.do")
	public ResultInfo<SysPosts> article(@RequestParam(value = "id", defaultValue = "-1") int postId) {
		return new ResultInfo<>(blogService.getSysPostsById(postId));
	}

	@PostMapping("/addComments.do")
	public ResultInfo<?> addComments(HttpServletRequest request, SysComments comments) {
		if (StringUtils.isNotEmpty(comments.getCommentContent())) {
			comments.setCommentStatus(1);
			comments.setCommentUserId(0);
			comments.setCommentAuthorIp(request.getRemoteAddr());
			comments.setCommentUserAgent(request.getHeader("User-Agent"));
			comments.setCommentDate(new Date());

			blogService.addSysComments(comments);
		}

		return new ResultInfo<>("评论成功!", true);
	}

	@RequestMapping("/searchSysComment.do")
	public ResultInfo<Page<SysComments>> searchSysComment(SysComments comment, SearchCondition condition) {
		return new ResultInfo<>(blogService.searchSysComment(comment, condition));
	}

	@RequestMapping("/getAllSysLinks.do")
	public ResultInfo<List<SysLinks>> getAllSysLinks() {
		return new ResultInfo<>(blogService.getAllSysLinks());
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