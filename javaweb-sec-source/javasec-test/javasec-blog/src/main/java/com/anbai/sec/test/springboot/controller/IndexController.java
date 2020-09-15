package com.anbai.sec.test.springboot.controller;

import com.anbai.sec.test.springboot.commons.ResultInfo;
import com.anbai.sec.test.springboot.commons.SearchCondition;
import com.anbai.sec.test.springboot.entity.SysComments;
import com.anbai.sec.test.springboot.entity.SysPosts;
import com.anbai.sec.test.springboot.entity.SysPostsCategory;
import com.anbai.sec.test.springboot.service.SysCommentService;
import com.anbai.sec.test.springboot.service.SysPostsService;
import org.javaweb.utils.StringUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.Date;

import static org.javaweb.utils.HttpServletRequestUtils.getRemoteAddr;
import static org.javaweb.utils.HttpServletRequestUtils.htmlSpecialChars;

/**
 * Created by yz on 2016/12/16.
 */
@Controller
public class IndexController {

	@Resource
	private SysPostsService sysPostsService;

	@Resource
	private SysCommentService sysCommentService;

	@DeleteMapping
	@RequestMapping(value = "/")
	public String index(@RequestParam(value = "p", defaultValue = "-1", required = false) Integer postId,
	                    @RequestParam(value = "pid", required = false) Integer parentId,
	                    @RequestParam(value = "uid", required = false) Integer userId,
	                    Integer cat, SysPosts posts, SysPostsCategory category,
	                    SearchCondition condition, HttpServletRequest request) {

		if (postId < 1) {
			posts.setUserId(userId);
			posts.setPostId(postId);
			category.setCategoryId(cat);
			category.setParentId(parentId);

			request.setAttribute("pages", sysPostsService.search(posts, category, condition));
		} else {
			return "forward:/article.php";
		}

		return "/index.html";
	}

	@RequestMapping(value = "/article.php")
	public String article(@RequestParam(value = "p", defaultValue = "-1") int postId, HttpServletRequest request) {
		SysPosts sysPosts = sysPostsService.getSysPostsById(postId);

		if (sysPosts != null) {
			request.setAttribute("post", sysPosts);
			return "/article.html";
		} else {
			return "/404.html";
		}
	}

	@ResponseBody
	@RequestMapping(value = "/addComments.php", method = RequestMethod.POST)
	public ResultInfo addComments(HttpServletRequest request, SysComments comments) {
		ResultInfo info = new ResultInfo();

		try {
			if (StringUtils.isNotEmpty(comments.getCommentContent())) {
				comments.setCommentStatus(1);
				comments.setCommentUserId(0);
				comments.setCommentAuthorIp(getRemoteAddr(request));
				comments.setCommentUserAgent(htmlSpecialChars(request.getHeader("User-Agent")));
				comments.setCommentDate(new Date());
				comments.setCommentAuthor(htmlSpecialChars(comments.getCommentAuthor()));
				comments.setCommentContent(htmlSpecialChars(comments.getCommentContent()));

				sysCommentService.addSysComments(comments);
				sysPostsService.updateCommentCount(comments.getCommentPostId());
				info.setValid(true);
			}
		} catch (Exception e) {
			info.setMsg("评论失败,服务器异常!");
		}

		return info;
	}

}