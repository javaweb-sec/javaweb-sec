package com.anbai.sec.vuls.controller;

import com.anbai.sec.vuls.commons.ResultInfo;
import com.anbai.sec.vuls.dao.SysArticleDAO;
import com.anbai.sec.vuls.dao.SysUserDAO;
import com.anbai.sec.vuls.entity.SysArticle;
import com.anbai.sec.vuls.entity.SysComments;
import com.anbai.sec.vuls.entity.SysUser;
import org.javaweb.utils.FileUtils;
import org.javaweb.utils.HttpServletResponseUtils;
import org.javaweb.utils.StringUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.anbai.sec.vuls.commons.Constants.SESSION_USER;
import static org.javaweb.utils.HttpServletRequestUtils.getDocumentRoot;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 * 演示环境首页漏洞
 * Creator: yz
 * Date: 2019-08-29
 */
@Controller
public class IndexController {

	@Resource
	private SysUserDAO sysUserDAO;

	@Resource
	private SysArticleDAO sysArticleDAO;

	@RequestMapping("/")
	public String indexPage() {
		return "/index.html";
	}

	@RequestMapping("/SpELVul.php")
	public String spELVul(int id, HttpServletRequest request, HttpServletResponse response) {
		request.setAttribute("id", id);

		return "/spel.html";
	}

	@RequestMapping("/login.php")
	public String loginPage(HttpSession session) {
		Object sessionUser = session.getAttribute(SESSION_USER);

		if (sessionUser == null) {
			return "/html/user/login.html";
		}

		return "/html/user/home.html";
	}

	@RequestMapping("/reg.php")
	public String regPage() {
		return "/html/user/reg.html";
	}

	@RequestMapping("/forget.php")
	public String forgetPage() {
		return "/html/user/forget.html";
	}

	@RequestMapping("/addArticle.php")
	public String addArticlePage() {
		return "/html/jie/add.html";
	}

	@RequestMapping("/user/index.do")
	public String userHomePage() {
		return "/html/user/home.html";
	}

	@RequestMapping("/getUserById.do")
	public String getUserById(HttpServletRequest request, int id) {
		request.setAttribute("userInfo", sysUserDAO.getSysUserByID(String.valueOf(id)));
		return "/html/user/user.html";
	}

	@ResponseBody
	@RequestMapping(value = "/login.do", method = RequestMethod.POST, consumes = APPLICATION_JSON_VALUE)
	public ResultInfo<SysUser> login(@RequestBody SysUser user, HttpSession session) {
		ResultInfo<SysUser> result = new ResultInfo<SysUser>();
		SysUser             u      = sysUserDAO.getSysUserByUsername(user.getUsername());

		if (u != null) {
			SysUser loginUser = sysUserDAO.login(user.getUsername(), user.getPassword());

			if (loginUser != null) {
				session.setAttribute(SESSION_USER, loginUser);
				result.setValid(true);
				result.setData(loginUser);
			} else {
				result.setData(u);
				result.setMsg("登陆失败，密码错误!");
			}
		} else {
			result.setMsg("登陆失败，该用户不存在!");
		}

		return result;
	}

	@RequestMapping("/user/logout.php")
	public void logout(HttpServletRequest request, HttpServletResponse response,
	                   HttpSession session) throws IOException {

		session.removeAttribute(SESSION_USER);
		response.sendRedirect(request.getContextPath() + "/index.do");
	}

	@ResponseBody
	@RequestMapping("/register.do")
	public ResultInfo<SysUser> register(SysUser user) {
		ResultInfo<SysUser> result = new ResultInfo<SysUser>();
		SysUser             u      = sysUserDAO.getSysUserByUsername(user.getUsername());

		if (StringUtils.isNotEmpty(user.getUsername()) && StringUtils.isNotEmpty(user.getPassword())) {
			if (u == null) {
				if (sysUserDAO.register(user) > 0) {
					result.setValid(true);
					result.setMsg("用户注册成功!");
				} else {
					result.setData(u);
					result.setMsg("用户注册失败!");
				}
			} else {
				result.setMsg("用户注册失败，该用户已存在!");
			}
		} else {
			result.setMsg("用户注册失败，账号或密码不能为空!");
		}

		return result;
	}

	@RequestMapping("/index.do")
	public String index(HttpServletRequest request) {
		List<SysArticle> articleList = sysArticleDAO.getSysArticleList();
		request.setAttribute("articleList", articleList);

		return "/html/index.html";
	}

	@RequestMapping("/getArticle.do")
	public String getArticle(HttpServletRequest request, String articleId) {
		SysArticle article = sysArticleDAO.getSysArticle(articleId);
		request.setAttribute("article", article);

		return "/html/jie/detail.html";
	}

	@ResponseBody
	@RequestMapping("/addArticle.do")
	public ResultInfo<?> addArticle(SysArticle article, HttpSession session) {
		ResultInfo<?> resultInfo  = new ResultInfo();
		Object        sessionUser = session.getAttribute(SESSION_USER);

		if (sessionUser != null) {
			SysUser u = (SysUser) sessionUser;
			article.setUserId(u.getId());
			article.setAuthor(u.getUsername());

			if (sysArticleDAO.addArticle(article)) {
				resultInfo.setValid(true);
			} else {
				resultInfo.setMsg("添加文章失败!");
			}
		} else {
			resultInfo.setMsg("未检测到用户登陆信息，请重新登陆！");
		}

		return resultInfo;
	}

	@ResponseBody
	@RequestMapping("/addComments.do")
	public ResultInfo<?> addComments(SysComments comment, HttpSession session) {
		ResultInfo<?> resultInfo = new ResultInfo();

		if (StringUtils.isNotEmpty(comment.getCommentContent())) {
			Object sessionUser = session.getAttribute(SESSION_USER);

			if (sessionUser != null) {
				SysUser u = (SysUser) sessionUser;
				comment.setCommentUserId(u.getId());
				comment.setCommentAuthor(u.getUsername());
			} else {
				comment.setCommentUserId(1L);
				comment.setCommentAuthor("游客");
			}

			if (sysArticleDAO.addSysComments(comment)) {
				resultInfo.setValid(true);
			}
		} else {
			resultInfo.setMsg("评论内容不能为空!");
		}

		return resultInfo;
	}

	@ResponseBody
	@RequestMapping(value = "/upload.php", method = RequestMethod.POST)
	public Map<String, Object> upload(@RequestParam("file") MultipartFile file,
	                                  HttpServletRequest request) throws Exception {

		File uploadDir  = new File(getDocumentRoot(request), "UploadImages");
		File uploadFile = new File(uploadDir, file.getOriginalFilename());

		if (!uploadDir.exists()) {
			uploadDir.mkdir();
		}

		FileUtils.copyInputStreamToFile(file.getInputStream(), uploadFile);

		Map<String, Object> jsonMap = new HashMap<String, Object>();
		jsonMap.put("url", "/download.php?fileName=" + uploadFile.getName());
		jsonMap.put("status", 0);
		jsonMap.put("msg", 0);

		return jsonMap;
	}

	@RequestMapping("/download.php")
	public void download(String fileName, HttpServletRequest request,
	                     HttpServletResponse response) throws IOException {

		File uploadDir    = new File(getDocumentRoot(request), "UploadImages");
		File downloadFile = new File(uploadDir, fileName);

		HttpServletResponseUtils.download(response, downloadFile);
	}

}
