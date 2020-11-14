package com.anbai.sec.vuls.controller;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

import static org.javaweb.utils.HttpServletResponseUtils.responseHTML;

/**
 * Creator: yz
 * Date: 2020-05-04
 */
@Controller
@RequestMapping("/SQLInjection/")
public class SQLInjectionController {

	@Resource
	private JdbcTemplate jdbcTemplate;

	@RequestMapping("/Login.php")
	public void login(String username, String password, String action, String formType,
	                  HttpServletRequest request, HttpServletResponse response,
	                  HttpSession session) throws IOException {

		String      contentType = request.getContentType();
		String      sessionKey  = "USER_INFO";
		Object      sessionUser = session.getAttribute(sessionKey);
		PrintWriter out         = response.getWriter();

		// 退出登陆
		if (sessionUser != null && "exit".equals(action)) {
			session.removeAttribute(sessionKey);

			response.sendRedirect(request.getServletPath() + (formType != null ? "?formType=" + formType : ""));
			return;
		}

		Map<String, Object> userInfo = null;

		// 检查用户是否已经登陆成功
		if (sessionUser instanceof Map) {
			userInfo = (Map<String, Object>) sessionUser;

			responseHTML(response,
					"<p>欢迎回来:" + userInfo.get("username") + ",ID:" +
							userInfo.get("id") + " \r<a href='?action=exit" + (formType != null ? "&formType=" + formType : "") + "'>退出登陆</a></p>"
			);

			return;
		}

		// 处理用户登陆逻辑
		if (username != null && password != null) {
			userInfo = new HashMap<String, Object>();

			try {
				String sql = "select id,username,password from sys_user where username = '" +
						username + "' and password = '" + password + "'";

				System.out.println(sql);

				userInfo = jdbcTemplate.queryForMap(sql);

				// 检查是否登陆成功
				if (userInfo.size() > 0) {
					// 设置用户登陆信息
					session.setAttribute(sessionKey, userInfo);

					String q = request.getQueryString();

					// 跳转到登陆成功页面
					response.sendRedirect(request.getServletPath() + (q != null ? "?" + q : ""));
				} else {
					responseHTML(response, "<script>alert('登陆失败，账号或密码错误!');history.back(-1)</script>");
				}
			} catch (Exception e) {
				responseHTML(response, "<script>alert('登陆失败，服务器异常!');history.back(-1)</script>");
			}

			return;
		}

		String multipartReq = "";

		// 如果传入formType=multipart参数就输出multipart表单，否则输出普通的表单
		if ("multipart".equals(formType)) {
			multipartReq = " enctype=\"multipart/form-data\" ";
		}

		responseHTML(response, "<html>\n" +
				"<head>\n" +
				"    <title>Login Test</title>\n" +
				"</head>\n" +
				"<body>\n" +
				"<div style=\"margin: 30px;\">\n" +
				"    <form action=\"#\" " + multipartReq + " method=\"POST\">\n" +
				"        Username:<input type=\"text\" name=\"username\" value=\"admin\"/><br/>\n" +
				"        Password:<input type=\"text\" name=\"password\" value=\"'=0#\"/><br/>\n" +
				"        <input type=\"submit\" value=\"登陆\"/>\n" +
				"    </form>\n" +
				"</div>\n" +
				"</body>\n" +
				"</html>");

		out.flush();
		out.close();
	}

}
