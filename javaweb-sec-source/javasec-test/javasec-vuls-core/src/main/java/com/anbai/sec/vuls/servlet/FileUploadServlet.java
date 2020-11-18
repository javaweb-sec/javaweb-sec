package com.anbai.sec.vuls.servlet;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;

@MultipartConfig
@WebServlet(urlPatterns = "/FileUploadServlet")
public class FileUploadServlet extends HttpServlet {

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
		PrintWriter out = resp.getWriter();

		out.println("<!DOCTYPE html>\n" +
				"<html lang=\"zh\">\n" +
				"<head>\n" +
				"    <meta charset=\"UTF-8\">\n" +
				"    <title>File upload</title>\n" +
				"</head>\n" +
				"<body>\n" +
				"<form action=\"\" enctype=\"multipart/form-data\" method=\"post\">\n" +
				"    <p>\n" +
				"        用户名: <input name=\"username\" type=\"text\"/>\n" +
				"        文件: <input id=\"file\" name=\"file\" type=\"file\"/>\n" +
				"    </p>\n" +
				"    <input name=\"submit\" type=\"submit\" value=\"Submit\"/>\n" +
				"</form>\n" +
				"</body>\n" +
				"</html>");

		out.flush();
		out.close();
	}

	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		PrintWriter out         = response.getWriter();
		String      contentType = request.getContentType();

		// 检测是否是multipart请求
		if (contentType != null && contentType.startsWith("multipart/")) {
			String dir       = request.getSession().getServletContext().getRealPath("/uploads/");
			File   uploadDir = new File(dir);

			if (!uploadDir.exists()) {
				uploadDir.mkdir();
			}

			Collection<Part> parts = request.getParts();

			for (Part part : parts) {
				String fileName = part.getSubmittedFileName();

				if (fileName != null) {
					File uploadFile = new File(uploadDir, fileName);
					out.println(part.getName() + ": " + uploadFile.getAbsolutePath());

					FileUtils.write(uploadFile, IOUtils.toString(part.getInputStream(), "UTF-8"));
				} else {
					out.println(part.getName() + ": " + IOUtils.toString(part.getInputStream()));
				}
			}
		}

		out.flush();
		out.close();
	}

}
