package com.anbai.sec.vuls.controller;

import org.javaweb.utils.FileUtils;
import org.javaweb.utils.HttpServletResponseUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.javaweb.utils.HttpServletRequestUtils.getDocumentRoot;

@Controller
@RequestMapping("/FileUpload/")
public class FileUploadController {

	@RequestMapping("/upload.php")
	public void uploadPage(HttpServletResponse response) {
		HttpServletResponseUtils.responseHTML(response, "<!DOCTYPE html>\n" +
				"<html lang=\"en\">\n" +
				"<head>\n" +
				"    <meta charset=\"UTF-8\">\n" +
				"    <title>File upload</title>\n" +
				"</head>\n" +
				"<body>\n" +
				"<form action=\"/FileUpload/upload.do\" enctype=\"multipart/form-data\" method=\"post\">\n" +
				"    <p>\n" +
				"        用户名: <input name=\"username\" type=\"text\"/>\n" +
				"        文件: <input id=\"file\" name=\"file\" type=\"file\"/>\n" +
				"    </p>\n" +
				"    <input name=\"submit\" type=\"submit\" value=\"Submit\"/>\n" +
				"</form>\n" +
				"</body>\n" +
				"</html>");
	}

	@ResponseBody
	@RequestMapping("/upload.do")
	public Map<String, Object> upload(String username, @RequestParam("file") MultipartFile file, HttpServletRequest request) {
		// 文件名称
		String filePath   = "uploads/" + username + "/" + file.getOriginalFilename();
		File   uploadFile = new File(getDocumentRoot(request), filePath);

		// 上传目录
		File uploadDir = uploadFile.getParentFile();

		// 上传文件对象
		Map<String, Object> jsonMap = new LinkedHashMap<String, Object>();

		if (!uploadDir.exists()) {
			uploadDir.mkdirs();
		}

		try {
			FileUtils.copyInputStreamToFile(file.getInputStream(), uploadFile);

			jsonMap.put("url", filePath);
			jsonMap.put("msg", "上传成功!");
		} catch (IOException e) {
			jsonMap.put("msg", "上传失败，服务器异常!");
		}

		return jsonMap;
	}

}