package com.anbai.sec.vuls.action;

import com.alibaba.fastjson.JSON;
import com.opensymphony.xwork2.ActionSupport;
import org.apache.struts2.ServletActionContext;
import org.javaweb.utils.FileUtils;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.URLEncoder;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class FileUploadAction extends ActionSupport {

	private static final long serialVersionUID = -3741991962338505509L;

	private File myFile;

	private String fileName;

	private String imageFileName;

	private String contentType;

	public void setMyFileContentType(String contentType) {
		this.contentType = contentType;
	}

	public void setMyFileFileName(String fileName) {
		this.fileName = fileName;
	}

	public File getMyFile() {
		return myFile;
	}

	public void setMyFile(File myFile) {
		this.myFile = myFile;
	}

	public String getImageFileName() {
		return imageFileName;
	}

	public void setImageFileName(String imageFileName) {
		this.imageFileName = imageFileName;
	}

	public String getContentType() {
		return contentType;
	}

	public void setContentType(String contentType) {
		this.contentType = contentType;
	}

	public String execute() {
		Map<String, Object> result   = new HashMap<String, Object>();
		HttpServletResponse response = ServletActionContext.getResponse();
		HttpServletRequest  request  = ServletActionContext.getRequest();

		try {
			PrintWriter out = response.getWriter();
			this.imageFileName = (new Date()).getTime() + "." + FileUtils.getFileSuffix(fileName);
			File imageFile = new File(ServletActionContext.getServletContext().getRealPath("UploadImages") + "/" + this.imageFileName);
			FileUtils.copyFile(myFile, imageFile);
			response.setHeader("Content-type", "text/html;charset=UTF-8");
			String url = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() + "/" + request.getContextPath();
			result.put("url", url + "/fileLoad.action?fileName=" + this.imageFileName);
			result.put("status", 0);
			result.put("msg", 0);

			out.write(JSON.toJSON(result).toString());
			out.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}

	public String fileLoad() {
		try {
			String fileName = ServletActionContext.getRequest().getParameter("fileName");
			fileName = new String(fileName.getBytes("iso8859-1"), "utf-8");

			String      path = ServletActionContext.getServletContext().getRealPath("/");
			InputStream is   = new FileInputStream(path + "UploadImages/" + fileName);

			HttpServletResponse response            = ServletActionContext.getResponse();
			ServletOutputStream servletOutputStream = response.getOutputStream();

			response.addHeader("content-disposition", "attachment;filename=" + URLEncoder.encode(fileName, "utf-8"));

			byte[] b    = new byte[1024];
			int    size = 0;

			while ((size = is.read(b)) != -1) {
				servletOutputStream.write(b, 0, size);
			}

			is.close();
			servletOutputStream.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}

}
