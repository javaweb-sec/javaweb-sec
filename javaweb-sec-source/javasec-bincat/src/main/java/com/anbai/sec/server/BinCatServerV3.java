package com.anbai.sec.server;

import com.anbai.sec.server.servlet.BinCatRequest;
import com.anbai.sec.server.servlet.BinCatResponse;
import com.anbai.sec.server.test.servlet.CMDServlet;
import com.anbai.sec.server.test.servlet.TestServlet;
import org.javaweb.utils.StringUtils;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * ServerSocket Http 服务器示例
 */
public class BinCatServerV3 {

	private static final Logger LOG = Logger.getLogger("info");

	public static void main(String[] args) {
		try {
			// 设置服务监听端口
			int port = 8080;

			// 设置服务名称
			String serverName = "BinCat-0.0.3";

			// 创建ServerSocket，监听本地端口
			ServerSocket ss = new ServerSocket(port);

			// 初始化Servlet映射类对象
			final Set<Class<? extends HttpServlet>> servletList = new HashSet<Class<? extends HttpServlet>>();

			// 手动注册Servlet类
			servletList.add(TestServlet.class);
			servletList.add(CMDServlet.class);

			LOG.info(serverName + " 启动成功，监听端口: " + port);

			while (true) {
				// 等待客户端连接
				Socket socket = ss.accept();

				try {
					// 获取Socket输入流对象
					InputStream in = socket.getInputStream();

					// 获取Socket输出流对象
					OutputStream out = socket.getOutputStream();

					// 创建BinCat请求处理对象
					BinCatRequest request = new BinCatRequest(socket);

					// 创建BinCat请求处理结果输出流
					ByteArrayOutputStream baos = new ByteArrayOutputStream();

					// 创建BinCat请求处理结果Header对象
					Map<String, String> responseHeader = new ConcurrentHashMap<String, String>();

					// 创建BinCat响应处理对象
					BinCatResponse response = new BinCatResponse(socket, responseHeader, baos);

					// 请求URI地址
					String uri = request.getRequestURI();

					// 处理Http请求URL
					for (Class<? extends HttpServlet> clazz : servletList) {
						WebServlet webServlet  = clazz.getAnnotation(WebServlet.class);
						String[]   urlPatterns = webServlet.urlPatterns();

						for (String urlPattern : urlPatterns) {
							try {
								// 检测请求的URL地址和Servlet的地址是否匹配
								if (Pattern.compile(urlPattern).matcher(uri).find()) {
									// 修改状态码
									response.setStatus(200, "OK");

									// 创建Servlet类实例
									HttpServlet httpServlet = clazz.newInstance();

									// 调用Servlet请求处理方法
									httpServlet.service(request, response);
									break;
								}
							} catch (Exception e) {
								// 修改状态码
								response.setStatus(500, "Internal Server Error");
								e.printStackTrace();

								baos.write(("<pre>" + StringUtils.exceptionToString(e) + "</pre>").getBytes());
							}
						}
					}

					// 处理Http响应内容
					out.write(("HTTP/1.1 " + response.getStatus() + " " + response.getMessage() + "\n").getBytes());
					// 输出Web服务器信息
					out.write(("Server: " + serverName + "\n").getBytes());
					// 输出返回的消息类型
					out.write(("Content-Type: " + response.getContentType() + "\n").getBytes());
					// 输出返回字节数
					out.write(("Content-Length: " + baos.size() + "\n").getBytes());

					// 输出用户自定义的Header
					for (String key : responseHeader.keySet()) {
						out.write((key + ": " + responseHeader.get(key) + "\n").getBytes());
					}

					// 写入换行
					out.write("\n".getBytes());
					// 将读取到的数据写入到客户端Socket
					out.write(baos.toByteArray());

					in.close();
					out.close();
				} catch (Exception e) {
					LOG.info("处理客户端请求异常:" + e);
				} finally {
					socket.close();
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
