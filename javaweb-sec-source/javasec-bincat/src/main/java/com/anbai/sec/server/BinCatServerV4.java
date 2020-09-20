package com.anbai.sec.server;

import com.anbai.sec.server.config.BinCatConfig;
import com.anbai.sec.server.handler.BinCatDispatcherServlet;
import com.anbai.sec.server.handler.BinCatResponseHandler;
import com.anbai.sec.server.servlet.BinCatRequest;
import com.anbai.sec.server.servlet.BinCatResponse;
import com.anbai.sec.server.servlet.BinCatServletContext;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * ServerSocket Http 服务器示例
 */
public class BinCatServerV4 {

	// 设置服务监听端口
	private static final int PORT = 8080;

	// 设置服务名称
	private static final String SERVER_NAME = "BinCat-0.0.4";

	private static final Logger LOG = Logger.getLogger("info");

	public static void main(String[] args) {
		try {
			// 创建ServerSocket，监听本地端口
			ServerSocket ss = new ServerSocket(PORT);

			// 创建BinCatServletContext对象
			BinCatServletContext servletContext = BinCatConfig.createServletContext();

			// 初始化Servlet
			BinCatConfig.initServlet(servletContext);

			LOG.info(SERVER_NAME + " 启动成功，监听端口: " + PORT);

			while (true) {
				// 等待客户端连接
				Socket socket = ss.accept();

				try {
					// 获取Socket输入流对象
					InputStream in = socket.getInputStream();

					// 获取Socket输出流对象
					OutputStream out = socket.getOutputStream();

					// 创建BinCat请求处理对象
					BinCatRequest request = new BinCatRequest(socket, servletContext);

					// 创建BinCat请求处理结果输出流
					ByteArrayOutputStream baos = new ByteArrayOutputStream();

					// 创建BinCat请求处理结果Header对象
					Map<String, String> responseHeader = new ConcurrentHashMap<String, String>();

					// 创建BinCat响应处理对象
					BinCatResponse response = new BinCatResponse(socket, responseHeader, baos);

					// 创建BinCatDispatcherServlet对象，用于分发Http请求
					BinCatDispatcherServlet dispatcherServlet = new BinCatDispatcherServlet();

					// 创建BinCatResponseHandler对象，用于处理Http请求结果
					BinCatResponseHandler responseHandler = new BinCatResponseHandler();

					// 使用BinCatDispatcherServlet处理Servlet请求
					dispatcherServlet.doDispatch(request, response, baos);

					// 响应服务器处理结果
					responseHandler.processResult(response, responseHeader, SERVER_NAME, out, baos);

					in.close();
					out.close();
				} catch (Exception e) {
					LOG.info("处理客户端请求异常:" + e);
				} finally {
					socket.close();
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}