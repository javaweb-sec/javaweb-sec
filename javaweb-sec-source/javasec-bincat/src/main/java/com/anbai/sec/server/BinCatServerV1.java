package com.anbai.sec.server;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Logger;

/**
 * ServerSocket示例
 */
public class BinCatServerV1 {

	private static final Logger LOG = Logger.getLogger("info");

	public static void main(String[] args) {
		try {
			// 设置服务监听端口
			int port = 8080;

			// 设置服务名称
			String serverName = "BinCat-0.0.1";

			// 创建ServerSocket，监听本地端口
			ServerSocket ss = new ServerSocket(port);

			LOG.info(serverName + " 启动成功，监听端口: " + port);

			while (true) {
				// 等待客户端连接
				Socket socket = ss.accept();

				try {
					// 获取Socket输入流对象
					InputStream in = socket.getInputStream();

					// 获取Socket输出流对象
					OutputStream out = socket.getOutputStream();

					// 创建输出流对象
					BufferedReader br = new BufferedReader(new InputStreamReader(in));

					// 从Socket中读取一行数据
					String str = br.readLine();

					if (str == null) {
						continue;
					}

					// 切割请求Http协议信息
					String[] strs = str.split("\\s+");

					// 解析Http请求URL地址
					String url = strs[1];

					// 输出服务器返回信息
					String msg = "";

					// 当前服务器运行目录下的文件
					File file = new File(System.getProperty("user.dir"), url);

					if (file.exists()) {
						out.write("HTTP/1.1 200 OK\n".getBytes());
						msg = file.getAbsolutePath();
					} else {
						out.write("HTTP/1.1 404 Not Found\n".getBytes());
						msg = file.getAbsolutePath() + " Not Found!";
					}

					// 输出返回字节数
					out.write(("Content-Length: " + msg.getBytes().length + "\n").getBytes());

					// 写入换行
					out.write("\n".getBytes());

					// 将读取到的数据写入到客户端Socket
					out.write(msg.getBytes());

					in.close();
					out.close();
				} catch (IOException e) {
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
