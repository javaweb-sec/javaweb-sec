package com.anbai.sec.server.handler;

import com.anbai.sec.server.servlet.BinCatResponse;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Map;

public class BinCatResponseHandler {

	public void processResult(BinCatResponse response, Map<String, String> responseHeader, String serverName,
	                          OutputStream out, ByteArrayOutputStream baos) throws IOException {

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
	}

}