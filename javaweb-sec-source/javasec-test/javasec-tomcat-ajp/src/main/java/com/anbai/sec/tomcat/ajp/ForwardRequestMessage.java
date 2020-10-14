package com.anbai.sec.tomcat.ajp;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.net.URL;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class ForwardRequestMessage {

	private int method = 2;

	private String requestUri;

	private String serverName;

	private int serverPort;

	public static final byte[] AJP_TAG = {0x12, 0x34};

	private final ByteArrayOutputStream bos;

	private final List<Map<String, String>> headers = new LinkedList<Map<String, String>>();

	private final List<Map<String, String>> attributes = new LinkedList<Map<String, String>>();

	public ForwardRequestMessage(int packetType) {
		bos = new ByteArrayOutputStream();
		bos.write(AJP_TAG, 0, AJP_TAG.length);
		bos.write(0);
		bos.write(0);
		bos.write(packetType);
	}


	public ForwardRequestMessage(URL url, int method) {
		this(2);
		setMethod(method);
		setServerName(url.getHost());

		if (url.getPort() == -1) {
			setServerPort(url.getDefaultPort());
		} else {
			setServerPort(url.getPort());
		}

		setRequestUri(url.getPath());

		if (url.getQuery() != null) {
			addAttribute("query_string", url.getQuery());
		}
	}

	public final void setMethod(int method) {
		this.method = method;
	}

	public final void setRequestUri(String requestUri) {
		this.requestUri = requestUri;
	}

	public final void setServerName(String serverName) {
		this.serverName = serverName;
		addHeader("Host", serverName);
	}

	public final void setServerPort(int serverPort) {
		this.serverPort = serverPort;
	}

	public final void addHeader(String name, String value) {
		Map<String, String> map = new HashMap<String, String>();
		map.put(name, value);
		headers.add(map);
	}

	public final void addAttribute(String name, String value) {
		Map<String, String> map = new HashMap<String, String>();
		map.put(name, value);
		attributes.add(map);
	}

	public final void writeTo(OutputStream out) {
		writeByte(method);
		// HTTP 协议
		writeString("HTTP/1.1");
		writeString(requestUri);
		// 远程地址
		writeString("127.0.0.1");
		// 远程主机
		writeString("localhost");
		writeString(serverName);
		writeInt(serverPort);
		// 是否支持SSL
		writeBoolean(false);
		writeInt(headers.size());
		writeHeaders(headers);
		writeAttributes(attributes);
		writeByte(0xff);
		try {
			out.write(bytes());
			out.flush();
		} catch (Exception ignored) {
		}
	}

	private void writeHeaders(List<Map<String, String>> headers) {
		for (Map<String, String> header : headers) {
			for (String s : header.keySet()) {
				writeString(s);
				writeString(header.get(s));
			}
		}
	}

	private void writeAttributes(List<Map<String, String>> attributes) {
		for (Map<String, String> attribute : attributes) {
			for (String s : attribute.keySet()) {
				writeInt(0x0A);
				writeString(s);
				writeString(attribute.get(s));
			}
		}
	}

	public final byte[] bytes() {
		byte[] bytes  = bos.toByteArray();
		int    length = bytes.length - 4;
		if (length == -1) {
			bytes[2] = -1;
			bytes[3] = -1;
		} else {
			bytes[2] = (byte) ((length & 0xff00) >> 8);
			bytes[3] = (byte) (length & 0x00ff);
		}
		return bytes;
	}

	public void writeByte(int b) {
		bos.write(b);
	}

	public void writeInt(int i) {
		bos.write((i & 0xff00) >> 8);
		bos.write(i & 0x00ff);
	}

	public void writeBoolean(boolean b) {
		bos.write(b ? 1 : 0);
	}

	public void writeString(String s) {
		if (s == null) {
			bos.write(-1);
		} else {
			try {
				writeInt(s.length());
				byte[] buf = s.getBytes("UTF-8");
				bos.write(buf, 0, buf.length);
				bos.write('\0');
			} catch (Exception ignored) {
			}

		}
	}
}