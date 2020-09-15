package com.anbai.sec.server.servlet;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.URLEncoder;
import java.util.*;

public class BinCatResponse implements HttpServletResponse {

	private final Socket socket;

	private final Map<String, String> header;

	private final ByteArrayOutputStream out;

	private int status = 404;

	private String statusMessage = "Not Found";

	private String charset = "UTF-8";

	private int contentLength = 0;

	private String contentType = "text/html; charset=UTF-8";

	private String location;

	public BinCatResponse(Socket socket, Map<String, String> header, ByteArrayOutputStream out) {
		this.socket = socket;
		this.header = header;
		this.out = out;
	}

	public void addCookie(Cookie cookie) {
		if (header.containsKey("cookie")) {
			String cookieStr   = header.get("cookie");
			String cookieValue = URLEncoder.encode(cookie.getValue());

			header.put("cookie", cookieStr + "; " + cookie.getName() + "=" + cookieValue);
		}
	}

	public boolean containsHeader(String name) {
		return header.containsKey(name);
	}

	public String encodeURL(String url) {
		return null;
	}

	public String encodeRedirectURL(String url) {
		return null;
	}

	public String encodeUrl(String url) {
		return null;
	}

	public String encodeRedirectUrl(String url) {
		return null;
	}

	public void sendError(int sc, String msg) throws IOException {
		this.status = sc;
		this.statusMessage = msg;
	}

	public void sendError(int sc) throws IOException {
		this.status = sc;
	}

	public void sendRedirect(String location) throws IOException {
		this.location = location;
	}

	public void setDateHeader(String name, long date) {

	}

	public void addDateHeader(String name, long date) {

	}

	public void setHeader(String name, String value) {
		this.header.put(name, value);
	}

	public void addHeader(String name, String value) {
		this.header.put(name, value);
	}

	public void setIntHeader(String name, int value) {
		this.header.put(name, String.valueOf(value));
	}

	public void addIntHeader(String name, int value) {
		this.header.put(name, String.valueOf(value));
	}

	public void setStatus(int sc) {
		this.status = sc;
	}

	public void setStatus(int sc, String sm) {
		this.status = sc;
		this.statusMessage = sm;
	}

	public int getStatus() {
		return this.status;
	}

	public String getHeader(String name) {
		return header.get(name);
	}

	public Collection<String> getHeaders(String name) {
		Collection<String> headerList = new HashSet<>();
		headerList.add(header.get(name));
		return headerList;
	}

	public Collection<String> getHeaderNames() {
		Set<String> headers = new HashSet<String>();

		headers.addAll(header.keySet());
		return headers;
	}

	public String getCharacterEncoding() {
		return charset;
	}

	public String getContentType() {
		return contentType;
	}

	public ServletOutputStream getOutputStream() throws IOException {
		return new ServletOutputStream() {
			@Override
			public void write(int b) throws IOException {
				out.write(b);
			}
		};
	}

	public PrintWriter getWriter() throws IOException {
		return new PrintWriter(out);
	}

	public void setCharacterEncoding(String charset) {
		this.charset = charset;
	}

	public void setContentLength(int len) {
		this.contentLength = len;
	}

	public void setContentType(String type) {
		this.contentType = type;
	}

	public void setBufferSize(int size) {

	}

	public int getBufferSize() {
		return 0;
	}

	public void flushBuffer() throws IOException {

	}

	public void resetBuffer() {

	}

	public boolean isCommitted() {
		return false;
	}

	public void reset() {

	}

	public void setLocale(Locale loc) {

	}

	public Locale getLocale() {
		return null;
	}

	public String getMessage() {
		return statusMessage;
	}

}
