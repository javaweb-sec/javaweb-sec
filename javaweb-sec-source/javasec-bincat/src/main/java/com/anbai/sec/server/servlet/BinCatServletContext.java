package com.anbai.sec.server.servlet;

import javax.servlet.*;
import javax.servlet.annotation.WebServlet;
import javax.servlet.descriptor.JspConfigDescriptor;
import java.io.File;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class BinCatServletContext implements ServletContext {

	// 创建ServletContext对象
	Map<String, Servlet> servletMap = new ConcurrentHashMap<String, Servlet>();

	public BinCatServletContext(Set<Class<? extends Servlet>> servletList) throws Exception {
		for (Class<? extends Servlet> clazz : servletList) {
			WebServlet webServlet  = clazz.getAnnotation(WebServlet.class);
			String     servletName = webServlet.name();
			Servlet    httpServlet = clazz.newInstance();

			servletMap.put(servletName, httpServlet);

			httpServlet.init(new BinCatServletConfig(this, webServlet));
		}
	}

	@Override
	public String getContextPath() {
		return null;
	}

	@Override
	public ServletContext getContext(String uripath) {
		return null;
	}

	@Override
	public int getMajorVersion() {
		return 3;
	}

	@Override
	public int getMinorVersion() {
		return 0;
	}

	@Override
	public int getEffectiveMajorVersion() {
		return 0;
	}

	@Override
	public int getEffectiveMinorVersion() {
		return 0;
	}

	@Override
	public String getMimeType(String file) {
		return null;
	}

	@Override
	public Set<String> getResourcePaths(String path) {
		return null;
	}

	@Override
	public URL getResource(String path) throws MalformedURLException {
		return null;
	}

	@Override
	public InputStream getResourceAsStream(String path) {
		return null;
	}

	@Override
	public RequestDispatcher getRequestDispatcher(String path) {
		return null;
	}

	@Override
	public RequestDispatcher getNamedDispatcher(String name) {
		return null;
	}

	@Override
	public Servlet getServlet(String name) throws ServletException {
		return servletMap.get(name);
	}

	@Override
	public Enumeration<Servlet> getServlets() {
		Set<Servlet> servlets = new HashSet<Servlet>();
		servlets.addAll(servletMap.values());

		return Collections.enumeration(servlets);
	}

	@Override
	public Enumeration<String> getServletNames() {
		Set<String> servlets = new HashSet<String>();
		servlets.addAll(servletMap.keySet());

		return Collections.enumeration(servlets);
	}

	@Override
	public void log(String msg) {

	}

	@Override
	public void log(Exception exception, String msg) {

	}

	@Override
	public void log(String message, Throwable throwable) {

	}

	@Override
	public String getRealPath(String path) {
		return new File(System.getProperty("user.dir"), path).getAbsolutePath();
	}

	@Override
	public String getServerInfo() {
		return null;
	}

	@Override
	public String getInitParameter(String name) {
		return null;
	}

	@Override
	public Enumeration<String> getInitParameterNames() {
		return null;
	}

	@Override
	public boolean setInitParameter(String name, String value) {
		return false;
	}

	@Override
	public Object getAttribute(String name) {
		return null;
	}

	@Override
	public Enumeration<String> getAttributeNames() {
		return null;
	}

	@Override
	public void setAttribute(String name, Object object) {

	}

	@Override
	public void removeAttribute(String name) {

	}

	@Override
	public String getServletContextName() {
		return null;
	}

	@Override
	public ServletRegistration.Dynamic addServlet(String servletName, String className) {
		return null;
	}

	@Override
	public ServletRegistration.Dynamic addServlet(String servletName, Servlet servlet) {
		return null;
	}

	@Override
	public ServletRegistration.Dynamic addServlet(String servletName, Class<? extends Servlet> servletClass) {
		return null;
	}

	@Override
	public <T extends Servlet> T createServlet(Class<T> clazz) throws ServletException {
		return null;
	}

	@Override
	public ServletRegistration getServletRegistration(String servletName) {
		return null;
	}

	@Override
	public Map<String, ? extends ServletRegistration> getServletRegistrations() {
		return null;
	}

	@Override
	public FilterRegistration.Dynamic addFilter(String filterName, String className) {
		return null;
	}

	@Override
	public FilterRegistration.Dynamic addFilter(String filterName, Filter filter) {
		return null;
	}

	@Override
	public FilterRegistration.Dynamic addFilter(String filterName, Class<? extends Filter> filterClass) {
		return null;
	}

	@Override
	public <T extends Filter> T createFilter(Class<T> clazz) throws ServletException {
		return null;
	}

	@Override
	public FilterRegistration getFilterRegistration(String filterName) {
		return null;
	}

	@Override
	public Map<String, ? extends FilterRegistration> getFilterRegistrations() {
		return null;
	}

	@Override
	public SessionCookieConfig getSessionCookieConfig() {
		return null;
	}

	@Override
	public void setSessionTrackingModes(Set<SessionTrackingMode> sessionTrackingModes) {

	}

	@Override
	public Set<SessionTrackingMode> getDefaultSessionTrackingModes() {
		return null;
	}

	@Override
	public Set<SessionTrackingMode> getEffectiveSessionTrackingModes() {
		return null;
	}

	@Override
	public void addListener(String className) {

	}

	@Override
	public <T extends EventListener> void addListener(T t) {

	}

	@Override
	public void addListener(Class<? extends EventListener> listenerClass) {

	}

	@Override
	public <T extends EventListener> T createListener(Class<T> clazz) throws ServletException {
		return null;
	}

	@Override
	public JspConfigDescriptor getJspConfigDescriptor() {
		return null;
	}

	@Override
	public ClassLoader getClassLoader() {
		return null;
	}

	@Override
	public void declareRoles(String... roleNames) {

	}

}
