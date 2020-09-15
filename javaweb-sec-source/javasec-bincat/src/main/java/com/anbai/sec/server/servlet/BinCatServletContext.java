package com.anbai.sec.server.servlet;

import com.anbai.sec.server.loader.BinCatWebAppClassLoader;

import javax.servlet.*;
import javax.servlet.descriptor.JspConfigDescriptor;
import java.io.File;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

public class BinCatServletContext implements ServletContext {

	// 创建ServletContext对象
	private final Map<String, Servlet> servletMap = new HashMap<>();

	private final Map<String, String> initParameterMap = new HashMap<>();

	private final Map<String, Object> attributeMap = new HashMap<>();

	private final Set<BinCatServletRegistrationDynamic> registrationDynamics = new LinkedHashSet<>();

	private final BinCatWebAppClassLoader appClassLoader;

	public BinCatServletContext(BinCatWebAppClassLoader appClassLoader) throws Exception {
		this.appClassLoader = appClassLoader;
	}

	@Override
	public String getContextPath() {
		return null;
	}

	@Override
	public ServletContext getContext(String uriPath) {
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
		Set<Servlet> servlets = new HashSet<Servlet>(servletMap.values());
		return Collections.enumeration(servlets);
	}

	@Override
	public Enumeration<String> getServletNames() {
		Set<String> servlets = new HashSet<String>(servletMap.keySet());
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

	public Map<String, String> getInitParameterMap() {
		return initParameterMap;
	}

	@Override
	public String getInitParameter(String name) {
		return initParameterMap.get(name);
	}

	@Override
	public Enumeration<String> getInitParameterNames() {
		return Collections.enumeration(initParameterMap.keySet());
	}

	@Override
	public boolean setInitParameter(String name, String value) {
		if (!initParameterMap.containsKey(name)) {
			initParameterMap.put(name, value);

			return true;
		}

		return false;
	}

	@Override
	public Object getAttribute(String name) {
		return attributeMap.get(name);
	}

	@Override
	public Enumeration<String> getAttributeNames() {
		return Collections.enumeration(attributeMap.keySet());
	}

	@Override
	public void setAttribute(String name, Object object) {
		attributeMap.put(name, object);
	}

	@Override
	public void removeAttribute(String name) {
		attributeMap.remove(name);
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
		servletMap.put(servletName, servlet);

		BinCatServletRegistrationDynamic dynamic = new BinCatServletRegistrationDynamic(servletName, servlet, this);
		registrationDynamics.add(dynamic);

		return dynamic;
	}

	@Override
	public ServletRegistration.Dynamic addServlet(String servletName, Class<? extends Servlet> servletClass) {
		return null;
	}

	@Override
	public <T extends Servlet> T createServlet(Class<T> clazz) throws ServletException {
		return null;
	}

//	private ServletRegistration.Dynamic addServlet(
//			String servletName, String servletClass,
//			Servlet servlet, Map<String, String> initParams) throws IllegalStateException {
//
//		if (servletName == null || servletName.equals("")) {
//			throw new IllegalArgumentException(sm.getString(
//					"applicationContext.invalidServletName", servletName));
//		}
//
//		if (!context.getState().equals(LifecycleState.STARTING_PREP)) {
//			//TODO Spec breaking enhancement to ignore this restriction
//			throw new IllegalStateException(
//					sm.getString("applicationContext.addServlet.ise",
//							getContextPath()));
//		}
//
//		Wrapper wrapper = (Wrapper) context.findChild(servletName);
//
//		// Assume a 'complete' ServletRegistration is one that has a class and
//		// a name
//		if (wrapper == null) {
//			wrapper = context.createWrapper();
//			wrapper.setName(servletName);
//			context.addChild(wrapper);
//		} else {
//			if (wrapper.getName() != null &&
//					wrapper.getServletClass() != null) {
//				if (wrapper.isOverridable()) {
//					wrapper.setOverridable(false);
//				} else {
//					return null;
//				}
//			}
//		}
//
//		ServletSecurity annotation = null;
//		if (servlet == null) {
//			wrapper.setServletClass(servletClass);
//			Class<?> clazz = Introspection.loadClass(context, servletClass);
//			if (clazz != null) {
//				annotation = clazz.getAnnotation(ServletSecurity.class);
//			}
//		} else {
//			wrapper.setServletClass(servlet.getClass().getName());
//			wrapper.setServlet(servlet);
//			if (context.wasCreatedDynamicServlet(servlet)) {
//				annotation = servlet.getClass().getAnnotation(ServletSecurity.class);
//			}
//		}
//
//		if (initParams != null) {
//			for (Map.Entry<String, String> initParam: initParams.entrySet()) {
//				wrapper.addInitParameter(initParam.getKey(), initParam.getValue());
//			}
//		}
//
//		ServletRegistration.Dynamic registration = new ServletRegistration(wrapper, context);
//		if (annotation != null) {
//			registration.setServletSecurity(new ServletSecurityElement(annotation));
//		}
//
//		ServletRegistration.Dynamic registration = new BinCatServletRegistrationDynamic(this);
//
//		return registration;
//	}

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
		return this.appClassLoader;
	}

	@Override
	public void declareRoles(String... roleNames) {

	}

	public Map<String, Servlet> getServletMap() {
		return servletMap;
	}

	public Set<BinCatServletRegistrationDynamic> getRegistrationDynamics() {
		return registrationDynamics;
	}

}
