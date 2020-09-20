package com.anbai.sec.osgi;

import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHandler;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;

import java.util.Hashtable;

public class Activator implements BundleActivator {

	private static BundleContext context;

	static BundleContext getContext() {
		return context;
	}
	
	public void start(BundleContext bundleContext) throws Exception {
		Activator.context = bundleContext;

		//1. We create a Servlet Handler
		ServletHandler handler = new ServletHandler();

		//2. We register our Servlet and its URL mapping
		handler.addServletWithMapping(JcgServlet.class, "/*");

		//3. We are creating a Servlet Context handler
		ServletContextHandler ch = new ServletContextHandler();

		//4. We are defining the context path
		ch.setContextPath("/servlet");

		//5. We are attaching our servlet handler
		ch.setServletHandler(handler);

		//6. We are creating an empty Hashtable as the properties
		Hashtable props = new Hashtable();

		// 7. Here we register the ServletContextHandler as the OSGi service
		bundleContext.registerService(ContextHandler.class.getName(), ch, props);

		System.out.println("Registration Complete");
	}


	public void stop(BundleContext bundleContext) throws Exception {
		Activator.context = null;
	}

}