package com.anbai.sec.server.test.servlet;

import com.caucho.quercus.servlet.QuercusServlet;

import javax.servlet.annotation.WebServlet;

@WebServlet(name = "QuercusPHPServlet", urlPatterns = ".*\\.php$")
public class QuercusPHPServlet extends QuercusServlet {


}
