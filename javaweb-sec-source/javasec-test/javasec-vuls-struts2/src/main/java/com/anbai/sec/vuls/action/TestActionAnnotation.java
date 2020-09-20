package com.anbai.sec.vuls.action;

import com.opensymphony.xwork2.ActionSupport;
import org.apache.struts2.convention.annotation.Action;
import org.apache.struts2.convention.annotation.Result;

@Action(value = "rasp", results = {@Result(location = "/rasp.jsp")})
public class TestActionAnnotation extends ActionSupport {

	private static final long serialVersionUID = 8221357269652048151L;

	public String execute() {
		return SUCCESS;
	}

}