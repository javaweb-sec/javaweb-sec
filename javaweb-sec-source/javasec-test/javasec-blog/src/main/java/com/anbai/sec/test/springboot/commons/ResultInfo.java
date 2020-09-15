package com.anbai.sec.test.springboot.commons;

import java.io.Serializable;

public class ResultInfo implements Serializable {

	private static final long serialVersionUID = 5809537318660176489L;

	private int code;

	private String msg;

	private boolean valid = false;

	private String description;

	private Object data = new Object();

	public ResultInfo() {
		super();
	}

	public ResultInfo(String msg, boolean valid) {
		super();
		this.valid = valid;
		this.msg = msg;
	}

	public ResultInfo(Object data, boolean valid) {
		this.data = data;
		this.valid = valid;
	}

	public int getCode() {
		return code;
	}

	public void setCode(int code) {
		this.code = code;
	}

	public String getMsg() {
		return msg;
	}

	public void setMsg(String msg) {
		this.msg = msg;
	}

	public boolean isValid() {
		return valid;
	}

	public void setValid(boolean valid) {
		this.valid = valid;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public Object getData() {
		return data;
	}

	public void setData(Object data) {
		this.data = data;
	}

}
