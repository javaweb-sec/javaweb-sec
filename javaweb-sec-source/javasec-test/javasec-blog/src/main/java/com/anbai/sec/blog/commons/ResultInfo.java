package com.anbai.sec.blog.commons;

public class ResultInfo<T> {

	private Integer code;

	private String msg;

	private Boolean valid = false;

	private String description;

	private T data;

	public ResultInfo() {
	}

	public ResultInfo(String msg, Boolean valid) {
		this.valid = valid;
		this.msg = msg;
	}

	public ResultInfo(T data, Boolean valid) {
		this.data = data;
		this.valid = valid;
	}

	public ResultInfo(T data) {
		this.data = data;
		this.valid = true;
	}

	public Integer getCode() {
		return code;
	}

	public void setCode(Integer code) {
		this.code = code;
	}

	public String getMsg() {
		return msg;
	}

	public void setMsg(String msg) {
		this.msg = msg;
	}

	public Boolean getValid() {
		return valid;
	}

	public void setValid(Boolean valid) {
		this.valid = valid;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public T getData() {
		return data;
	}

	public void setData(T data) {
		this.data = data;
	}

}
