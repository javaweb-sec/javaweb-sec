/*
 * Copyright yz 2016-01-14  Email:admin@javaweb.org.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.anbai.sec.vuls.commons;

import java.io.Serializable;

/**
 * 返回结果信息对象
 *
 * @param <T>
 */
public class ResultInfo<T> implements Serializable {

	private static final long serialVersionUID = -1950220254616398870L;

	/**
	 * 结果消息编码
	 */
	private int code = MessageCode.DEFAULT_MESSAGE.getCode();

	/**
	 * 消息信息
	 */
	private String msg;

	/**
	 * 是否验证通过
	 */
	private boolean valid = false;

	/**
	 * 返回的结果描述信息
	 */
	private String description;

	/**
	 * 返回的响应数据
	 */
	private T data;

	public ResultInfo() {
	}

	public ResultInfo(String msg, boolean valid) {
		this.valid = valid;
		this.msg = msg;
	}

	public ResultInfo(T data, boolean valid) {
		this.data = data;
		this.valid = valid;
	}

	/**
	 * 获取结果消息编码
	 *
	 * @return
	 */
	public int getCode() {
		return code;
	}

	/**
	 * 设置结果消息编码
	 *
	 * @param code
	 */
	public void setCode(int code) {
		this.code = code;
	}

	/**
	 * 获取消息信息
	 *
	 * @return
	 */
	public String getMsg() {
		return msg;
	}

	/**
	 * 设置消息信息
	 *
	 * @param msg
	 */
	public void setMsg(String msg) {
		this.msg = msg;
	}

	/**
	 * 检测是否验证通过
	 *
	 * @return
	 */
	public boolean isValid() {
		return valid;
	}

	/**
	 * 设置是否验证通过
	 * @param valid
	 */
	public void setValid(boolean valid) {
		this.valid = valid;
	}

	/**
	 * 获取返回描述信息
	 *
	 * @return
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * 设置返回描述信息
	 *
	 * @param description
	 */
	public void setDescription(String description) {
		this.description = description;
	}

	/**
	 * 获取响应数据
	 *
	 * @return
	 */
	public T getData() {
		return data;
	}

	/**
	 * 设置响应数据
	 *
	 * @param data
	 */
	public void setData(T data) {
		this.data = data;
	}

	/**
	 * 设置响应消息信息
	 *
	 * @param messageCode
	 */
	public void setMessageCode(MessageCode messageCode) {
		this.code = messageCode.getCode();
		this.msg = messageCode.getMessage();
	}

}
