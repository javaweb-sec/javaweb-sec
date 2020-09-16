package com.anbai.sec.blog.entity;

import javax.persistence.*;
import java.io.Serializable;

@Entity
@Table(name = "sys_config")
public class SysConfig implements Serializable {

	private static final long serialVersionUID = -1105560324715857646L;

	/**
	 * 配置Id
	 */
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer id;

	/**
	 * 配置key(键名)
	 */
	private String configKey;

	/**
	 * 配置value(值)
	 */
	private String configValue;

	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public String getConfigKey() {
		return configKey;
	}

	public void setConfigKey(String configKey) {
		this.configKey = configKey;
	}

	public String getConfigValue() {
		return configValue;
	}

	public void setConfigValue(String configValue) {
		this.configValue = configValue;
	}

}
