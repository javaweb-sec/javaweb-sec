package com.anbai.sec.vuls.dao;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Creator: yz
 * Date: 2020-05-04
 */
@Component
public class SysConfigDAO {

	@Resource
	private JdbcTemplate jdbcTemplate;

	public Map<String, Object> getSysConfig() {
		String sql = "select * from sys_config";

		Map<String, Object>       configMap     = new HashMap<String, Object>();
		List<Map<String, Object>> sysConfigList = jdbcTemplate.queryForList(sql);

		for (Map<String, Object> config : sysConfigList) {
			configMap.put((String) config.get("config_key"), config.get("config_value"));
		}

		return configMap;
	}

}
