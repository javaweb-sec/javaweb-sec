package com.anbai.sec.test.springboot.service.impl;

import com.anbai.sec.test.springboot.repository.SysConfigRepository;
import com.anbai.sec.test.springboot.service.SysConfigService;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.HashMap;
import java.util.Map;

/**
 * @author yz
 */
@Service
public class SysConfigServiceImpl implements SysConfigService {

	@Resource
	private SysConfigRepository sysConfigRepository;

	@Override
	public Map<String, Object> getSysConfig() {
		Map<String, Object> configMap = new HashMap<>();

		sysConfigRepository.findAll().forEach(config -> {
			configMap.put(config.getConfigKey(), config.getConfigValue());
		});

		return configMap;
	}

}
