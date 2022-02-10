package com.anbai.shiro.spring.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import com.anbai.shiro.spring.Service.PluginService;
import com.anbai.shiro.spring.data.PluginRequest;

import javax.annotation.Resource;
import java.util.HashMap;
import java.util.Map;

/**
 * @author su18
 */
@RestController
@RequestMapping(value = "/plugin")
public class PluginController {

	@Resource
	private PluginService pluginService;

	@PostMapping("/add")
	public String create(@RequestPart(value = "file", required = false) MultipartFile file) {
		return pluginService.editPlugin(file);
	}

	@PostMapping(value = "/customMethod")
	@ResponseBody
	public Object customMethod(@RequestBody PluginRequest request) {
		Map<String, Object> result = new HashMap<>(16);
		result.put("success", true);
		result.put("message","");
		result.put("data",  pluginService.customMethod(request));
		return result;
	}

}