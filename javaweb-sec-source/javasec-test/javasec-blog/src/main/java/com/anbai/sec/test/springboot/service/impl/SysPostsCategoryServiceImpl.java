package com.anbai.sec.test.springboot.service.impl;

import com.anbai.sec.test.springboot.entity.SysPostsCategory;
import com.anbai.sec.test.springboot.repository.SysPostsCategoryRepository;
import com.anbai.sec.test.springboot.service.SysPostsCategoryService;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

/**
 * @author yz
 */
@Service
public class SysPostsCategoryServiceImpl implements SysPostsCategoryService {

	@Resource
	private SysPostsCategoryRepository sysPostsCategoryRepository;

	@Override
	public List<SysPostsCategory> getSysPostsCategoryByParentId(Integer parentId) {
		return sysPostsCategoryRepository.findByParentIdOrderByCategoryOrder(parentId);
	}

}
