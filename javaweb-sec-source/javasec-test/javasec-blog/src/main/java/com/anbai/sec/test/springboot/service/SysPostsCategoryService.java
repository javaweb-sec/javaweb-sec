package com.anbai.sec.test.springboot.service;

import com.anbai.sec.test.springboot.entity.SysPostsCategory;

import java.util.List;

/**
 * @author yz
 */
public interface SysPostsCategoryService {

	List<SysPostsCategory> getSysPostsCategoryByParentId(Integer parentId);

}
