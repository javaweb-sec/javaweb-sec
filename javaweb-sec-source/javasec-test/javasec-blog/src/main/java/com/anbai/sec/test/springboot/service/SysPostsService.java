package com.anbai.sec.test.springboot.service;

import com.anbai.sec.test.springboot.commons.SearchCondition;
import com.anbai.sec.test.springboot.entity.SysPosts;
import com.anbai.sec.test.springboot.entity.SysPostsCategory;
import org.springframework.data.domain.Page;

/**
 * @author yz
 */
public interface SysPostsService {

	Page<SysPosts> search(SysPosts posts, SysPostsCategory category, SearchCondition condition);

	SysPosts getSysPostsById(Integer postId);

	void updateCommentCount(Integer postId);

}
