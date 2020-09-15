package com.anbai.sec.test.springboot.service;

import com.anbai.sec.test.springboot.commons.SearchCondition;
import com.anbai.sec.test.springboot.entity.SysComments;
import org.springframework.data.domain.Page;

/**
 * @author yz
 */
public interface SysCommentService {

	Page<SysComments> search(SysComments comments, SearchCondition condition);

	void addSysComments(SysComments comments);

}
