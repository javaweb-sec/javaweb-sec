package com.anbai.sec.test.springboot.service.impl;

import com.anbai.sec.test.springboot.entity.SysLinks;
import com.anbai.sec.test.springboot.repository.SysLinksRepository;
import com.anbai.sec.test.springboot.service.SysLinksService;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

/**
 * @author yz
 */
@Service
public class SysLinksServiceImpl implements SysLinksService {

	@Resource
	private SysLinksRepository sysLinksRepository;

	@Override
	public List<SysLinks> findAll() {
		return sysLinksRepository.findAll();
	}

}
