package com.anbai.sec.test.springboot.service.impl;

import com.anbai.sec.test.springboot.commons.JPAPage;
import com.anbai.sec.test.springboot.commons.SearchCondition;
import com.anbai.sec.test.springboot.entity.SysPosts;
import com.anbai.sec.test.springboot.entity.SysPostsCategory;
import com.anbai.sec.test.springboot.repository.SysPostsRepository;
import com.anbai.sec.test.springboot.service.SysPostsService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import javax.persistence.criteria.Path;
import javax.persistence.criteria.Predicate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * @author yz
 */
@Service
public class SysPostsServiceImpl implements SysPostsService {

	@Resource
	private SysPostsRepository sysPostsRepository;

	@Override
	public Page<SysPosts> search(SysPosts posts, SysPostsCategory category, SearchCondition condition) {
		Sort sort = Sort.by(Sort.Direction.DESC, "publishDate");

		return sysPostsRepository.findAll((root, query, cb) -> {
			List<Predicate> ls = new ArrayList<>();

			if (condition.getKeyword() != null) {
				Path<String> mapPath = root.get("postContent");
				ls.add((cb.like(mapPath, "%" + condition.getKeyword() + "%")));
			}

			if (posts.getPostId() > 0) {
				Path<String> mapPath = root.get("postId");
				ls.add((cb.equal(mapPath, posts.getPostId())));
			}

			if (category.getCategoryId() != null) {
				Path<String> mapPath = root.get("categoryId");
				ls.add((cb.equal(mapPath, category.getCategoryId())));
			}

			if (category.getParentId() != null) {
				Path<String> mapPath = root.get("parentId");
				ls.add((cb.equal(mapPath, category.getParentId())));
			}

			if (ls.size() > 0) {
				query.where(ls.toArray(new Predicate[ls.size()]));
			}

			return null;
		}, JPAPage.buildPageRequest(condition.getPage(), condition.getSize(), sort));
	}

	@Override
	public SysPosts getSysPostsById(Integer postId) {
		Optional<SysPosts> optional = sysPostsRepository.findById(postId);

		if (optional.isPresent()) {
			SysPosts sysPosts = optional.get();

			// 修改文章阅读量
			sysPosts.setPostClicks(sysPosts.getPostClicks() + 1);
			sysPostsRepository.save(sysPosts);

			return sysPosts;
		}

		return null;
	}

	@Override
	public void updateCommentCount(Integer postId) {
		Optional<SysPosts> optional = sysPostsRepository.findById(postId);

		if (optional.isPresent()) {
			SysPosts sysPosts = optional.get();
			sysPosts.setCommentCount(sysPosts.getCommentCount() + 1);
			sysPostsRepository.save(sysPosts);
		}
	}

}
