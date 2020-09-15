package com.anbai.sec.test.springboot.service;

import com.anbai.sec.test.springboot.commons.JPAPage;
import com.anbai.sec.test.springboot.commons.SearchCondition;
import com.anbai.sec.test.springboot.entity.*;
import com.anbai.sec.test.springboot.repository.*;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import javax.persistence.criteria.Path;
import javax.persistence.criteria.Predicate;
import java.util.*;

@Service
public class BlogService {

	@Resource
	private SysCommentsRepository sysCommentsRepository;

	@Resource
	private SysConfigRepository sysConfigRepository;

	@Resource
	private SysPostsCategoryRepository sysPostsCategoryRepository;

	@Resource
	private SysLinksRepository sysLinksRepository;

	@Resource
	private SysPostsRepository sysPostsRepository;

	@Resource
	private SysUserRepository sysUserRepository;

	public Page<SysComments> searchSysComment(SysComments comments, SearchCondition condition) {
		Sort sort = Sort.by(Sort.Direction.DESC, "commentId");

		return sysCommentsRepository.findAll((root, query, cb) -> {
			List<Predicate> ls = new ArrayList<>();

			if (condition.getKeyword() != null) {
				Path<String> mapPath = root.get("commentContent");
				ls.add((cb.like(mapPath, "%" + condition.getKeyword() + "%")));
			}

			if (comments.getCommentPostId() != null) {
				Path<String> mapPath = root.get("commentPostId");
				ls.add((cb.equal(mapPath, comments.getCommentPostId())));
			}

			if (comments.getCommentUserId() != null) {
				Path<String> mapPath = root.get("commentUserId");
				ls.add((cb.equal(mapPath, comments.getCommentUserId())));
			}

			if (comments.getCommentAuthor() != null) {
				Path<String> mapPath = root.get("commentAuthor");
				ls.add((cb.equal(mapPath, comments.getCommentAuthor())));
			}

			if (comments.getCommentAuthorEmail() != null) {
				Path<String> mapPath = root.get("commentAuthorEmail");
				ls.add((cb.equal(mapPath, comments.getCommentAuthorEmail())));
			}

			if (comments.getCommentAuthorIp() != null) {
				Path<String> mapPath = root.get("commentAuthorIp");
				ls.add((cb.equal(mapPath, comments.getCommentAuthorIp())));
			}

			if (ls.size() > 0) {
				query.where(ls.toArray(new Predicate[ls.size()]));
			}

			return null;
		}, JPAPage.buildPageRequest(condition.getPage(), condition.getSize(), sort));
	}

	public void addSysComments(SysComments comments) {
		sysCommentsRepository.save(comments);
	}

	public Map<String, Object> getSysConfig() {
		Map<String, Object> configMap = new HashMap<>();

		sysConfigRepository.findAll().forEach(config -> {
			configMap.put(config.getConfigKey(), config.getConfigValue());
		});

		return configMap;
	}

	public List<SysLinks> getAllSysLinks() {
		return sysLinksRepository.findAll();
	}

	public List<SysPostsCategory> getSysPostsCategoryByParentId(Integer parentId) {
		return sysPostsCategoryRepository.findByParentIdOrderByCategoryOrder(parentId);
	}

	public Page<SysPosts> searchSysPost(SysPosts posts, SysPostsCategory category, SearchCondition condition) {
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

	public SysPosts getSysPostsById(Integer postId) {
		Optional<SysPosts> optional = sysPostsRepository.findById(postId);

		SysPosts sysPosts = optional.get();

		// 修改文章阅读量
		sysPosts.setPostClicks(sysPosts.getPostClicks() + 1);
		sysPostsRepository.save(sysPosts);

		return sysPosts;
	}

	public void updateCommentCount(Integer postId) {
		Optional<SysPosts> optional = sysPostsRepository.findById(postId);

		if (optional.isPresent()) {
			SysPosts sysPosts = optional.get();
			sysPosts.setCommentCount(sysPosts.getCommentCount() + 1);
			sysPostsRepository.save(sysPosts);
		}
	}

	public SysUser getSysUserById(Integer userId) {
		return sysUserRepository.getOne(userId);
	}

	public SysUser setUser(SysUser user) {
		SysUser u = sysUserRepository.getOne(user.getUserId());

		u.setNick(user.getNick());
		u.setUsername(user.getUsername());

		return sysUserRepository.save(user);
	}

}
