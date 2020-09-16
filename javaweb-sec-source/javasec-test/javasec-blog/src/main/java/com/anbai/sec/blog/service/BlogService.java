package com.anbai.sec.blog.service;

import com.anbai.sec.blog.commons.SearchCondition;
import com.anbai.sec.blog.entity.*;
import com.anbai.sec.blog.repository.*;
import org.javaweb.utils.StringUtils;
import org.jsoup.Jsoup;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
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
	private SysLinksRepository sysLinksRepository;

	@Resource
	private SysPostsRepository sysPostsRepository;

	@Resource
	private SysUserRepository sysUserRepository;

	@Resource
	private SysPostsCategoryRepository sysPostsCategoryRepository;

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
				query.where(ls.toArray(new Predicate[0]));
			}

			return null;
		}, PageRequest.of(condition.getPage() - 1, condition.getSize(), sort));
	}

	public void addSysComments(SysComments comments) {
		sysCommentsRepository.save(comments);
		updateCommentCount(comments.getCommentPostId());
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

	public Page<SysPosts> searchSysPost(Integer catId, Integer catParentId, SearchCondition condition) {
		Sort sort = Sort.by(Sort.Direction.DESC, "publishDate");

		Page<SysPosts> sysPostsPage = sysPostsRepository.findAll((root, query, cb) -> {
			List<Predicate> ls = new ArrayList<>();

			if (StringUtils.isNotEmpty(condition.getKeyword())) {
				Path<String> mapPath = root.get("postContent");
				ls.add((cb.like(mapPath, "%" + condition.getKeyword() + "%")));
			}

			if (catId != null) {
				Path<String> mapPath = root.get("categoryId");
				ls.add((cb.equal(mapPath, catId)));
			}

			if (catParentId != null) {
				Path<String> mapPath = root.get("parentId");
				ls.add((cb.equal(mapPath, catParentId)));
			}

			if (ls.size() > 0) {
				query.where(ls.toArray(new Predicate[0]));
			}

			return null;
		}, PageRequest.of(condition.getPage() - 1, condition.getSize(), sort));

		// 文章内容截取，最多不超过500个字符
		for (SysPosts sysPosts : sysPostsPage.getContent()) {
			String content = sysPosts.getPostContent();

			if (StringUtils.isNotEmpty(content)) {
				content = Jsoup.parse(content).text();
				int maxLen = 500;
				int len    = Math.min(content.length(), maxLen);
				sysPosts.setPostContent(content.substring(0, len));
			}
		}

		return sysPostsPage;
	}

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

	public List<SysPostsCategory> getSysPostsCategoryByParentId(int parentId) {
		return sysPostsCategoryRepository.findByParentIdOrderByCategoryOrder(parentId);
	}

	public List<SysPostsCategory> getSysPostsCategoryByParentIdNotEqual(int parentId) {
		return sysPostsCategoryRepository.findByParentIdNotOrderByCategoryOrderAsc(parentId);
	}

}
