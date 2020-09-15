package com.anbai.sec.test.springboot.service.impl;

import com.anbai.sec.test.springboot.commons.JPAPage;
import com.anbai.sec.test.springboot.commons.SearchCondition;
import com.anbai.sec.test.springboot.entity.SysComments;
import com.anbai.sec.test.springboot.repository.SysCommentsRepository;
import com.anbai.sec.test.springboot.service.SysCommentService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import javax.persistence.criteria.Path;
import javax.persistence.criteria.Predicate;
import java.util.ArrayList;
import java.util.List;

/**
 * @author yz
 */
@Service
public class SysCommentServiceImpl implements SysCommentService {

	@Resource
	private SysCommentsRepository sysCommentsRepository;

	@Override
	public Page<SysComments> search(SysComments comments, SearchCondition condition) {
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

	@Override
	public void addSysComments(SysComments comments) {
		sysCommentsRepository.save(comments);
	}

}
