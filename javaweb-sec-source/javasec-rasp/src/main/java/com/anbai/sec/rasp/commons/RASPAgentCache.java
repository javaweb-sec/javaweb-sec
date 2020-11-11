/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.commons;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * 灵蜥Agent缓存类
 * Creator: yz
 * Date: 2019-08-19
 */
public class RASPAgentCache {

	private Instrumentation instrumentation;

	private Set<String> modifiedClass = Collections.synchronizedSet(new HashSet<String>());

	private Set<String> reTransformClass = Collections.synchronizedSet(new HashSet<String>());

	private ClassFileTransformer transformer;

	public RASPAgentCache(Instrumentation instrumentation, ClassFileTransformer classFileTransformer) {
		this.instrumentation = instrumentation;
		this.transformer = classFileTransformer;
	}

	public Instrumentation getInstrumentation() {
		return instrumentation;
	}

	public Set<String> getModifiedClass() {
		return modifiedClass;
	}

	public ClassFileTransformer getTransformer() {
		return transformer;
	}

	public Set<String> getReTransformClass() {
		return reTransformClass;
	}

}
