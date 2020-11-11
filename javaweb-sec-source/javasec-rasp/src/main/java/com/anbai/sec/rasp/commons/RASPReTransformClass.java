/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.commons;

import java.util.Arrays;

/**
 * ReTransform 配置
 * Creator: yz
 * Date: 2019-07-30
 */
public class RASPReTransformClass {

	private String className;

	private String superClassName;

	private String[] classAnnotations;

	private String[] methodAnnotations;

	public String getClassName() {
		return className;
	}

	public void setClassName(String className) {
		this.className = className;
	}

	public String getSuperClassName() {
		return superClassName;
	}

	public void setSuperClassName(String superClassName) {
		this.superClassName = superClassName;
	}

	public String[] getClassAnnotations() {
		return classAnnotations;
	}

	public void setClassAnnotations(String[] classAnnotations) {
		this.classAnnotations = classAnnotations;
	}

	public String[] getMethodAnnotations() {
		return methodAnnotations;
	}

	public void setMethodAnnotations(String[] methodAnnotations) {
		this.methodAnnotations = methodAnnotations;
	}

	@Override
	public String toString() {
		return "RASPReTransformClass{" +
				"className='" + className + '\'' +
				", superClassName='" + superClassName + '\'' +
				", classAnnotations=" + Arrays.toString(classAnnotations) +
				", methodAnnotations=" + Arrays.toString(methodAnnotations) +
				'}';
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}

		if (o == null || getClass() != o.getClass()) {
			return false;
		}

		RASPReTransformClass that = (RASPReTransformClass) o;

		if (className != null ? !className.equals(that.className) : that.className != null) {
			return false;
		}

		if (superClassName != null ? !superClassName.equals(that.superClassName) : that.superClassName != null) {
			return false;
		}

		// Probably incorrect - comparing Object[] arrays with Arrays.equals
		if (!Arrays.equals(classAnnotations, that.classAnnotations)) {
			return false;
		}

		// Probably incorrect - comparing Object[] arrays with Arrays.equals
		return Arrays.equals(methodAnnotations, that.methodAnnotations);
	}

	@Override
	public int hashCode() {
		int result = className != null ? className.hashCode() : 0;
		result = 31 * result + (superClassName != null ? superClassName.hashCode() : 0);
		result = 31 * result + Arrays.hashCode(classAnnotations);
		result = 31 * result + Arrays.hashCode(methodAnnotations);

		return result;
	}

}
