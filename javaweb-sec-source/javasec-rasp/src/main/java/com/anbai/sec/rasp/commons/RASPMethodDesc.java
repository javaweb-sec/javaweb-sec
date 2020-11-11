/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.commons;

import javassist.CtClass;

/**
 * Creator: yz
 * Date: 2019-06-28
 */
public class RASPMethodDesc {

    private final int methodAccess;

    private final String methodSignature;

    private final String[] exceptions;

    private final String methodName;

    public RASPMethodDesc(int methodAccess, String methodSignature, CtClass[] exceptions, String methodName) {
        this.methodAccess = methodAccess;
        this.methodSignature = methodSignature;
        this.exceptions = new String[exceptions.length];

        for (int i = 0; i < exceptions.length; i++) {
            this.exceptions[i] = exceptions[i].getName();
        }

        this.methodName = methodName;
    }

    public int getMethodAccess() {
        return methodAccess;
    }

    public String getMethodSignature() {
        return methodSignature;
    }

    public String[] getExceptions() {
        return exceptions;
    }

    public String getMethodName() {
        return methodName;
    }

}
