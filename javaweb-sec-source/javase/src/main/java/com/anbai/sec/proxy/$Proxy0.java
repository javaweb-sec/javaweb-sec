package com.anbai.sec.proxy;

import java.io.File;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.lang.reflect.UndeclaredThrowableException;

/**
 * JDK动态代理生成的com.sun.proxy.$Proxy0类反编译后的代码
 */
public final class $Proxy0 extends Proxy implements FileSystem {

	private static Method m1;

// 实现的FileSystem接口方法，如果FileSystem里面有多个方法那么在这个类中将从m3开始n个成员变量
	private static Method m3;

	private static Method m0;

	private static Method m2;

	public $Proxy0(InvocationHandler var1) {
		super(var1);
	}

	public final boolean equals(Object var1) {
		try {
			return (Boolean) super.h.invoke(this, m1, new Object[]{var1});
		} catch (RuntimeException | Error var3) {
			throw var3;
		} catch (Throwable var4) {
			throw new UndeclaredThrowableException(var4);
		}
	}

	public final String[] list(File var1) {
		try {
			return (String[]) super.h.invoke(this, m3, new Object[]{var1});
		} catch (RuntimeException | Error var3) {
			throw var3;
		} catch (Throwable var4) {
			throw new UndeclaredThrowableException(var4);
		}
	}

	public final int hashCode() {
		try {
			return (Integer) super.h.invoke(this, m0, (Object[]) null);
		} catch (RuntimeException | Error var2) {
			throw var2;
		} catch (Throwable var3) {
			throw new UndeclaredThrowableException(var3);
		}
	}

	public final String toString() {
		try {
			return (String) super.h.invoke(this, m2, (Object[]) null);
		} catch (RuntimeException | Error var2) {
			throw var2;
		} catch (Throwable var3) {
			throw new UndeclaredThrowableException(var3);
		}
	}

	static {
		try {
			m1 = Class.forName("java.lang.Object").getMethod("equals", Class.forName("java.lang.Object"));
			m3 = Class.forName("com.anbai.sec.proxy.FileSystem").getMethod("list", Class.forName("java.io.File"));
			m0 = Class.forName("java.lang.Object").getMethod("hashCode");
			m2 = Class.forName("java.lang.Object").getMethod("toString");
		} catch (NoSuchMethodException var2) {
			throw new NoSuchMethodError(var2.getMessage());
		} catch (ClassNotFoundException var3) {
			throw new NoClassDefFoundError(var3.getMessage());
		}
	}
}
