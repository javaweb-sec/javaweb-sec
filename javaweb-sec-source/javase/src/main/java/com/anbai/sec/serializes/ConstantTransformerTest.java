package com.anbai.sec.serializes;

import org.apache.commons.collections.functors.ConstantTransformer;

public class ConstantTransformerTest {

	public static void main(String[] args) {
		Object              obj         = Runtime.class;
		ConstantTransformer transformer = new ConstantTransformer(obj);
		System.out.println(transformer.transform(obj));
	}

}
