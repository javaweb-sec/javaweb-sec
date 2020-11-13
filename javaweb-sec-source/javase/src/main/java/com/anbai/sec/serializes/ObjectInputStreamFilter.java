/*
 * 修改自：https://github.com/ikkisoft/SerialKiller
 */
package com.anbai.sec.serializes;

import java.io.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ObjectInputStreamFilter extends ObjectInputStream {

	// 定义禁止反序列化的类黑名单正则表达式
	private static final String[] REGEXPS = new String[]{
			"bsh\\.XThis$", "bsh\\.Interpreter$",
			"com\\.mchange\\.v2\\.c3p0\\.impl\\.PoolBackedDataSourceBase$",
			"org\\.apache\\.commons\\.beanutils\\.BeanComparator$",
			"org\\.apache\\.commons\\.collections\\.Transformer$",
			"org\\.apache\\.commons\\.collections\\.functors\\.InvokerTransformer$",
			"org\\.apache\\.commons\\.collections\\.functors\\.ChainedTransformer$",
			"org\\.apache\\.commons\\.collections\\.functors\\.ConstantTransformer$",
			"org\\.apache\\.commons\\.collections\\.functors\\.InstantiateTransformer$",
			"org\\.apache\\.commons\\.collections4\\.functors\\.InvokerTransformer$",
			"org\\.apache\\.commons\\.collections4\\.functors\\.ChainedTransformer$",
			"org\\.apache\\.commons\\.collections4\\.functors\\.ConstantTransformer$",
			"org\\.apache\\.commons\\.collections4\\.functors\\.InstantiateTransformer$",
			"org\\.apache\\.commons\\.collections4\\.comparators\\.TransformingComparator$",
			"org\\.apache\\.commons\\.fileupload\\.disk\\.DiskFileItem$",
			"org\\.apache\\.wicket\\.util\\.upload\\.DiskFileItem$",
			"org\\.codehaus\\.groovy\\.runtime\\.ConvertedClosure$",
			"org\\.codehaus\\.groovy\\.runtime\\.MethodClosure$",
			"org\\.hibernate\\.engine\\.spi\\.TypedValue$",
			"org\\.hibernate\\.tuple\\.component\\.AbstractComponentTuplizer$",
			"org\\.hibernate\\.tuple\\.component\\.PojoComponentTuplizer$",
			"org\\.hibernate\\.type\\.AbstractType$", "org\\.hibernate\\.type\\.ComponentType$",
			"org\\.hibernate\\.type\\.Type$", "com\\.sun\\.rowset\\.JdbcRowSetImpl$",
			"org\\.jboss\\.(weld\\.)?interceptor\\.builder\\.InterceptionModelBuilder$",
			"org\\.jboss\\.(weld\\.)?interceptor\\.builder\\.MethodReference$",
			"org\\.jboss\\.(weld\\.)?interceptor\\.proxy\\.DefaultInvocationContextFactory$",
			"org\\.jboss\\.(weld\\.)?interceptor\\.proxy\\.InterceptorMethodHandler$",
			"org\\.jboss\\.(weld\\.)?interceptor\\.reader\\.ClassMetadataInterceptorReference$",
			"org\\.jboss\\.(weld\\.)?interceptor\\.reader\\.DefaultMethodMetadata$",
			"org\\.jboss\\.(weld\\.)?interceptor\\.reader\\.ReflectiveClassMetadata$",
			"org\\.jboss\\.(weld\\.)?interceptor\\.reader\\.SimpleInterceptorMetadata$",
			"org\\.jboss\\.(weld\\.)?interceptor\\.spi\\.instance\\.InterceptorInstantiator$",
			"org\\.jboss\\.(weld\\.)?interceptor\\.spi\\.metadata\\.InterceptorReference$",
			"org\\.jboss\\.(weld\\.)?interceptor\\.spi\\.metadata\\.MethodMetadata$",
			"org\\.jboss\\.(weld\\.)?interceptor\\.spi\\.model\\.InterceptionModel$",
			"org\\.jboss\\.(weld\\.)?interceptor\\.spi\\.model\\.InterceptionType$",
			"java\\.rmi\\.registry\\.Registry$", "java\\.rmi\\.server\\.ObjID$",
			"java\\.rmi\\.server\\.RemoteObjectInvocationHandler$",
			"net\\.sf\\.json\\.JSONObject$", "javax\\.xml\\.transform\\.Templates$",
			"org\\.python\\.core\\.PyObject$", "org\\.python\\.core\\.PyBytecode$",
			"org\\.python\\.core\\.PyFunction$", "org\\.mozilla\\.javascript\\..*$",
			"org\\.apache\\.myfaces\\.context\\.servlet\\.FacesContextImpl$",
			"org\\.apache\\.myfaces\\.context\\.servlet\\.FacesContextImplBase$",
			"org\\.apache\\.myfaces\\.el\\.CompositeELResolver$",
			"org\\.apache\\.myfaces\\.el\\.unified\\.FacesELContext$",
			"org\\.apache\\.myfaces\\.view\\.facelets\\.el\\.ValueExpressionMethodExpression$",
			"com\\.sun\\.syndication\\.feed\\.impl\\.ObjectBean$",
			"org\\.springframework\\.beans\\.factory\\.ObjectFactory$",
			"org\\.springframework\\.core\\.SerializableTypeWrapper\\$MethodInvokeTypeProvider$",
			"org\\.springframework\\.aop\\.framework\\.AdvisedSupport$",
			"org\\.springframework\\.aop\\.target\\.SingletonTargetSource$",
			"org\\.springframework\\.aop\\.framework\\.JdkDynamicAopProxy$",
			"org\\.springframework\\.core\\.SerializableTypeWrapper\\$TypeProvider$",
			"java\\.util\\.PriorityQueue$", "java\\.lang\\.reflect\\.Proxy$",
			"javax\\.management\\.MBeanServerInvocationHandler$",
			"javax\\.management\\.openmbean\\.CompositeDataInvocationHandler$",
			"org\\.springframework\\.aop\\.framework\\.JdkDynamicAopProxy$",
			"java\\.beans\\.EventHandler$", "java\\.util\\.Comparator$",
			"org\\.reflections\\.Reflections$"
	};

	public ObjectInputStreamFilter(final InputStream inputStream) throws IOException {
		super(inputStream);
	}

	@Override
	protected Class<?> resolveClass(final ObjectStreamClass serialInput) throws IOException, ClassNotFoundException {
		classNameFilter(new String[]{serialInput.getName()});
		return super.resolveClass(serialInput);
	}

	@Override
	protected Class<?> resolveProxyClass(String[] interfaces) throws IOException, ClassNotFoundException {
		classNameFilter(interfaces);
		return super.resolveProxyClass(interfaces);
	}

	private void classNameFilter(String[] classNames) throws InvalidClassException {
		for (String className : classNames) {
			for (String regexp : REGEXPS) {
				Matcher blackMatcher = Pattern.compile(regexp).matcher(className);

				if (blackMatcher.find()) {
					throw new InvalidClassException("禁止反序列化的类：" + className);
				}
			}
		}
	}

}