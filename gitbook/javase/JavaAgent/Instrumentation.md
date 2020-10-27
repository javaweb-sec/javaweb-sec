# Instrumentation

`java.lang.instrument.Instrumentation`是`Java`提供的监测运行在`JVM`程序的`API`。利用`Instrumentation`我们可以实现如下功能：

1. 动态添加自定义的`Transformer(addTransformer)`。
2. 动态修改`classpath(appendToBootstrapClassLoaderSearch、appendToSystemClassLoaderSearch)`。
3. 动态获取所有`JVM`已加载的类(`getAllLoadedClasses`)。
4. 动态获取某个类加载器已实例化的所有类(`getInitiatedClasses`)。
5. 直接修改已加载的类的字节码(`redefineClasses`)。
6. 动态设置`JNI`前缀(`setNativeMethodPrefix`)。
7. 重加载指定类字节码(`retransformClasses`)。

**`Instrumentation`类方法如下：**

![07EC4F97-CD49-41E6-95CE-FEB000325E33](../../images/07EC4F97-CD49-41E6-95CE-FEB000325E33.png)