package com.anbai.sec.proxy;

import java.io.File;
import java.io.Serializable;

/**
 * Creator: yz
 * Date: 2020/1/14
 */
public interface FileSystem extends Serializable {

	String[] list(File file);

}
