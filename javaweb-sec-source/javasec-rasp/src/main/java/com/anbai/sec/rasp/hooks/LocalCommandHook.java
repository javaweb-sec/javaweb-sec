/*
 * 灵蜥Java Agent版 [Web应用安全智能防护系统]
 * ----------------------------------------------------------------------
 * Copyright © 安百科技（北京）有限公司
 */
package com.anbai.sec.rasp.hooks;

import com.anbai.sec.rasp.annotation.RASPClassHook;
import com.anbai.sec.rasp.annotation.RASPMethodHook;
import com.anbai.sec.rasp.commons.RASPHookResult;
import com.anbai.sec.rasp.commons.RASPMethodAdvice;
import org.javaweb.utils.ClassUtils;

import java.util.List;

import static com.anbai.sec.rasp.commons.RASPConstants.AGENT_NAME;
import static com.anbai.sec.rasp.commons.RASPConstants.CONSTRUCTOR_INIT;
import static com.anbai.sec.rasp.commons.RASPHookHandlerType.RETURN;
import static com.anbai.sec.rasp.hooks.handler.LocalCommandHookHandler.processCommand;

/**
 * Hook 本地命令执行
 */
@RASPClassHook
public class LocalCommandHook {

	/**
	 * Hook 通用的ProcessBuilder类
	 */
	@RASPMethodHook(className = "java.lang.ProcessBuilder", methodName = "start")
	public static class ProcessBuilderHook extends RASPMethodAdvice {

		@Override
		public RASPHookResult<?> onMethodEnter() {
			Object obj = getThisObject();

			try {
				List<String> command  = ClassUtils.getFieldValue(obj, "command");
				String[]     commands = command.toArray(new String[command.size()]);

				return processCommand(commands, obj, this);
			} catch (Exception e) {
				new RuntimeException(AGENT_NAME + "获取ProcessBuilder类command变量异常:" + e, e).printStackTrace();
			}

			return new RASPHookResult(RETURN);
		}

	}

	/**
	 * Hook Unix系统UNIXProcess类构造方法
	 */
	@RASPMethodHook(
			className = "java.lang.UNIXProcess", methodName = CONSTRUCTOR_INIT,
			methodArgsDesc = ".*", methodDescRegexp = true
	)
	public static class UNIXProcessHook extends RASPMethodAdvice {

		/**
		 * 合并执行的命令字节为字符串
		 *
		 * @param prog
		 * @param argBlock
		 * @return
		 */
		private static String mergeCommandBytes(byte[] prog, byte[] argBlock) {
			if (prog == null) {
				return null;
			}

			byte[]   bytes = new byte[prog.length + argBlock.length];
			byte[][] bs    = new byte[][]{prog, argBlock};
			int      idx   = 0;

			for (byte[] arr : bs) {
				for (int i = 0; i < arr.length; i++) {
					byte b = arr[i];

					if (b == 0) {
						bytes[idx] = 20;
					} else {
						bytes[idx] = b;
					}

					idx++;
				}
			}

			return new String(bytes).trim();
		}

		@Override
		public RASPHookResult<?> onMethodEnter() {
			try {
				Object[] args     = getArgs();
				String   command  = mergeCommandBytes((byte[]) args[0], (byte[]) args[1]);
				String[] commands = new String[]{command};

				return processCommand(commands, getThisObject(), this);
			} catch (Exception e) {
				new RuntimeException(AGENT_NAME + "处理UNIXProcess异常:" + e, e).printStackTrace();
			}

			return new RASPHookResult(RETURN);
		}

	}

	/**
	 * Hook Windows系统ProcessImpl类构造方法
	 */
	@RASPMethodHook(
			className = "java.lang.ProcessImpl", methodName = CONSTRUCTOR_INIT,
			methodArgsDesc = ".*", methodDescRegexp = true
	)
	public static class ProcessImplHook extends RASPMethodAdvice {

		@Override
		public RASPHookResult<?> onMethodEnter() {
			try {
				String[] commands = null;

				// JDK9+的API参数不一样！
				if (getArg(0) instanceof String[]) {
					commands = getArg(0);
				} else if (getArg(0) instanceof byte[]) {
					commands = new String[]{new String((byte[]) getArg(0))};
				}

				return processCommand(commands, getThisObject(), this);
			} catch (Exception e) {
				new RuntimeException(AGENT_NAME + "处理ProcessImpl异常:" + e, e).printStackTrace();
			}

			return new RASPHookResult(RETURN);
		}

	}

}