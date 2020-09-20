package com.anbai.sec.vuls.commons;

public enum MessageCode {

	DEFAULT_MESSAGE(-1, "默认状态码值!"),
	API_EXCEPTION(100, "API接口服务异常!"),
	API_SERVER_EXCEPTION(101, "接口服务访问异常!"),
	AUTH_EXCEPTION(102, "用户授权访问异常!"),
	JWT_TOKEN_EXPIRED_EXCEPTION(103, "用户Token已失效,请重新获取登陆!"),
	JWT_VERIFICATION_EXCEPTION(104, "用户Token验证异常!"),
	JWT_UNKNOWN_TOKEN(105, "未检查到授权信息，授权信息不能为空!"),
	JWT_CLAIM_EXCEPTION(106, "用户Token数据解析异常!"),
	AUTH_ROLE_EXCEPTION(210, "角色不匹配,权限不足!"),
	AUTH_PERMISSION_EXCEPTION(211, "权限校验异常,权限不足!"),
	REQUIRE_AUTH_EXCEPTION(212, "未授权访问,请先获取Token!");

	/**
	 * 消息编码
	 */
	private final int code;

	/**
	 * 消息内容
	 */
	private final String message;

	MessageCode(int code, String message) {
		this.code = code;
		this.message = message;
	}

	/**
	 * 获取状态码
	 *
	 * @return
	 */
	public int getCode() {
		return code;
	}

	/**
	 * 获取消息内容
	 *
	 * @return
	 */
	public String getMessage() {
		return message;
	}

}
