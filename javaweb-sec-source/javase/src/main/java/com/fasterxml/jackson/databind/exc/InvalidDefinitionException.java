package com.fasterxml.jackson.databind.exc;

import org.springframework.http.converter.HttpMessageConversionException;

public class InvalidDefinitionException extends HttpMessageConversionException {

	public InvalidDefinitionException(String msg, Throwable cause) {
		super(msg, cause);
	}

	public String getType() {
		return "UNKNOWN";
	}

}
