/*
 * Copyright sky 2019-12-07 Email:sky@03sec.com.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.anbai.sec.filesystem;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.JarURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.jar.Attributes;

/**
 * @author sky
 */
public class URLConnectionDemo {

	public static void main(String[] args) throws IOException {
		URL url = new URL("file:///etc/passwd");

		HttpURLConnection connection = (HttpURLConnection) url.openConnection();

		connection.connect();

		connection.getInputStream();

		StringBuilder response = new StringBuilder();
		BufferedReader in = new BufferedReader(
				new InputStreamReader(connection.getInputStream()));
		String line;

		while ((line = in.readLine()) != null) {
			response.append("/n").append(line);
		}

		System.out.print(response.toString());
	}
}
