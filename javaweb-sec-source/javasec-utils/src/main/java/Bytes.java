import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;

/**
 * 字符串、文件快速转换成byte数组
 * Creator: yz
 * Date: 2019/12/8
 */
public class Bytes {

	public static void main(String[] args) throws IOException {

		if (args.length > 0) {
			String str   = args[0];
			byte[] bytes = null;

			if (args.length == 2 && str.equals("-f")) {
				File file = new File(args[1]);
				bytes = Files.readAllBytes(file.toPath());
			} else {
				bytes = str.getBytes();
			}

			System.out.println(Arrays.toString(bytes));
		} else {
			System.out.println("Examples:");
			System.out.println("java Bytes [string]");
			System.out.println("java Bytes -f [path]");
		}
	}

}
