package com.anbai.sec.agent;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.TimeUnit;

/**
 * Creator: yz
 * Date: 2020/10/29
 */
public class CrackLicenseTest {

    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    private static boolean checkExpiry(String expireDate) {
        try {
            Date date = DATE_FORMAT.parse(expireDate);

            // 检测当前系统时间早于License授权截至时间
            if (new Date().before(date)) {
                return false;
            }
        } catch (ParseException e) {
            e.printStackTrace();
        }

        return true;
    }

    public static void main(String[] args) {
        // 设置一个已经过期的License时间
        final String expireDate = "2020-10-01 23:59:01";

        new Thread(new Runnable() {
            @Override
            public void run() {
                while (true) {
                    try {
                        String time = "[" + DATE_FORMAT.format(new Date()) + "] ";

                        // 检测license是否已经过期
                        if (checkExpiry(expireDate)) {
                            System.err.println(time + "您的授权已过期，请重新购买授权！");
                        } else {
                            System.out.println(time + "您的授权正常，截止时间为：" + expireDate);
                        }

                        // sleep 1秒
                        TimeUnit.SECONDS.sleep(5);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            }
        }).start();
    }

}