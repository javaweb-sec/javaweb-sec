# Java反序列化漏洞

自从2015年11月[Apache Commons Collections反序列化漏洞](https://issues.apache.org/jira/browse/COLLECTIONS-580)([ysoserial](https://github.com/frohoff/ysoserial)的最早的commit记录是2015年1月29日,说明这个漏洞可能早在2014年甚至更早就已经被人所利用)被人公开后Java反序列化漏洞仿佛掀起了燎原之势，无数的使用了反序列化机制的Java应用系统惨遭黑客疯狂的攻击，为企业安全甚至是国家安全带来了沉重的打击！直至今日(2019年12月)已经燃烧了Java平台四年之久的反序列化漏洞之火还仍未熄灭。

