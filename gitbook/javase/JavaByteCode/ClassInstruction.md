# Java虚拟机指令集

在上一章节我们解析了`Code`属性，并从中解析出了一些虚拟机指令，本章节我们将深入学习Java虚拟机的指令集。

## 类型/方法描述符

Java虚拟机中描述类型和方法有固定的描述符和Java语法中所所用的完全不一样，比如`int`应当表示为`i`，表示一个java类名，如：`java.lang.Object`类在虚拟机中应该使用`java/lang/Object`，表示引用对象应当使`L类名;`如：`Object obj`应当使用`Ljava/lang/Object;`表示，表示成员方法时候应当使用(参数类型描述符)返回值，如：`void main(String[] args)`应当使用`([Ljava/lang/String;)V`表示，表示数组使用`[类型描述符`，如`int[]`应当使用`[i`表示，表示构造方法名称应当使用`<init>`表示。

**类型描述符表**

| 描述符   | Java类型       | 示例                 |
| -------- | -------------- | -------------------- |
| `B`      | `byte`         | `B`                  |
| `C`      | `char`         | `C`                  |
| `D`      | `double`       | `D`                  |
| `F`      | `float`        | `F`                  |
| `I`      | `int`          | `I`                  |
| `J`      | `long`         | `J`                  |
| `S`      | `short`        | `S`                  |
| `Z`      | `boolean`      | `Z`                  |
| `[`      | `数组`         | `[IJ`                |
| `L类名;` | `引用类型对象` | `Ljava/lang/Object;` |

**方法描述符示例**

| 方法示例                            | 描述符                                   | 描述                      |
| ----------------------------------- | ---------------------------------------- | ------------------------- |
| `static{...}`，`static int id = 1;` | 方法名：`<clinit>`                       | 静态语句块/静态变量初始化 |
| `public Test (){...}`               | 方法名：`<init>`，描述符`()V`            | 构造方法                  |
| `void hello(){...}`                 | `()V`                                    | `V`表示`void`，无返回值   |
| `Object login(String str) {...}`    | `(Ljava/lang/String;)Ljava/lang/Object;` | 普通方法，返回Object类型  |
| `void login(String str) {...}`      | `(Ljava/lang/String;)V`                  | 普通方法，无返回值        |

## Java虚拟机指令

栈指令是由0-255的整型表示，在JVM规范的第六章中有完整的说明：[JVM规范-指令](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-6.html#jvms-6.5)。不同的指令会有自己的数据结构，如`TABLESWITCH`和`LOOKUPSWITCH`表示的是`switch`语句，当匹配到该指令时需要按照它特有的二进制格式解析。除此之外，新版本的JDK可能会新增指令，`Java15`所有的指令大概有205个。

**Java虚拟机指令表**

| 十六进制 | 助记符          | 指令说明                                                     |
| -------- | --------------- | ------------------------------------------------------------ |
| 0x00     | nop             | 什么都不做                                                   |
| 0x01     | aconst_null     | 将null推送至栈顶                                             |
| 0x02     | iconst_m1       | 将int型-1推送至栈顶                                          |
| 0x03     | iconst_0        | 将int型0推送至栈顶                                           |
| 0x04     | iconst_1        | 将int型1推送至栈顶                                           |
| 0x05     | iconst_2        | 将int型2推送至栈顶                                           |
| 0x06     | iconst_3        | 将int型3推送至栈顶                                           |
| 0x07     | iconst_4        | 将int型4推送至栈顶                                           |
| 0x08     | iconst_5        | 将int型5推送至栈顶                                           |
| 0x09     | lconst_0        | 将long型0推送至栈顶                                          |
| 0x0a     | lconst_1        | 将long型1推送至栈顶                                          |
| 0x0b     | fconst_0        | 将float型0推送至栈顶                                         |
| 0x0c     | fconst_1        | 将float型1推送至栈顶                                         |
| 0x0d     | fconst_2        | 将float型2推送至栈顶                                         |
| 0x0e     | dconst_0        | 将double型0推送至栈顶                                        |
| 0x0f     | dconst_1        | 将double型1推送至栈顶                                        |
| 0x10     | bipush          | 将单字节的常量值(-128~127)推送至栈顶                         |
| 0x11     | sipush          | 将一个短整型常量值(-32768~32767)推送至栈顶                   |
| 0x12     | ldc             | 将int, float或String型常量值从常量池中推送至栈顶             |
| 0x13     | ldc_w           | 将int, float或String型常量值从常量池中推送至栈顶（宽索引）   |
| 0x14     | ldc2_w          | 将long或double型常量值从常量池中推送至栈顶（宽索引）         |
| 0x15     | iload           | 将指定的int型本地变量推送至栈顶                              |
| 0x16     | lload           | 将指定的long型本地变量推送至栈顶                             |
| 0x17     | fload           | 将指定的float型本地变量推送至栈顶                            |
| 0x18     | dload           | 将指定的double型本地变量推送至栈顶                           |
| 0x19     | aload           | 将指定的引用类型本地变量推送至栈顶                           |
| 0x1a     | iload_0         | 将第一个int型本地变量推送至栈顶                              |
| 0x1b     | iload_1         | 将第二个int型本地变量推送至栈顶                              |
| 0x1c     | iload_2         | 将第三个int型本地变量推送至栈顶                              |
| 0x1d     | iload_3         | 将第四个int型本地变量推送至栈顶                              |
| 0x1e     | lload_0         | 将第一个long型本地变量推送至栈顶                             |
| 0x1f     | lload_1         | 将第二个long型本地变量推送至栈顶                             |
| 0x20     | lload_2         | 将第三个long型本地变量推送至栈顶                             |
| 0x21     | lload_3         | 将第四个long型本地变量推送至栈顶                             |
| 0x22     | fload_0         | 将第一个float型本地变量推送至栈顶                            |
| 0x23     | fload_1         | 将第二个float型本地变量推送至栈顶                            |
| 0x24     | fload_2         | 将第三个float型本地变量推送至栈顶                            |
| 0x25     | fload_3         | 将第四个float型本地变量推送至栈顶                            |
| 0x26     | dload_0         | 将第一个double型本地变量推送至栈顶                           |
| 0x27     | dload_1         | 将第二个double型本地变量推送至栈顶                           |
| 0x28     | dload_2         | 将第三个double型本地变量推送至栈顶                           |
| 0x29     | dload_3         | 将第四个double型本地变量推送至栈顶                           |
| 0x2a     | aload_0         | 将第一个引用类型本地变量推送至栈顶                           |
| 0x2b     | aload_1         | 将第二个引用类型本地变量推送至栈顶                           |
| 0x2c     | aload_2         | 将第三个引用类型本地变量推送至栈顶                           |
| 0x2d     | aload_3         | 将第四个引用类型本地变量推送至栈顶                           |
| 0x2e     | iaload          | 将int型数组指定索引的值推送至栈顶                            |
| 0x2f     | laload          | 将long型数组指定索引的值推送至栈顶                           |
| 0x30     | faload          | 将float型数组指定索引的值推送至栈顶                          |
| 0x31     | daload          | 将double型数组指定索引的值推送至栈顶                         |
| 0x32     | aaload          | 将引用型数组指定索引的值推送至栈顶                           |
| 0x33     | baload          | 将boolean或byte型数组指定索引的值推送至栈顶                  |
| 0x34     | caload          | 将char型数组指定索引的值推送至栈顶                           |
| 0x35     | saload          | 将short型数组指定索引的值推送至栈顶                          |
| 0x36     | istore          | 将栈顶int型数值存入指定本地变量                              |
| 0x37     | lstore          | 将栈顶long型数值存入指定本地变量                             |
| 0x38     | fstore          | 将栈顶float型数值存入指定本地变量                            |
| 0x39     | dstore          | 将栈顶double型数值存入指定本地变量                           |
| 0x3a     | astore          | 将栈顶引用型数值存入指定本地变量                             |
| 0x3b     | istore_0        | 将栈顶int型数值存入第一个本地变量                            |
| 0x3c     | istore_1        | 将栈顶int型数值存入第二个本地变量                            |
| 0x3d     | istore_2        | 将栈顶int型数值存入第三个本地变量                            |
| 0x3e     | istore_3        | 将栈顶int型数值存入第四个本地变量                            |
| 0x3f     | lstore_0        | 将栈顶long型数值存入第一个本地变量                           |
| 0x40     | lstore_1        | 将栈顶long型数值存入第二个本地变量                           |
| 0x41     | lstore_2        | 将栈顶long型数值存入第三个本地变量                           |
| 0x42     | lstore_3        | 将栈顶long型数值存入第四个本地变量                           |
| 0x43     | fstore_0        | 将栈顶float型数值存入第一个本地变量                          |
| 0x44     | fstore_1        | 将栈顶float型数值存入第二个本地变量                          |
| 0x45     | fstore_2        | 将栈顶float型数值存入第三个本地变量                          |
| 0x46     | fstore_3        | 将栈顶float型数值存入第四个本地变量                          |
| 0x47     | dstore_0        | 将栈顶double型数值存入第一个本地变量                         |
| 0x48     | dstore_1        | 将栈顶double型数值存入第二个本地变量                         |
| 0x49     | dstore_2        | 将栈顶double型数值存入第三个本地变量                         |
| 0x4a     | dstore_3        | 将栈顶double型数值存入第四个本地变量                         |
| 0x4b     | astore_0        | 将栈顶引用型数值存入第一个本地变量                           |
| 0x4c     | astore_1        | 将栈顶引用型数值存入第二个本地变量                           |
| 0x4d     | astore_2        | 将栈顶引用型数值存入第三个本地变量                           |
| 0x4e     | astore_3        | 将栈顶引用型数值存入第四个本地变量                           |
| 0x4f     | iastore         | 将栈顶int型数值存入指定数组的指定索引位置                    |
| 0x50     | lastore         | 将栈顶long型数值存入指定数组的指定索引位置                   |
| 0x51     | fastore         | 将栈顶float型数值存入指定数组的指定索引位置                  |
| 0x52     | dastore         | 将栈顶double型数值存入指定数组的指定索引位置                 |
| 0x53     | aastore         | 将栈顶引用型数值存入指定数组的指定索引位置                   |
| 0x54     | bastore         | 将栈顶boolean或byte型数值存入指定数组的指定索引位置          |
| 0x55     | castore         | 将栈顶char型数值存入指定数组的指定索引位置                   |
| 0x56     | sastore         | 将栈顶short型数值存入指定数组的指定索引位置                  |
| 0x57     | pop             | 将栈顶数值弹出 (数值不能是long或double类型的)                |
| 0x58     | pop2            | 将栈顶的一个（long或double类型的)或两个数值弹出（其它）      |
| 0x59     | dup             | 复制栈顶数值并将复制值压入栈顶                               |
| 0x5a     | dup_x1          | 复制栈顶数值并将两个复制值压入栈顶                           |
| 0x5b     | dup_x2          | 复制栈顶数值并将三个（或两个）复制值压入栈顶                 |
| 0x5c     | dup2            | 复制栈顶一个（long或double类型的)或两个（其它）数值并将复制值压入栈顶 |
| 0x5d     | dup2_x1         | <待补充>                                                     |
| 0x5e     | dup2_x2         | <待补充>                                                     |
| 0x5f     | swap            | 将栈最顶端的两个数值互换(数值不能是long或double类型的)       |
| 0x60     | iadd            | 将栈顶两int型数值相加并将结果压入栈顶                        |
| 0x61     | ladd            | 将栈顶两long型数值相加并将结果压入栈顶                       |
| 0x62     | fadd            | 将栈顶两float型数值相加并将结果压入栈顶                      |
| 0x63     | dadd            | 将栈顶两double型数值相加并将结果压入栈顶                     |
| 0x64     | isub            | 将栈顶两int型数值相减并将结果压入栈顶                        |
| 0x65     | lsub            | 将栈顶两long型数值相减并将结果压入栈顶                       |
| 0x66     | fsub            | 将栈顶两float型数值相减并将结果压入栈顶                      |
| 0x67     | dsub            | 将栈顶两double型数值相减并将结果压入栈顶                     |
| 0x68     | imul            | 将栈顶两int型数值相乘并将结果压入栈顶                        |
| 0x69     | lmul            | 将栈顶两long型数值相乘并将结果压入栈顶                       |
| 0x6a     | fmul            | 将栈顶两float型数值相乘并将结果压入栈顶                      |
| 0x6b     | dmul            | 将栈顶两double型数值相乘并将结果压入栈顶                     |
| 0x6c     | idiv            | 将栈顶两int型数值相除并将结果压入栈顶                        |
| 0x6d     | ldiv            | 将栈顶两long型数值相除并将结果压入栈顶                       |
| 0x6e     | fdiv            | 将栈顶两float型数值相除并将结果压入栈顶                      |
| 0x6f     | ddiv            | 将栈顶两double型数值相除并将结果压入栈顶                     |
| 0x70     | irem            | 将栈顶两int型数值作取模运算并将结果压入栈顶                  |
| 0x71     | lrem            | 将栈顶两long型数值作取模运算并将结果压入栈顶                 |
| 0x72     | frem            | 将栈顶两float型数值作取模运算并将结果压入栈顶                |
| 0x73     | drem            | 将栈顶两double型数值作取模运算并将结果压入栈顶               |
| 0x74     | ineg            | 将栈顶int型数值取负并将结果压入栈顶                          |
| 0x75     | lneg            | 将栈顶long型数值取负并将结果压入栈顶                         |
| 0x76     | fneg            | 将栈顶float型数值取负并将结果压入栈顶                        |
| 0x77     | dneg            | 将栈顶double型数值取负并将结果压入栈顶                       |
| 0x78     | ishl            | 将int型数值左移位指定位数并将结果压入栈顶                    |
| 0x79     | lshl            | 将long型数值左移位指定位数并将结果压入栈顶                   |
| 0x7a     | ishr            | 将int型数值右（符号）移位指定位数并将结果压入栈顶            |
| 0x7b     | lshr            | 将long型数值右（符号）移位指定位数并将结果压入栈顶           |
| 0x7c     | iushr           | 将int型数值右（无符号）移位指定位数并将结果压入栈顶          |
| 0x7d     | lushr           | 将long型数值右（无符号）移位指定位数并将结果压入栈顶         |
| 0x7e     | iand            | 将栈顶两int型数值作“按位与”并将结果压入栈顶                  |
| 0x7f     | land            | 将栈顶两long型数值作“按位与”并将结果压入栈顶                 |
| 0x80     | ior             | 将栈顶两int型数值作“按位或”并将结果压入栈顶                  |
| 0x81     | lor             | 将栈顶两long型数值作“按位或”并将结果压入栈顶                 |
| 0x82     | ixor            | 将栈顶两int型数值作“按位异或”并将结果压入栈顶                |
| 0x83     | lxor            | 将栈顶两long型数值作“按位异或”并将结果压入栈顶               |
| 0x84     | iinc            | 将指定int型变量增加指定值（i++, i--, i+=2）                  |
| 0x85     | i2l             | 将栈顶int型数值强制转换成long型数值并将结果压入栈顶          |
| 0x86     | i2f             | 将栈顶int型数值强制转换成float型数值并将结果压入栈顶         |
| 0x87     | i2d             | 将栈顶int型数值强制转换成double型数值并将结果压入栈顶        |
| 0x88     | l2i             | 将栈顶long型数值强制转换成int型数值并将结果压入栈顶          |
| 0x89     | l2f             | 将栈顶long型数值强制转换成float型数值并将结果压入栈顶        |
| 0x8a     | l2d             | 将栈顶long型数值强制转换成double型数值并将结果压入栈顶       |
| 0x8b     | f2i             | 将栈顶float型数值强制转换成int型数值并将结果压入栈顶         |
| 0x8c     | f2l             | 将栈顶float型数值强制转换成long型数值并将结果压入栈顶        |
| 0x8d     | f2d             | 将栈顶float型数值强制转换成double型数值并将结果压入栈顶      |
| 0x8e     | d2i             | 将栈顶double型数值强制转换成int型数值并将结果压入栈顶        |
| 0x8f     | d2l             | 将栈顶double型数值强制转换成long型数值并将结果压入栈顶       |
| 0x90     | d2f             | 将栈顶double型数值强制转换成float型数值并将结果压入栈顶      |
| 0x91     | i2b             | 将栈顶int型数值强制转换成byte型数值并将结果压入栈顶          |
| 0x92     | i2c             | 将栈顶int型数值强制转换成char型数值并将结果压入栈顶          |
| 0x93     | i2s             | 将栈顶int型数值强制转换成short型数值并将结果压入栈顶         |
| 0x94     | lcmp            | 比较栈顶两long型数值大小，并将结果（1，0，-1）压入栈顶       |
| 0x95     | fcmpl           | 比较栈顶两float型数值大小，并将结果（1，0，-1）压入栈顶；当其中一个数值为NaN时，将-1压入栈顶 |
| 0x96     | fcmpg           | 比较栈顶两float型数值大小，并将结果（1，0，-1）压入栈顶；当其中一个数值为NaN时，将1压入栈顶 |
| 0x97     | dcmpl           | 比较栈顶两double型数值大小，并将结果（1，0，-1）压入栈顶；当其中一个数值为NaN时，将-1压入栈顶 |
| 0x98     | dcmpg           | 比较栈顶两double型数值大小，并将结果（1，0，-1）压入栈顶；当其中一个数值为NaN时，将1压入栈顶 |
| 0x99     | ifeq            | 当栈顶int型数值等于0时跳转                                   |
| 0x9a     | ifne            | 当栈顶int型数值不等于0时跳转                                 |
| 0x9b     | iflt            | 当栈顶int型数值小于0时跳转                                   |
| 0x9c     | ifge            | 当栈顶int型数值大于等于0时跳转                               |
| 0x9d     | ifgt            | 当栈顶int型数值大于0时跳转                                   |
| 0x9e     | ifle            | 当栈顶int型数值小于等于0时跳转                               |
| 0x9f     | if_icmpeq       | 比较栈顶两int型数值大小，当结果等于0时跳转                   |
| 0xa0     | if_icmpne       | 比较栈顶两int型数值大小，当结果不等于0时跳转                 |
| 0xa1     | if_icmplt       | 比较栈顶两int型数值大小，当结果小于0时跳转                   |
| 0xa2     | if_icmpge       | 比较栈顶两int型数值大小，当结果大于等于0时跳转               |
| 0xa3     | if_icmpgt       | 比较栈顶两int型数值大小，当结果大于0时跳转                   |
| 0xa4     | if_icmple       | 比较栈顶两int型数值大小，当结果小于等于0时跳转               |
| 0xa5     | if_acmpeq       | 比较栈顶两引用型数值，当结果相等时跳转                       |
| 0xa6     | if_acmpne       | 比较栈顶两引用型数值，当结果不相等时跳转                     |
| 0xa7     | goto            | 无条件跳转                                                   |
| 0xa8     | jsr             | 跳转至指定16位offset位置，并将jsr下一条指令地址压入栈顶      |
| 0xa9     | ret             | 返回至本地变量指定的index的指令位置（一般与jsr, jsr_w联合使用） |
| 0xaa     | tableswitch     | 用于switch条件跳转，case值连续（可变长度指令）               |
| 0xab     | lookupswitch    | 用于switch条件跳转，case值不连续（可变长度指令）             |
| 0xac     | ireturn         | 从当前方法返回int                                            |
| 0xad     | lreturn         | 从当前方法返回long                                           |
| 0xae     | freturn         | 从当前方法返回float                                          |
| 0xaf     | dreturn         | 从当前方法返回double                                         |
| 0xb0     | areturn         | 从当前方法返回对象引用                                       |
| 0xb1     | return          | 从当前方法返回void                                           |
| 0xb2     | getstatic       | 获取指定类的静态域，并将其值压入栈顶                         |
| 0xb3     | putstatic       | 为指定的类的静态域赋值                                       |
| 0xb4     | getfield        | 获取指定类的实例域，并将其值压入栈顶                         |
| 0xb5     | putfield        | 为指定的类的实例域赋值                                       |
| 0xb6     | invokevirtual   | 调用实例方法                                                 |
| 0xb7     | invokespecial   | 调用超类构造方法，实例初始化方法，私有方法                   |
| 0xb8     | invokestatic    | 调用静态方法                                                 |
| 0xb9     | invokeinterface | 调用接口方法                                                 |
| 0xba     | --              |                                                              |
| 0xbb     | new             | 创建一个对象，并将其引用值压入栈顶                           |
| 0xbc     | newarray        | 创建一个指定原始类型（如int, float, char…）的数组，并将其引用值压入栈顶 |
| 0xbd     | anewarray       | 创建一个引用型（如类，接口，数组）的数组，并将其引用值压入栈顶 |
| 0xbe     | arraylength     | 获得数组的长度值并压入栈顶                                   |
| 0xbf     | athrow          | 将栈顶的异常抛出                                             |
| 0xc0     | checkcast       | 检验类型转换，检验未通过将抛出ClassCastException             |
| 0xc1     | instanceof      | 检验对象是否是指定的类的实例，如果是将1压入栈顶，否则将0压入栈顶 |
| 0xc2     | monitorenter    | 获得对象的锁，用于同步方法或同步块                           |
| 0xc3     | monitorexit     | 释放对象的锁，用于同步方法或同步块                           |
| 0xc4     | wide            | <待补充>                                                     |
| 0xc5     | multianewarray  | 创建指定类型和指定维度的多维数组（执行该指令时，操作栈中必须包含各维度的长度值），并将其引用值压入栈顶 |
| 0xc6     | ifnull          | 为null时跳转                                                 |
| 0xc7     | ifnonnull       | 不为null时跳转                                               |
| 0xc8     | goto_w          | 无条件跳转（宽索引）                                         |
| 0xc9     | jsr_w           | 跳转至指定32位offset位置，并将jsr_w下一条指令地址压入栈顶    |

## 指令解析

为了便于理解，以`TestHelloWorld`类中有一个`hello`方法为例，学习字节码和源代码之间的关联性。

**TestHelloWorld类的hello方法代码如下：**

```java
public String hello(String content) {
    String str = "Hello:";
    return str + content;
}
```

`hello`方法是一个非静态方法，返回值是`String`，`hello`方法有一个`String`类型的参数。

编译后的栈指令如下：

```json
{
    "opcodes": [
        "ldc #3 <Hello:>", 
        "astore_2", 
        "new #4 <java/lang/StringBuilder>", 
        "dup", 
        "invokespecial #5 <java/lang/StringBuilder.<init>>", 
        "aload_2", 
        "invokevirtual #6 <java/lang/StringBuilder.append>", 
        "aload_1", 
        "invokevirtual #6 <java/lang/StringBuilder.append>", 
        "invokevirtual #7 <java/lang/StringBuilder.toString>", 
        "areturn"
    ]
}
```

### hello方法字节码解析

虽然`hello`方法的代码非常简单，但是翻译成指令后就会变得比较难以理解了，有很多细节是隐藏在编译细节中的，比如`return str + content;`是一个简单的两个字符串相加的操作，但实际上`javac`编译时会创建一个`StringBuilder`对象，然后调用`append`方法来实现`str`字符串和`content`字符串相加的。

**hello方法字节码解析：**

1. `ldc`表示的是将int, float或String型常量值从常量池中推送至栈顶，而`ldc #3`表示的是将常量池中的第三个索引位置压入栈顶，也就是`Hello:`；
2. `astore_2`表示的是将栈顶的值存入到`局部变量表`的第二个位置，`局部变量表`的索引位置是从0开始的，因为`hello`方法是一个非静态方法，所以索引0表示的是`this`对象（如果是`static`方法那么就意味着没有`this`对象，索引0就应该表示第一个参数）。索引1表示的是`hello`方法的第一个参数，也就是`String content`。如果在方法体中想创建一个新的对象，那么就必须计算这个变量在局部变量表中的索引位置，否则无法存储对象。还有一个需要特别注意的点是`long`和`double`是宽类型(`wide type`)需要占用两个索引位置。`astore_2`实际上表达的是将栈顶的对象压入到局部变量表中，等价于`String arg2 = new String("Hello:")`；
3. `new #4`表示的是创建`java/lang/StringBuilder`类实例；
4. `dup`表示复制栈顶数值并将复制值压入栈顶，即`StringBuilder`对象；
5. `invokespecial #5`，`invokespecial`表示的是调用超类构造方法，实例初始化方法，私有方法，即调用`StringBuilder`类的构造方法(`<init>`)，`#5`在常量池中是一个`CONSTANT_METHOD_REF`类型的对象，用于表示一个类方法引用，`invokespecial #5`实际上是在调用的`StringBuilder`的构造方法，等价于：`new StringBuilder()`；
6. `aload_2`表示的是加载局部变量表中的第二个变量，也就是读取`astore_2`存入的值，即`Hello:`。
7. `invokevirtual #6`表示的是调用`StringBuilder`类的`append`方法，等价于：`sb.append("Hello:")`；
8. `aload_1`表示的是将局部变量表中的第一个变量压入栈顶，也就是将`hello`方法的第一个参数`content`的值压入栈顶；
9. `invokevirtual #6`，再次调用`StringBuilder`类的`append`方法，等价于：`sb.append(content)`；
10. `invokevirtual #7`，调用`StringBuilder`类的`toString`方法，等价于：`sb.toString()`；
11. `areturn`表示的是返回一个引用类型对象，需要注意的是如果不同的数据类型需要使用正确的return指令；

`hello`方法的逻辑非常简单，如果只是看源代码的情况下我们可以秒懂该方法的执行流程和逻辑，但是如果我们从字节码层来看就会显得非常复杂不便于阅读；从第3步到第10步实际上只是在做源代码中的`str + content`字符串相加操作而已。正是因为直接阅读虚拟机的指令对我们是一种非常不好的体验，所以才会有根据字节码逆向生成Java源代码的需求，通过反编译工具我们能够非常好的阅读程序逻辑，从而省去阅读字节码和指令的压力。但是反编译工具不是万能的，某些时候在解析指令的时候可能会报错，甚至是崩溃，所以为了更好的分析类业务逻辑以及学习`ASM`字节码库，我们需要尽可能的掌握字节码解析和虚拟机指令解析的原理。