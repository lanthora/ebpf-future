# uprobe

## 基本函数测试

uprobe需要向内核传递一个函数地址,在这个地址的函数被调用时触发事件.
编译一个简单的 Go 程序,通过uprobe追踪其中的某个函数的调用.
下面的例子追踪的是 Divide 函数,根据被除数除数计算商和模.

```go
package main

import (
	"fmt"
)

//go:noinline
func Divide(dividend int, divisor int) (quotient int, remainder int) {
	quotient = dividend / divisor
	remainder = dividend % divisor
	return
}

func main() {
	dividend, divisor := 5, 3
	quotient, remainder := Divide(dividend, divisor)
	fmt.Printf("dividend=%d divisor=%d quotient=%d remainder=%d\n", dividend, divisor, quotient, remainder)
}
```

通过 `//go:noinline` 禁止 `Divide` 函数内联.

```bash
go build -o uranus-uprobe
```

从符号表中找到函数 `Divide` 的地址为 `0x47f500`,

```bash
readelf --syms --wide uranus-uprobe | grep Divide
#1447: 000000000047f500    53 FUNC    GLOBAL DEFAULT    1 main.Divide
```

在 libbpf-bootstrap 的 uprobe 示例中有这样一段注释

> If we were to parse ELF to calculate this function, we'd need 
> to add .text section offset and function's offset within .text
> ELF section.

所以需要两个偏移量:

* 函数在.text段中的偏移量 (0x47f500 - 0x401000)
* .text本身的偏移量 (0x1000)

最终结果为 0x7f500 (0x47f500 - 0x401000 + 0x1000)

```bash
readelf --section-headers uranus-uprobe | grep .text
# [ 1] .text             PROGBITS         0000000000401000  00001000
```

参考内核文档进行设置.

> Similar to the kprobe-event tracer, this doesn’t need to be activated via current_tracer. Instead of that, add probe points via /sys/kernel/debug/tracing/uprobe_events, and enable it via /sys/kernel/debug/tracing/events/uprobes/<EVENT>/enable.

```bash
# 注册一个新的uprobe
echo 'p /path/to/uranus-uprobe:0x7f500' >> /sys/kernel/debug/tracing/uprobe_events

# 如果偏移量计算错误,这里会出现写入错误
echo 1 > /sys/kernel/debug/tracing/events/uprobes/enable
```

```bash
# 运行测试程序
/path/to/uranus-uprobe

# 查看日志
cat /sys/kernel/debug/tracing/trace
```

```txt
# tracer: nop
#
# entries-in-buffer/entries-written: 1/1   #P:16
#
#                                _-----=> irqs-off/BH-disabled
#                               / _----=> need-resched
#                              | / _---=> hardirq/softirq
#                              || / _--=> preempt-depth
#                              ||| / _-=> migrate-disable
#                              |||| /     delay
#           TASK-PID     CPU#  |||||  TIMESTAMP  FUNCTION
#              | |         |   |||||     |         |
   uranus-uprobe-14031   [007] DNZff  6798.683418: p_uranus_0x7f500: (0x47f500)
```

接下来的目标就是从 Go 二进制中(`.gopclntab` 段)计算出 `0x7f500`.
从 go 1.8 开始,不能保证从 `.gopclntab` 段一定能拿到函数地址,
具体原因见[use the address of runtime.text as textStart](https://github.com/golang/go/commit/b38ab0ac5f78ac03a38052018ff629c03e36b864).尝试直接读二进制文件获取函数地址的项目多少存在一些问题.

目前阶段,想要完美使用 uprobe 进行追踪,通过符号表获取函数地址是必不可少的步骤.

## 追踪 Go net/http 实现的 HTTP

符号 `net/http.serverHandler.ServeHTTP`,对应函数

```go
func (sh serverHandler) ServeHTTP(rw ResponseWriter, req *Request)
```

能够追踪到这个函数调用,但是能拿到的值不多,至少不能轻易拿到 HTTP Body.

## 追踪加密解密

src/stirling/source_connectors/socket_tracer/bcc_bpf/go_tls_trace.c

```go
crypto/tls.(*Conn).Write
crypto/tls.(*Conn).Read
```

00000000005ffe40  1925 FUNC    GLOBAL DEFAULT    1 crypto/tls.(*Conn).Write
0000000000601240  1022 FUNC    GLOBAL DEFAULT    1 crypto/tls.(*Conn).Read

echo 'p /root/uranus/cmd/web/uranus-web:0x1ffe40' >> /sys/kernel/debug/tracing/uprobe_events
echo 'p /root/uranus/cmd/web/uranus-web:0x201240' >> /sys/kernel/debug/tracing/uprobe_events
echo 1 > /sys/kernel/debug/tracing/events/uprobes/enable
