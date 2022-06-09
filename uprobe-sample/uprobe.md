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

```go
crypto/tls.(*Conn).Write
crypto/tls.(*Conn).Read
```

`uprobe` 可以在函数入口拿到参数, 因此可以获得 `Write` 函数的参数,也就是即将要加密的明文.

但是 golang 中 [不能使用 uretprobe](https://github.com/iovisor/bcc/issues/1320), 因此不能在 `Read` 函数执行成功后读出的明文.

但是文中给出了一个 [存在缺陷](https://github.com/iovisor/bcc/issues/1320#issuecomment-441783319) 的解决方案: 扫描整个 `Read` 函数,记录 `call` 命令的位置,并在这些位置上设置 `uprobe` 来模拟 `uretprobe`.

整个方案在 Go 1.18.3 上测试可行.但目前还存在以下问题:

1. 根据函数名(符号名)和二进制文件自动获取用于设置 `uprobe` 和模拟 `uretprobe` 的地址.在用户空间独立完成,eBPF仅知道设置了 `uprobe`,对模拟过程无感知.
2. 一个 `uprobe` 函数设置给一个进程的多个地址,解决模拟 `uretprobe` 存在多个返回位置的问题.这是函数接口用法的问题,应该好解决.
3. 根据 Go 版本确认函数参数的具体位置(如果参数在栈上,确定与栈指针的相对位置;如果在寄存器上,确定具体的寄存器),这一部分应该由用户空间获取信息,并把信息传递内核空间(eBPF).
