package tools

import "fmt"

type VM struct {
	Registers []int // 模拟寄存器
	PC        int   // 程序计数器
	Stack     []int // 方法调用栈
}

// 解析字节码
func (vm *VM) ExecuteBytecode(bytecode []uint16) {
	for vm.PC < len(bytecode) {
		opcode := bytecode[vm.PC]
		fmt.Printf("PC: %d, Opcode: 0x%x\n", vm.PC, opcode)
		vm.PC += 1
	}
}
