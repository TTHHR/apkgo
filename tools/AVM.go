package tools

import "fmt"

type VM struct {
	Registers []int // 模拟寄存器
	PC        int   // 程序计数器
	Stack     []int // 方法调用栈
}

// 解析字节码
func (vm *VM) ExecuteBytecode(bytecode []uint16) {
	vRet := 0
	vInput := 1
	vInput2 := 2
	for vm.PC < len(bytecode) {
		opcode := bytecode[vm.PC]
		fmt.Printf("PC: %d, Opcode: 0x%x\n", vm.PC, opcode)
		vm.PC += 1
		switch opcode {
		case 0x90:
			vA := (bytecode[vm.PC] >> 8) & 0x0F // 操作数A
			vB := bytecode[vm.PC] & 0xFF        // 操作数B
			vm.Registers[vB] = vInput

			vm.PC += 1
			vC := bytecode[vm.PC] & 0xFF // 操作数C
			vm.Registers[vC] = vInput2
			vm.Registers[vA] = vm.Registers[vB] + vm.Registers[vC]
			vRet = int(vA)
		case 0xf:
			fmt.Printf("return %d\n", vm.Registers[vRet])
		default:
			fmt.Printf("not support 0x%x\n", opcode)
		}
	}
}
