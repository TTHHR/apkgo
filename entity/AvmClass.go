package entity

import "fmt"

// 模拟 Application 类
type Application interface {
	OnCreate()
}

type MyApplication struct {
}

func (app *MyApplication) OnCreate() {
	fmt.Println("MyApplication OnCreate")
}
