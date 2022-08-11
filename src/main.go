package main

import (
	"fmt"
	bpf "github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
	"os"
)

var (
	mmap *bpf.Map
)

func getMetrics(ctx *gin.Context) {
	var syns, fins uint64
	err := mmap.Lookup(uint32(0), &syns)
	if err != nil {
		ctx.String(500, "ERROR! %d", err)
		return
	}
	err = mmap.Lookup(uint32(1), &fins)
	if err != nil {
		ctx.String(500, "ERROR! %d", err)
		return
	}
	ctx.String(200, "syns %d\n\rfins %d", syns, fins)
	return
}

func main() {
	//	opts = dpf.Load
	var err error
	mmap, err = bpf.LoadPinnedMap("/sys/fs/bpf/xdp_stats_map", &bpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		fmt.Println("Error %d", err)
		os.Exit(0)
	}
	fmt.Println("Keysize", mmap.KeySize())
	r := gin.Default()
	r.GET("/metrics", getMetrics)

	r.Run(":8080")

	//var val uint64
	//
	//val = make([]byte, 10)
	//err = mmap.Lookup(uint32(0), &val)
	//fmt.Println(err, val)
}
