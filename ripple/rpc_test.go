package ripple

import (
	"fmt"
	"testing"
	"time"
)

func TestRPC(t *testing.T) {

	rippleRPC := DialHTTP("http://120.92.117.47:5005")
	if rippleRPC == nil {
		fmt.Println("rippleRPC == nil")
	}
	for i := 0; i < 2000; i++ {

		tx, err := rippleRPC.GetRawTransaction("74DBFA500E97DFE1CC141E9D237CFF8CC3DBE67C1B3200F4A4A9D27BD5D37B26")
		fmt.Printf("getrawtransaction %s, %+v, %d\n", string(tx), err, i)
		//time.Sleep(3 * time.Second)
		//currentBlockIndex, err := rippleRPC.GetCurrentBlockIndex()
		//fmt.Println("currentBlockIndex = ", currentBlockIndex, err)
		//time.Sleep(5 * time.Second)
		//currentBlockIndex, err = rippleRPC.GetCurrentBlockIndex()
		//fmt.Println("currentBlockIndex = ", currentBlockIndex, err)
		time.Sleep(1 * time.Second)
	}
	//tx, err := rippleRPC.GetRawTransaction("74DBFA500E97DFE1CC141E9D237CFF8CC3DBE67C1B3200F4A4A9D27BD5D37B26")
	//fmt.Println(tx, err)
}
