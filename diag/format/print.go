package format

import (
	"fmt"

	"github.com/fatih/color"
)

var (
	okStr   = color.BlueString("[") + color.GreenString("ok") + color.BlueString("]")
	warnStr = color.BlueString("[") + color.YellowString("warn") + color.BlueString("]")
	errStr  = color.BlueString("[") + color.RedString("error") + color.BlueString("]")

	PadFmtStr = "%-70s"
)

func PrintErr(err error) {
	if err != nil {
		fmt.Println(errStr)
		fmt.Printf("  * Error details: %s\n", err)
	} else {
		fmt.Println(okStr)
	}
}

func PrintWarn(warn error) {
	if warn != nil {
		fmt.Println(warnStr)
		fmt.Printf("  * Error details: %s\n", warn)
	} else {
		fmt.Println(okStr)
	}
}
