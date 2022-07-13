package format

import (
	"fmt"

	"github.com/fatih/color"
)

var (
	okStr   = color.BlueString("[") + color.GreenString("ok") + color.BlueString("]")
	warnStr = color.BlueString("[") + color.YellowString("warn") + color.BlueString("]")
	errStr  = color.BlueString("[") + color.RedString("error") + color.BlueString("]")

	padFmtStr = "%-75s"
)

func PrintPadf(f string, args ...interface{}) {
	s := fmt.Sprintf(f, args...)
	fmt.Printf(padFmtStr, s)
}

func PrintErr(err error) {
	if err != nil {
		fmt.Println(errStr)
		fmt.Printf("  * Error: %s\n", err)
	} else {
		fmt.Println(okStr)
	}
}

func PrintWarn(warn error) {
	if warn != nil {
		fmt.Println(warnStr)
		fmt.Printf("  * Error: %s\n", warn)
	} else {
		fmt.Println(okStr)
	}
}
