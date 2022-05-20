package command

import (
	"bytes"
	"os/exec"
)

type Command interface {
	Run() ([]byte, error)
}

func Run(Shell, ShellArg string, Cmd string) ([]byte, []byte, error) {
	var c *exec.Cmd
	if Cmd != "" {
		c = exec.Command(Shell, ShellArg, Cmd)
	} else {
		c = exec.Command(Shell, ShellArg)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr
	err := c.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}
