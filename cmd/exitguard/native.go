package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"exitguard/internal/nativeapp"
)

type nativePlan struct {
	Schema       string `json:"schema"`
	ConfigSHA256 string `json:"configSHA256"`
	AppendINI    string `json:"appendINI"`
	Notice       string `json:"notice"`
}

func nativeCommand(ctx context.Context, command string, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	output := flags.String("output", "", "新建的计划/模板文件")
	target := flags.String("target", "chrome", "探针产品箱：chrome / edge / claude")
	planPath := flags.String("plan", "", "已经审核的 native-stage 计划")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errors.New("原生操作参数无效")
	}
	if command == "native-probe" {
		if *output != "" || *planPath != "" {
			return errors.New("native-probe 不接受报告作为保护证明")
		}
		command, err := nativeapp.ProbeCommand(ctx, *target)
		if err != nil {
			return err
		}
		command.Stdout = stdout
		command.Stderr = stderr
		if err := command.Run(); err != nil {
			return errors.New("箱内探针未正常完成；结论保持 incomplete，没有尝试箱外运行")
		}
		return nil
	}
	if command == "native-inspect" {
		if *output != "" || *planPath != "" {
			return errors.New("native-inspect 不接受文件作为保护证明")
		}
		report, err := nativeapp.Inspect(ctx)
		if writeErr := json.NewEncoder(stdout).Encode(report); writeErr != nil {
			return writeErr
		}
		return err
	}
	if command == "native-apply" {
		if *planPath == "" || *output != "" {
			return errors.New("请使用 native-apply --plan 已审核的计划.json")
		}
		file, err := os.Open(*planPath)
		if err != nil {
			return errors.New("无法读取已审核的配置计划")
		}
		defer file.Close()
		decoder := json.NewDecoder(io.LimitReader(file, 64<<10))
		decoder.DisallowUnknownFields()
		var plan nativePlan
		if decoder.Decode(&plan) != nil || plan.Schema != "exitguard-native-preview-v1" || plan.AppendINI != string(nativeapp.Snippet()) {
			return errors.New("计划格式或待追加分组已变化，请重新生成并审核")
		}
		if decoder.Decode(new(any)) != io.EOF {
			return errors.New("计划包含多余内容")
		}
		if err := nativeapp.Apply(ctx, plan.ConfigSHA256); err != nil {
			return err
		}
		_, err = io.WriteString(stdout, "已追加三个产品分组并重载。原生状态仍为 preview-incomplete，尚无完整保护证明；请继续完成 Windows 实机验收。\n")
		return err
	}
	if *output == "" || *planPath != "" {
		return errors.New("请用 --output 指定一个尚不存在的新文件")
	}
	data := nativeapp.Snippet()
	if command == "native-stage" {
		hash, snippet, err := nativeapp.Stage(ctx)
		if err != nil {
			return err
		}
		data, err = json.MarshalIndent(nativePlan{Schema: "exitguard-native-preview-v1", ConfigSHA256: hash, AppendINI: string(snippet), Notice: "仅追加三个新箱；不更改任何已有箱或全局 WFP。Apply 需独占文件和足够权限，先备份。未验证 DNS broker/Windows 应用验收，不能宣称完整保护。"}, "", "  ")
		if err != nil {
			return err
		}
	}
	file, err := os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("无法新建文件；不会覆盖现有文件")
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "已生成 %s；仅为待审核配置，不是运行时保护证明。\n", *output)
	return err
}
