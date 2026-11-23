package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// A choice is accepted only after the entire scope was displayed and the
// administrator submitted a complete line. EOF leaves the decision pending.
func reviewLocalGroups(in io.Reader, out io.Writer, groups map[string]int) (map[string]int, error) {
	if len(groups) == 0 {
		return map[string]int{}, nil
	}
	names := slices.Sorted(maps.Keys(groups))
	var menu strings.Builder
	menu.WriteString("旧版未保留群组撤销历史。请确认哪些 DSM 群组允许通讯录同步管理。\n首次同步会核对部门映射和 GID，后续新增成员可能获得原组的共享权限。\n")
	for i, name := range names {
		fmt.Fprintf(&menu, "%d. %q (GID %d)\n", i+1, name, groups[name])
	}
	menu.WriteString("输入要批准的编号（空格分隔），all 批准以上全部，none 保留空范围。直接回车暂缓：")
	if _, err := io.WriteString(out, menu.String()); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(in)
	for {
		line, err := reader.ReadString('\n')
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		answer := strings.TrimSpace(line)
		switch answer {
		case "":
			return nil, nil
		case "all":
			return groups, nil
		case "none":
			return map[string]int{}, nil
		}
		selected := make(map[string]int)
		for _, value := range strings.Fields(answer) {
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 || n > len(names) {
				selected = nil
				break
			}
			name := names[n-1]
			selected[name] = groups[name]
		}
		if selected != nil {
			return selected, nil
		}
		if _, err := io.WriteString(out, "编号无效，尚未批准任何群组。请重新输入，或直接回车跳过："); err != nil {
			return nil, err
		}
	}
}
