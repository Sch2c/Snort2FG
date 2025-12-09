# Snort to FortiGate IPS 转换器 - 增强版

[![Version](https://img.shields.io/badge/version-4.1.1--Enhanced--Fixed-blue.svg)](#)
[![Python](https://img.shields.io/badge/python-3.6+-green.svg)](#)
[![Status](https://img.shields.io/badge/status-测试阶段-yellow.svg)](#)

**⚠️ 注意：当前脚本处于测试阶段，请在生产环境使用前充分测试。**

## 概述

这是一个基于 Fortinet 官方转换器 v3.1.1 的高级增强版 Snort 到 FortiGate IPS 签名转换工具。该脚本能够将 Snort 规则转换为 FortiGate 可用的 IPS 签名格式，并提供了多项增强功能和改进。

### 🎯 主要特性

- **核心逻辑对齐**：基于 Fortinet 官方转换器 v3.1.1，确保转换准确性
- **PCRE 支持**：完整支持正则表达式模式转换（`--pcre` 格式）
- **智能 HTTP 处理**：
  - 自动合并 HTTP 方法和 URI（如：GET /admin）
  - 自动为 HTTP 头部添加冒号（如：user -> user:）
  - 智能 User-Agent 和 Host 头部格式化
  - 支持 WebDAV 方法（PROPFIND, MKCOL 等）
- **增强验证**：实时输入验证和错误处理
- **批处理模式**：支持批量转换文件，带进度指示器
- **交互模式**：支持交互式单条规则转换
- **优化处理**：应用官方转换器的后处理优化

## 安装要求

- Python 3.6+
- 无需额外依赖包

## 使用方法

### 交互模式（推荐）

直接运行脚本进入交互模式：

```bash
python3 Snort2FG.py
```

在交互模式中，您可以：

- 直接粘贴 Snort 规则
- 输入 `help` 查看示例
- 输入 `quit` 或 `exit` 退出

### 文件批处理模式

批量转换文件中的规则：

```bash
# 基本用法
python3 Snort2FG.py -i input_rules.txt -o output_rules.txt

# 静默模式（减少输出）
python3 Snort2FG.py -i input.txt -o output.txt -q

# 启用调试日志
python3 Snort2FG.py -i input.txt -o output.txt --debug
```

## 支持的 Snort 功能

### ✅ 完全支持

- **Content 模式**：基本内容匹配
- **PCRE 正则表达式**：支持 `pcre:"/pattern/modifiers"` 格式
- **HTTP 流量检测**：
  - `http_method`, `http_uri`, `http_user_agent`
  - `http_header`, `http_cookie`, `http_client_body`
  - `uricontent`
- **流量方向**：`flow: to_server`, `flow: from_server`
- **协议支持**：TCP, UDP, ICMP, HTTP, HTTPS, FTP, SMTP, DNS, SSH 等
- **基本规则选项**：
  - `dsize`, `flags`, `ttl`, `tos`, `seq`, `ack`
  - `offset`, `depth`, `distance`, `within`
  - `nocase`

### ⚠️ 部分支持

- **复杂 PCRE 模式**：FortiGate 7.x 对复杂正则表达式支持有限
- **Snort 3 特定功能**：部分高级功能可能需要手动调整

### ❌ 不支持

- 元数据字段（`metadata`, `tag`, `target` 等）
- 某些 Snort 3 新增的关键字

## 转换示例

### 示例 1：AMOS 木马检测规则

**Snort 规则：**

```snort
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"AMOS Stealer CnC Checkin";
    flow:established,to_server;
    http.method; content:"POST";
    http.uri; content:"/contact";
    http.user_agent; content:"curl";
    http.header_names; content:"|0d 0a|user|0d 0a|BuildID|0d 0a|";
    sid:2061835;
)
```

**FortiGate 输出：**

```
F-SBID( --name "SID2061835-AMOS.Stealer.CnC.Checkin"; --protocol tcp; --service http; --flow from_client; --pattern "POST /contact"; --context uri; --pattern "User-Agent: curl"; --context header; --pattern "|0d0a|user: "; --pattern "|0d0a|BuildID: "; --context header; )
```

### 示例 2：PCRE 正则表达式

**Snort 规则：**

```snort
alert tcp any any -> any 80 (
    msg:"SQL Injection Attempt";
    flow:to_server;
    pcre:"/select.+from.+where/i";
    sid:1000002;
)
```

**FortiGate 输出：**

```
F-SBID( --name "SID1000002-SQL.Injection.Attempt"; --protocol tcp; --service http; --flow from_client; --pcre "/select.+from.+where/i"; --no_case; )
```

## 输出格式说明

转换后的 FortiGate 签名可以直接在 FortiGate CLI 中使用：

```bash
config ips custom
    edit "SID2061835-AMOS.Stealer.CnC.Checkin"
        set signature "F-SBID( --name \"SID2061835-AMOS.Stealer.CnC.Checkin\"; --protocol tcp; --service http; --flow from_client; ... )"
        set comment "Auto-converted from Snort"
        set action block
        set status enable
        set log enable
        set log-packet enable
    next
end
```

## 增强功能详解

### 1. 智能 HTTP 处理

- **自动合并方法 + URI**：将分散的 `http_method` 和 `http_uri` 自动合并为单一模式
- **HTTP 头部格式化**：自动为头部名称添加冒号（如：`user` → `user: `）
- **User-Agent 识别**：智能识别并格式化 User-Agent 字符串

### 2. PCRE 支持

- **格式转换**：`pcre:"/pattern/modifiers"` → `--pcre "/pattern/modifiers"`
- **修饰符处理**：支持标准 PCRE 修饰符（i, s, m, x, g）
- **Snort 特定修饰符**：自动处理 Snort 特定的上下文修饰符

### 3. 后处理优化

基于官方转换器的优化逻辑：

- 重复服务移除
- 服务优先级应用
- HTTP 方法优化（GET/POST → parsed_type）
- 多余上下文清理

## 性能和限制

### 性能指标

- **单规则转换**：< 100ms
- **批处理速度**：约 100-500 规则/秒（取决于规则复杂度）
- **内存占用**：< 50MB（处理 1000+ 规则）

### 限制说明

- **规则长度**：最大 1024 字符
- **签名名称**：最大 50 字符
- **PCRE 复杂度**：FortiGate 7.x 对复杂正则表达式支持有限
- **Snort 版本**：主要支持 Snort 2.x，部分支持 Snort 3.x

## 故障排除

### 常见问题

1. **PCRE 模式转换失败**
   - 检查正则表达式是否过于复杂
   - 简化模式或使用基本 content 匹配

2. **HTTP 规则转换不准确**
   - 确认 HTTP 相关关键字的使用方式
   - 查看转换警告信息

3. **规则长度超限**
   - 简化规则或拆分为多个规则
   - 移除不必要的选项

### 调试模式

启用调试模式查看详细转换过程：

```bash
python3 Snort2FG.py -i input.txt -o output.txt --debug
```

## 版本历史

- **v4.1.1-Enhanced-Fixed** (2025-10-28)
  - 修复 HTTP 头部格式化问题
  - 优化 PCRE 转换逻辑
  - 增强错误处理机制

- **v4.1.0-Enhanced**
  - 基于 Fortinet 官方转换器 v3.1.1
  - 新增 PCRE 支持
  - 智能模式合并功能

## 许可证

本工具基于 Fortinet 官方转换器的许可证条款。

## 贡献

欢迎提交问题报告和功能建议。在提交前请确保：

1. 详细描述问题或建议
2. 提供测试用的 Snort 规则示例
3. 说明期望的输出结果

## 免责声明

**⚠️ 重要提醒：本工具目前处于测试阶段**

- 在生产环境使用前请充分测试转换结果
- 建议先在测试环境中验证转换后的规则
- 对于关键的安全防护，建议同时使用其他验证方法
- 作者不对因使用本工具造成的任何损失承担责任

## 联系方式

如有问题或建议，请通过以下方式联系：

- 提交 GitHub Issue

---

**最后更新：2025-10-28**
