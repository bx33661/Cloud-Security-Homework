# SARIF自动修复Agent

基于SARIF漏洞报告的GitHub Action自动修复工具，集成Minimax AI提供智能修复建议。

## 快速开始

### 安装

```bash
# 安装uv
pip install uv

# 安装项目
uv pip install -e .
```

### 配置

在 `config.yaml` 中设置API密钥，或使用环境变量：

```bash
export MINIMAX_API_KEY="your-api-key"
```

### 使用

```bash
# 基本用法
uv run sarif-fix --sarif-dir ./scan-res --workflows-dir ./workflows

# 预览模式（不应用修复）
uv run sarif-fix --sarif-dir ./scan-res --workflows-dir ./workflows --dry-run

# 单个文件处理
uv run sarif-fix --sarif-file ./scan-res/file.sarif --workflows-dir ./workflows
```

## 配置说明

`config.yaml` 关键配置：

```yaml
minimax:
  api_key: "${MINIMAX_API_KEY}"  # 环境变量或直接填写
  model: "MiniMax-M2"            # 可选: MiniMax-M2, deepseek-coder
  base_url: "https://api.minimaxi.com/v1/text/chatcompletion_v2"

vulnerability_filter:
  min_severity: "medium"         # low, medium, high, critical

fixing:
  apply_fixes: false             # 建议先预览
```

## 输出

- `output/fix_report.md` - 修复报告（Markdown）
- `output/fix_report.json` - 修复报告（JSON）

## 命令行参数

| 参数 | 说明 |
|------|------|
| `--sarif-dir` | SARIF文件目录 |
| `--sarif-file` | 单个SARIF文件 |
| `--workflows-dir` | Workflows目录 |
| `--min-severity` | 最低严重性过滤 |
| `--dry-run` | 预览模式 |
| `--model` | AI模型 |


