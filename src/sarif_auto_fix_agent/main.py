#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SARIF自动修复Agent - 主入口脚本
整合SARIF解析、AI修复、思维链输出等功能

使用方法:
  python main.py --sarif-dir ./scan-res --workflows-dir ./workflows --output-dir ./output
  python main.py --config ./config.yaml
"""

import argparse
import os
import sys
import io
import yaml
import logging
from pathlib import Path
from typing import Dict, Any

# 设置标准输出为UTF-8编码 (Windows兼容)
if sys.platform.startswith('win'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# 导入自定义模块
from sarif_auto_fix_agent import (
    SarifParser,
    SeverityLevel,
    MinimaxClient,
    AIModel,
    AutoFixEngine,
)


def setup_logging(log_level: str = "INFO", log_file: str = "sarif_fix.log") -> None:
    """设置日志配置"""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )


def load_config(config_path: Path) -> Dict[str, Any]:
    """加载配置文件"""
    if not config_path.exists():
        logging.warning(f"配置文件不存在: {config_path}")
        return {}

    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)

        # 替换环境变量
        def replace_env_vars(obj):
            if isinstance(obj, dict):
                return {k: replace_env_vars(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [replace_env_vars(item) for item in obj]
            elif isinstance(obj, str) and obj.startswith("${") and obj.endswith("}"):
                env_var = obj[2:-1]
                return os.getenv(env_var, obj)
            return obj

        return replace_env_vars(config)
    except Exception as e:
        logging.error(f"加载配置文件失败: {str(e)}")
        return {}


def validate_inputs(sarif_dir: Path, workflows_dir: Path) -> bool:
    """验证输入参数"""
    if not sarif_dir.exists():
        logging.error(f"SARIF目录不存在: {sarif_dir}")
        return False

    if not workflows_dir.exists():
        logging.error(f"Workflows目录不存在: {workflows_dir}")
        return False

    sarif_files = list(sarif_dir.glob("*.sarif"))
    if not sarif_files:
        logging.error(f"SARIF目录中没有找到.sarif文件: {sarif_dir}")
        return False

    logging.info(f"验证通过: 找到 {len(sarif_files)} 个SARIF文件")
    return True


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="🤖 SARIF自动修复Agent - 基于SARIF漏洞报告的自动修复工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 使用默认配置运行
  python main.py --sarif-dir ./scan-res --workflows-dir ./workflows

  # 使用配置文件
  python main.py --config ./config.yaml

  # 只分析不修复
  python main.py --sarif-dir ./scan-res --workflows-dir ./workflows --dry-run

  # 设置最低严重性
  python main.py --sarif-dir ./scan-res --workflows-dir ./workflows --min-severity high
        """
    )

    # 必需参数
    parser.add_argument(
        "--sarif-dir",
        type=Path,
        help="SARIF文件目录路径"
    )

    parser.add_argument(
        "--workflows-dir",
        type=Path,
        help="GitHub Workflows文件目录路径"
    )

    parser.add_argument(
        "--sarif-file",
        type=Path,
        help="单个SARIF文件路径（用于单个文件处理模式）"
    )

    # 可选参数
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("./config.yaml"),
        help="配置文件路径 (默认: ./config.yaml)"
    )

    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./output"),
        help="输出目录 (默认: ./output)"
    )

    parser.add_argument(
        "--min-severity",
        type=str,
        choices=["low", "medium", "high", "critical"],
        help="最低严重性过滤"
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="只分析不实际修复"
    )

    parser.add_argument(
        "--api-key",
        type=str,
        help="Minimax API密钥 (也可以通过MINIMAX_API_KEY环境变量设置)"
    )

    parser.add_argument(
        "--model",
        type=str,
        choices=["MiniMax-M2", "deepseek-chat", "deepseek-coder", "abab6.5-chat", "abab6.5-gpt"],
        help="AI模型 (默认: MiniMax-M2)"
    )

    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="日志级别 (默认: INFO)"
    )

    args = parser.parse_args()

    # 加载配置
    config = load_config(args.config)

    # 设置日志
    setup_logging(
        log_level=args.log_level,
        log_file=config.get("logging", {}).get("file", "sarif_fix.log")
    )

    logger = logging.getLogger(__name__)

    # 获取API密钥（优先级：配置文件 > 命令行参数 > 环境变量）
    config_api_key = config.get("minimax", {}).get("api_key")
    api_key = config_api_key or args.api_key or os.getenv("MINIMAX_API_KEY")

    if not api_key:
        logger.error("❌ 未设置Minimax API密钥")
        logger.info("请在 config.yaml 中配置 api_key，或设置环境变量 MINIMAX_API_KEY，或使用 --api-key 参数")
        sys.exit(1)

    # 确定目录路径
    sarif_dir = args.sarif_dir or Path(config.get("sarif", {}).get("scan_res_directory", "./scan-res"))
    workflows_dir = args.workflows_dir or Path(config.get("sarif", {}).get("workflows_directory", "./workflows"))
    output_dir = args.output_dir
    sarif_file = args.sarif_file

    # 验证输入
    if sarif_file:
        # 单个文件处理模式
        if not sarif_file.exists():
            logger.error(f"SARIF文件不存在: {sarif_file}")
            sys.exit(1)
        if not workflows_dir.exists():
            logger.error(f"Workflows目录不存在: {workflows_dir}")
            sys.exit(1)
    else:
        # 批量处理模式
        if not validate_inputs(sarif_dir, workflows_dir):
            sys.exit(1)

    # 创建输出目录
    output_dir.mkdir(parents=True, exist_ok=True)

    # 显示启动信息
    logger.info("="*80)
    logger.info("🤖 SARIF自动修复Agent启动")
    logger.info("="*80)
    logger.info(f"📁 SARIF目录: {sarif_dir}")
    logger.info(f"📁 Workflows目录: {workflows_dir}")
    logger.info(f"📁 输出目录: {output_dir}")
    logger.info(f"🔑 使用模型: {args.model or config.get('minimax', {}).get('model', 'MiniMax-M2')}")
    logger.info(f"🔍 最低严重性: {args.min_severity or config.get('vulnerability_filter', {}).get('min_severity', 'medium')}")
    logger.info(f"🔧 运行模式: {'预览模式' if args.dry_run else '修复模式'}")
    logger.info("="*80)

    try:
        # 1. 解析SARIF文件
        logger.info("🔍 步骤1: 解析SARIF文件")
        parser = SarifParser()
        
        # 支持单个文件或批量处理
        if sarif_file:
            logger.info(f"📄 单个文件处理模式: {sarif_file}")
            vulnerabilities = parser.parse_file(sarif_file)
        else:
            logger.info(f"📁 批量处理模式: {sarif_dir}")
            vulnerabilities = parser.parse_directory(sarif_dir)

        if not vulnerabilities:
            logger.warning("⚠️ 未发现漏洞")
            sys.exit(0)

        # 按严重性过滤
        min_severity_str = args.min_severity or config.get("vulnerability_filter", {}).get("min_severity", "medium")
        min_severity = SeverityLevel(min_severity_str)
        filtered_vulnerabilities = parser.filter_by_severity(min_severity)

        logger.info(f"📊 发现 {len(vulnerabilities)} 个漏洞，过滤后剩余 {len(filtered_vulnerabilities)} 个")

        # 2. 初始化AI客户端
        logger.info("🤖 步骤2: 初始化AI客户端")
        model_name = args.model or config.get("minimax", {}).get("model", "MiniMax-M2")
        base_url = config.get("minimax", {}).get("base_url", "https://api.minimaxi.com/v1/text/chatcompletion_v2")
        model = AIModel(model_name)
        minimax_client = MinimaxClient(
            api_key=api_key,
            base_url=base_url,
            model=model
        )

        # 3. 创建修复引擎
        logger.info("🔧 步骤3: 创建自动修复引擎")
        engine = AutoFixEngine(minimax_client)

        # 4. 处理漏洞
        logger.info("🔨 步骤4: 生成修复方案")
        # 使用单个处理模式，每个漏洞独立处理
        fix_results = engine.process_vulnerabilities(filtered_vulnerabilities, workflows_dir)

        # 5. 显示摘要
        engine.print_summary()

        # 6. 导出报告
        logger.info("📝 步骤5: 导出报告")
        
        # 导出综合修复报告（Markdown格式）
        engine.export_fix_report_markdown(output_dir / "fix_report.md")

        # 7. 应用修复（如果不是dry-run）
        if not args.dry_run and config.get("fixing", {}).get("apply_fixes", False):
            logger.info("🔧 步骤6: 应用修复")
            backup_dir = None
            if config.get("fixing", {}).get("create_backup", True):
                backup_dir = Path(config.get("fixing", {}).get("backup_directory", "./backups"))
                backup_dir.mkdir(parents=True, exist_ok=True)

            results = engine.apply_all_fixes(workflows_dir, backup_dir)
            logger.info(f"✅ 修复完成: {results['applied']} 成功, {results['failed']} 失败")

            # 导出修复结果
            with open(output_dir / "fix_results.json", 'w', encoding='utf-8') as f:
                import json
                json.dump(results, f, indent=2, ensure_ascii=False)
        else:
            logger.info("🔍 预览模式：未应用修复，请检查修复建议")

        logger.info("="*80)
        logger.info("✅ 处理完成！")
        logger.info(f"📁 输出文件位置: {output_dir.absolute()}")
        logger.info("="*80)

    except KeyboardInterrupt:
        logger.warning("⚠️ 用户中断操作")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ 处理失败: {str(e)}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
