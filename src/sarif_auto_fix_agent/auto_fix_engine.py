#!/usr/bin/env python3
"""
基于SARIF漏洞信息的自动修复引擎
使用Minimax AI生成修复代码并自动应用
"""

import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

from .minimax_client import MinimaxClient, AIResponse
from .sarif_parser import SarifParser, Vulnerability, SeverityLevel

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class FixResult:
    """修复结果"""
    vulnerability: Vulnerability
    original_content: str
    fixed_content: str
    explanation: str
    ai_suggestion: str
    applied: bool = False
    error: Optional[str] = None


class AutoFixEngine:
    """自动修复引擎"""

    def __init__(self, minimax_client: MinimaxClient):
        """
        初始化自动修复引擎

        Args:
            minimax_client: Minimax AI客户端
        """
        self.minimax_client = minimax_client
        self.sarif_parser = SarifParser()
        self.fix_results: List[FixResult] = []

    def process_vulnerabilities(self, vulnerabilities: List[Vulnerability], workflows_directory: Path) -> List[FixResult]:
        """
        处理漏洞列表，生成修复方案（单个处理模式）

        Args:
            vulnerabilities: 漏洞列表
            workflows_directory: GitHub workflows目录

        Returns:
            修复结果列表
        """
        logger.info(f"开始处理 {len(vulnerabilities)} 个漏洞")

        # 为每个漏洞生成修复方案（单个处理模式）
        for vulnerability in vulnerabilities:
            try:
                # 重置思维链记录器，确保每个漏洞独立处理
                self.minimax_client.reset_chain_of_thought()
                fix_result = self._generate_fix_for_vulnerability(vulnerability, workflows_directory)
                if fix_result:
                    self.fix_results.append(fix_result)
            except Exception as e:
                logger.error(f"生成修复方案失败 {vulnerability.rule_id}: {str(e)}")
                # 即使失败也要重置，避免影响下一个漏洞
                self.minimax_client.reset_chain_of_thought()

        logger.info(f"生成了 {len(self.fix_results)} 个修复方案")
        return self.fix_results

    def process_sarif_files(self, sarif_directory: Path, workflows_directory: Path) -> List[FixResult]:
        """
        处理SARIF文件目录，生成修复方案

        Args:
            sarif_directory: SARIF文件目录
            workflows_directory: GitHub workflows目录

        Returns:
            修复结果列表
        """
        logger.info(f"开始处理SARIF文件: {sarif_directory}")

        # 解析所有SARIF文件
        vulnerabilities = self.sarif_parser.parse_directory(sarif_directory)
        logger.info(f"提取到 {len(vulnerabilities)} 个漏洞")

        # 使用通用的漏洞处理方法
        return self.process_vulnerabilities(vulnerabilities, workflows_directory)

    def _generate_fix_for_vulnerability(self, vulnerability: Vulnerability, workflows_directory: Path) -> Optional[FixResult]:
        """
        为单个漏洞生成修复方案

        Args:
            vulnerability: 漏洞信息
            workflows_directory: workflows目录

        Returns:
            修复结果
        """
        logger.info(f"为漏洞 {vulnerability.rule_id} 生成修复方案")

        # 获取对应的workflow文件
        workflow_file = self._find_workflow_file(vulnerability, workflows_directory)
        if not workflow_file or not workflow_file.exists():
            logger.warning(f"未找到对应的workflow文件: {vulnerability.location.workflow_name}")
            return None

        # 读取workflow内容
        try:
            with open(workflow_file, 'r', encoding='utf-8') as f:
                original_content = f.read()
        except Exception as e:
            logger.error(f"读取workflow文件失败 {workflow_file}: {str(e)}")
            return None

        # 调用AI生成修复建议
        vulnerability_dict = {
            "rule_id": vulnerability.rule_id,
            "message": vulnerability.message,
            "severity": vulnerability.severity.value,
            "workflow": vulnerability.location.workflow_name,
            "job": vulnerability.location.job_name,
            "step": vulnerability.location.step_name,
            "workflow_file": str(workflow_file)
        }

        try:
            # 分析漏洞
            analysis_response = self.minimax_client.analyze_vulnerability(vulnerability_dict)

            # 生成修复代码
            fix_response = self.minimax_client.generate_fix_code(original_content, vulnerability_dict)

            # 尝试应用修复
            fixed_content, explanation = self._apply_fix(original_content, vulnerability, fix_response.content)

            return FixResult(
                vulnerability=vulnerability,
                original_content=original_content,
                fixed_content=fixed_content,
                explanation=explanation,
                ai_suggestion=fix_response.content,
                applied=(fixed_content != original_content)
            )

        except Exception as e:
            logger.error(f"AI修复生成失败: {str(e)}")
            return FixResult(
                vulnerability=vulnerability,
                original_content=original_content,
                fixed_content=original_content,
                explanation="修复失败",
                ai_suggestion="",
                applied=False,
                error=str(e)
            )

    def _find_workflow_file(self, vulnerability: Vulnerability, workflows_directory: Path) -> Optional[Path]:
        """
        根据漏洞信息找到对应的workflow文件

        Args:
            vulnerability: 漏洞信息
            workflows_directory: workflows目录

        Returns:
            workflow文件路径
        """
        # 从SARIF文件名中提取编号，找到对应的workflow文件
        workflow_number = self._extract_workflow_number(vulnerability.workflow_file)

        # 尝试多种可能的文件名格式
        possible_names = [
            f"{workflow_number}.yml",
            f"{workflow_number}.yaml",
            f"workflow_{workflow_number}.yml",
            f"workflow_{workflow_number}.yaml"
        ]

        for name in possible_names:
            workflow_file = workflows_directory / name
            if workflow_file.exists():
                return workflow_file

        # 如果找不到，列出所有文件尝试匹配
        workflow_files = list(workflows_directory.glob("*.yml")) + list(workflows_directory.glob("*.yaml"))

        # 按修改时间排序，使用最新的文件
        if workflow_files:
            workflow_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            # 返回第一个文件（最新修改的）
            return workflow_files[0]

        return None

    def _extract_workflow_number(self, sarif_file_name: str) -> str:
        """从SARIF文件名提取工作流编号"""
        # 格式: "argusSecurityBot#vwbench#1.sarif"
        parts = sarif_file_name.split("#")
        if len(parts) >= 3:
            return parts[2].replace(".sarif", "")
        return "1"  # 默认返回1

    def _apply_fix(self, original_content: str, vulnerability: Vulnerability, ai_suggestion: str) -> Tuple[str, str]:
        """
        应用AI生成的修复

        Args:
            original_content: 原始内容
            vulnerability: 漏洞信息
            ai_suggestion: AI修复建议

        Returns:
            (修复后的内容, 解释)
        """
        logger.info(f"应用修复: {vulnerability.rule_id}")

        # 尝试从AI建议中提取YAML代码
        fixed_content = self._extract_yaml_from_suggestion(ai_suggestion)

        if fixed_content and self._validate_yaml(fixed_content):
            explanation = f"已根据AI建议修复 {vulnerability.rule_id} 漏洞"
            return fixed_content, explanation

        # 如果AI建议无效，尝试基于规则的修复
        fixed_content = self._apply_rule_based_fix(original_content, vulnerability)

        if fixed_content != original_content:
            explanation = f"已应用规则修复 {vulnerability.rule_id} 漏洞"
            return fixed_content, explanation

        # 无法修复，返回原内容
        explanation = f"无法自动修复 {vulnerability.rule_id}，需要手动处理"
        return original_content, explanation

    def _extract_yaml_from_suggestion(self, suggestion: str) -> Optional[str]:
        """从AI建议中提取YAML代码"""
        # 查找YAML代码块
        yaml_pattern = r'```(?:yaml|yml)?\n(.*?)\n```'
        matches = re.findall(yaml_pattern, suggestion, re.DOTALL)

        if matches:
            yaml_content = matches[0].strip()
            if self._validate_yaml(yaml_content):
                return yaml_content

        # 如果没有代码块，检查整个建议是否为YAML
        if self._validate_yaml(suggestion):
            return suggestion

        return None

    def _validate_yaml(self, content: str) -> bool:
        """验证YAML内容是否有效"""
        try:
            import yaml
            yaml.safe_load(content)
            return True
        except:
            return False

    def _apply_rule_based_fix(self, content: str, vulnerability: Vulnerability) -> str:
        """应用基于规则的修复"""
        if vulnerability.rule_id == "ContextToSink":
            return self._fix_context_to_sink(content, vulnerability)
        else:
            # 其他规则的修复逻辑
            return content

    def _fix_context_to_sink(self, content: str, vulnerability: Vulnerability) -> str:
        """修复Context-to-Sink漏洞"""
        # 基于漏洞消息确定修复策略
        message = vulnerability.message.lower()

        if "issue.title" in message:
            # 为issue.title添加验证
            content = self._add_input_validation(content, "github.event.issue.title")
        elif "commits" in message:
            # 为commits添加验证
            content = self._add_input_validation(content, "github.event.commits")
        elif "comment.body" in message:
            # 为comment.body添加验证
            content = self._add_input_validation(content, "github.event.comment.body")

        return content

    def _add_input_validation(self, content: str, context_path: str) -> str:
        """为输入添加验证逻辑"""
        # 在run命令前后添加验证步骤
        validation_snippet = f"""
      - name: Validate input
        run: |
          # 验证 {context_path}
          if [[ "${{{{ {context_path} }}}}" =~ ^[a-zA-Z0-9_\\-\\s]+$ ]]; then
            echo "Input validation passed"
          else
            echo "Invalid input detected"
            exit 1
          fi
"""

        # 在第一个run步骤前插入验证步骤
        if "    run: |" in content:
            content = content.replace("    run: |", validation_snippet + "    run: |", 1)

        return content

    def apply_all_fixes(self, workflows_directory: Path, backup_directory: Optional[Path] = None) -> Dict[str, Any]:
        """
        应用所有修复到文件

        Args:
            workflows_directory: workflows目录
            backup_directory: 备份目录（可选）

        Returns:
            修复统计信息
        """
        logger.info("开始应用所有修复")

        if backup_directory:
            backup_directory.mkdir(parents=True, exist_ok=True)

        applied_count = 0
        failed_count = 0
        results_by_file = {}

        for fix_result in self.fix_results:
            if not fix_result.applied:
                continue

            try:
                workflow_file = self._find_workflow_file(fix_result.vulnerability, workflows_directory)
                if not workflow_file:
                    failed_count += 1
                    continue

                # 创建备份
                if backup_directory:
                    backup_file = backup_directory / workflow_file.name
                    backup_file.write_text(fix_result.original_content, encoding='utf-8')

                # 应用修复
                workflow_file.write_text(fix_result.fixed_content, encoding='utf-8')
                applied_count += 1

                # 记录结果
                if workflow_file.name not in results_by_file:
                    results_by_file[workflow_file.name] = []
                results_by_file[workflow_file.name].append({
                    "vulnerability": fix_result.vulnerability.rule_id,
                    "explanation": fix_result.explanation,
                    "applied": True
                })

                logger.info(f"已修复: {workflow_file.name} - {fix_result.vulnerability.rule_id}")

            except Exception as e:
                logger.error(f"应用修复失败: {str(e)}")
                failed_count += 1

        results = {
            "total_fixes": len(self.fix_results),
            "applied": applied_count,
            "failed": failed_count,
            "results_by_file": results_by_file
        }

        logger.info(f"修复完成: {applied_count} 成功, {failed_count} 失败")
        return results

    def export_fix_report(self, output_path: Path) -> None:
        """导出修复报告（JSON格式）"""
        report = {
            "total_vulnerabilities": len(self.fix_results),
            "fixes": [
                {
                    "rule_id": fix.vulnerability.rule_id,
                    "severity": fix.vulnerability.severity.value,
                    "message": fix.vulnerability.message,
                    "workflow": fix.vulnerability.location.workflow_name,
                    "job": fix.vulnerability.location.job_name,
                    "step": fix.vulnerability.location.step_name,
                    "applied": fix.applied,
                    "explanation": fix.explanation,
                    "ai_suggestion": fix.ai_suggestion[:500] + "..." if len(fix.ai_suggestion) > 500 else fix.ai_suggestion,
                    "error": fix.error
                }
                for fix in self.fix_results
            ]
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        logger.info(f"修复报告已导出到: {output_path}")

    def export_fix_report_markdown(self, output_path: Path) -> None:
        """导出修复报告（Markdown格式）"""
        from datetime import datetime
        
        total = len(self.fix_results)
        applied = sum(1 for fix in self.fix_results if fix.applied)
        failed = total - applied
        
        md_content = [
            "# 🔧 SARIF自动修复报告\n",
            f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
            f"**总漏洞数**: {total}\n",
            f"**成功修复**: {applied}\n",
            f"**修复失败**: {failed}\n",
            f"**修复率**: {(applied/total*100):.1f}%\n",
            "\n---\n\n",
            "## 📋 详细修复结果\n\n"
        ]
        
        for i, fix in enumerate(self.fix_results, 1):
            status = "✅" if fix.applied else "❌"
            md_content.append(f"### {i}. {status} {fix.vulnerability.rule_id}\n\n")
            md_content.append(f"- **严重性**: {fix.vulnerability.severity.value}\n")
            md_content.append(f"- **漏洞描述**: {fix.vulnerability.message[:200]}{'...' if len(fix.vulnerability.message) > 200 else ''}\n")
            md_content.append(f"- **工作流**: {fix.vulnerability.location.workflow_name}\n")
            md_content.append(f"- **作业**: {fix.vulnerability.location.job_name}\n")
            md_content.append(f"- **步骤**: {fix.vulnerability.location.step_name}\n")
            md_content.append(f"- **修复状态**: {'已修复' if fix.applied else '修复失败'}\n")
            md_content.append(f"- **说明**: {fix.explanation}\n")
            
            if fix.ai_suggestion:
                md_content.append(f"\n**AI修复建议**:\n\n")
                md_content.append("```yaml\n")
                yaml_match = re.search(r'```(?:yaml|yml)?\n(.*?)\n```', fix.ai_suggestion, re.DOTALL)
                if yaml_match:
                    md_content.append(yaml_match.group(1))
                else:
                    md_content.append(fix.ai_suggestion[:1000])
                md_content.append("\n```\n\n")
            
            if fix.error:
                md_content.append(f"**错误信息**: {fix.error}\n")
            
            md_content.append("\n---\n\n")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(''.join(md_content))
        
        logger.info(f"修复报告(Markdown)已导出到: {output_path}")

    def print_summary(self) -> None:
        """打印修复摘要"""
        print("\n" + "="*60)
        print("🔧 自动修复引擎 - 修复摘要")
        print("="*60)

        total = len(self.fix_results)
        applied = sum(1 for fix in self.fix_results if fix.applied)
        failed = total - applied

        print(f"📊 总漏洞数: {total}")
        print(f"✅ 成功修复: {applied}")
        print(f"❌ 修复失败: {failed}")
        print(f"📈 修复率: {(applied/total*100):.1f}%" if total > 0 else "📈 修复率: 0%")

        if self.fix_results:
            print("\n📋 详细修复结果:")
            for i, fix in enumerate(self.fix_results, 1):
                status = "✅" if fix.applied else "❌"
                print(f"\n{i}. {status} {fix.vulnerability.rule_id}")
                print(f"   严重性: {fix.vulnerability.severity.value}")
                print(f"   描述: {fix.vulnerability.message[:100]}...")
                print(f"   解释: {fix.explanation}")

        print("\n" + "="*60)
