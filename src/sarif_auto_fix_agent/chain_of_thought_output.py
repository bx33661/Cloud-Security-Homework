#!/usr/bin/env python3

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from .minimax_client import ChainOfThoughtLogger

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class ReasoningStep:
    step: int
    timestamp: float
    step_name: str
    input: Any
    output: Any
    reasoning: str
    confidence: float


@dataclass
class ChainOfThoughtReport:
    vulnerability_id: str
    rule_id: str
    total_steps: int
    steps: List[ReasoningStep]
    start_time: str
    end_time: str
    duration: float
    summary: str


class ChainOfThoughtOutput:
    def __init__(self):
        self.reports: List[ChainOfThoughtReport] = []

    def generate_report(self, chain_logger: ChainOfThoughtLogger,
                       vulnerability_info: Dict[str, Any]) -> ChainOfThoughtReport:
        cot_dict = chain_logger.export_to_dict()

        steps = []
        for step_data in cot_dict.get("steps", []):
            step = ReasoningStep(
                step=step_data.get("step", 0),
                timestamp=step_data.get("timestamp", 0),
                step_name=step_data.get("step_name", ""),
                input=step_data.get("input", None),
                output=step_data.get("output", None),
                reasoning=step_data.get("reasoning", ""),
                confidence=step_data.get("confidence", 0.0)
            )
            steps.append(step)

        summary = self._generate_summary(vulnerability_info, steps)

        report = ChainOfThoughtReport(
            vulnerability_id=vulnerability_info.get("workflow", "") + "_" + vulnerability_info.get("rule_id", ""),
            rule_id=vulnerability_info.get("rule_id", ""),
            total_steps=len(steps),
            steps=steps,
            start_time=datetime.fromtimestamp(steps[0].timestamp).isoformat() if steps else "",
            end_time=datetime.fromtimestamp(steps[-1].timestamp).isoformat() if steps else "",
            duration=steps[-1].timestamp - steps[0].timestamp if len(steps) > 1 else 0.0,
            summary=summary
        )

        self.reports.append(report)
        return report

    def _generate_summary(self, vulnerability_info: Dict[str, Any], steps: List[ReasoningStep]) -> str:
        rule_id = vulnerability_info.get("rule_id", "")
        severity = vulnerability_info.get("severity", "")

        key_actions = [step.step_name for step in steps]

        summary = f"""
对漏洞 {rule_id} (严重性: {severity}) 的修复推理过程：

🔍 **分析阶段**: 识别漏洞类型和影响范围
📝 **方案生成**: 基于AI知识库生成修复建议
🔧 **代码实施**: 将修复方案应用到工作流文件
✅ **验证确认**: 确保修复有效且不破坏原有功能

推理步骤数: {len(steps)}
关键决策点: {', '.join(key_actions[:5])}
"""

        return summary.strip()

    def export_to_markdown(self, output_path: Path) -> None:
        if not self.reports:
            logger.warning("没有思维链报告可导出")
            return

        markdown_content = [
            "# 🤖 SARIF自动修复 - AI思维链报告\n",
            f"生成时间: {datetime.now().isoformat()}\n",
            f"总漏洞数: {len(self.reports)}\n",
            "="*80 + "\n"
        ]

        for report in self.reports:
            markdown_content.append(self._format_report_as_markdown(report))
            markdown_content.append("\n" + "-"*80 + "\n")

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(markdown_content))

        logger.info(f"思维链Markdown报告已导出到: {output_path}")

    def _format_report_as_markdown(self, report: ChainOfThoughtReport) -> str:
        content = [
            f"\n## 📊 漏洞修复思维链报告\n",
            f"**漏洞ID**: {report.vulnerability_id}\n",
            f"**规则ID**: {report.rule_id}\n",
            f"**总步骤数**: {report.total_steps}\n",
            f"**开始时间**: {report.start_time}\n",
            f"**结束时间**: {report.end_time}\n",
            f"**耗时**: {report.duration:.2f}秒\n",
            f"**置信度**: {self._calculate_confidence(report.steps):.2f}\n"
        ]

        content.append(f"\n### 📝 修复摘要\n")
        content.append(f"{report.summary}\n")

        content.append(f"\n### 🔍 详细推理步骤\n")

        for i, step in enumerate(report.steps, 1):
            timestamp = datetime.fromtimestamp(step.timestamp).strftime("%H:%M:%S")
            confidence_bar = self._generate_confidence_bar(step.confidence)

            content.append(f"\n#### 步骤 {i}: {step.step_name}\n")
            content.append(f"- **时间**: {timestamp}\n")
            content.append(f"- **置信度**: {confidence_bar} ({step.confidence:.2f})\n")
            content.append(f"- **推理**: {step.reasoning}\n")

            if step.input:
                content.append(f"- **输入**: \n```json\n{json.dumps(step.input, indent=2, ensure_ascii=False)}\n```\n")

            if step.output:
                content.append(f"- **输出**: \n```json\n{json.dumps(step.output, indent=2, ensure_ascii=False)}\n```\n")

        return ''.join(content)

    def _calculate_confidence(self, steps: List[ReasoningStep]) -> float:
        if not steps:
            return 0.0

        total_weighted_confidence = 0
        total_weight = 0

        for i, step in enumerate(steps):
            weight = i + 1
            total_weighted_confidence += step.confidence * weight
            total_weight += weight

        return total_weighted_confidence / total_weight if total_weight > 0 else 0.0

    def _generate_confidence_bar(self, confidence: float) -> str:
        bar_length = 20
        filled_length = int(bar_length * confidence)
        bar = '█' * filled_length + '░' * (bar_length - filled_length)
        return f"`{bar}`"

    def export_to_json(self, output_path: Path) -> None:
        reports_data = [asdict(report) for report in self.reports]

        report_data = {
            "generated_at": datetime.now().isoformat(),
            "total_vulnerabilities": len(self.reports),
            "reports": reports_data
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        logger.info(f"思维链JSON报告已导出到: {output_path}")

    def export_to_html(self, output_path: Path) -> None:
        if not self.reports:
            logger.warning("没有思维链报告可导出")
            return

        html_content = [
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "    <meta charset='UTF-8'>",
            "    <title>🤖 SARIF自动修复 - AI思维链报告</title>",
            "    <style>",
            "        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; }",
            "        .header { background: #f6f8fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; }",
            "        .step { background: #fff; border: 1px solid #d0d7de; border-radius: 6px; padding: 16px; margin: 12px 0; }",
            "        .step-header { font-weight: 600; color: #0969da; margin-bottom: 8px; }",
            "        .confidence { background: #ddf4ff; padding: 4px 8px; border-radius: 4px; display: inline-block; }",
            "        .reasoning { background: #f6f8fa; padding: 12px; border-left: 3px solid #0969da; margin: 8px 0; }",
            "        pre { background: #f6f8fa; padding: 12px; border-radius: 6px; overflow-x: auto; }",
            "        .summary { background: #dafbe1; border: 1px solid #4ac26b; padding: 16px; border-radius: 6px; margin: 16px 0; }",
            "    </style>",
            "</head>",
            "<body>",
            f"    <div class='header'>",
            f"        <h1>🤖 SARIF自动修复 - AI思维链报告</h1>",
            f"        <p>生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
            f"        <p>总漏洞数: {len(self.reports)}</p>",
            f"    </div>"
        ]

        for report in self.reports:
            html_content.append(f"    <div class='report'>")
            html_content.append(f"        <h2>📊 漏洞修复报告: {report.rule_id}</h2>")
            html_content.append(f"        <p><strong>漏洞ID:</strong> {report.vulnerability_id}</p>")
            html_content.append(f"        <p><strong>总步骤数:</strong> {report.total_steps}</p>")
            html_content.append(f"        <p><strong>耗时:</strong> {report.duration:.2f}秒</p>")

            html_content.append(f"        <div class='summary'>")
            html_content.append(f"            <h3>📝 修复摘要</h3>")
            html_content.append(f"            <pre>{report.summary}</pre>")
            html_content.append(f"        </div>")

            html_content.append(f"        <h3>🔍 详细推理步骤</h3>")

            for i, step in enumerate(report.steps, 1):
                timestamp = datetime.fromtimestamp(step.timestamp).strftime("%H:%M:%S")
                confidence_bar = self._generate_confidence_bar(step.confidence)

                html_content.append(f"        <div class='step'>")
                html_content.append(f"            <div class='step-header'>步骤 {i}: {step.step_name}</div>")
                html_content.append(f"            <p><strong>时间:</strong> {timestamp}</p>")
                html_content.append(f"            <p><strong>置信度:</strong> <span class='confidence'>{confidence_bar} ({step.confidence:.2f})</span></p>")
                html_content.append(f"            <div class='reasoning'><strong>推理:</strong> {step.reasoning}</div>")

                if step.input:
                    html_content.append(f"            <div><strong>输入:</strong></div>")
                    html_content.append(f"            <pre>{json.dumps(step.input, indent=2, ensure_ascii=False)}</pre>")

                if step.output:
                    html_content.append(f"            <div><strong>输出:</strong></div>")
                    html_content.append(f"            <pre>{json.dumps(step.output, indent=2, ensure_ascii=False)}</pre>")

                html_content.append(f"        </div>")

            html_content.append(f"    </div>")

        html_content.append("</body></html>")

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(html_content))

        logger.info(f"思维链HTML报告已导出到: {output_path}")

    def print_summary(self) -> None:
        if not self.reports:
            print("\n📊 没有思维链报告")
            return

        print("\n" + "="*80)
        print("🧠 AI思维链报告摘要")
        print("="*80)

        for report in self.reports:
            print(f"\n📌 漏洞: {report.rule_id}")
            print(f"   步骤数: {report.total_steps}")
            print(f"   耗时: {report.duration:.2f}秒")
            print(f"   置信度: {self._calculate_confidence(report.steps):.2f}")

            key_steps = report.steps[:3] if len(report.steps) >= 3 else report.steps
            print(f"   关键步骤:")
            for step in key_steps:
                print(f"     - {step.step_name} (置信度: {step.confidence:.2f})")

        print("\n" + "="*80)

