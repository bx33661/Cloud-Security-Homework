#!/usr/bin/env python3
"""
SARIF文件解析器 - 解析CodeQL或其他静态分析工具生成的SARIF文件
提取漏洞信息、位置和严重性等级
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class SeverityLevel(Enum):
    """漏洞严重性等级"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class VulnerabilityLocation:
    """漏洞位置信息"""
    workflow_name: str
    job_name: Optional[str] = None
    step_name: Optional[str] = None
    line_number: Optional[int] = None


@dataclass
class Vulnerability:
    """单个漏洞信息"""
    rule_id: str
    message: str
    severity: SeverityLevel
    level: str
    location: VulnerabilityLocation
    workflow_file: str


class SarifParser:
    """SARIF文件解析器"""

    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []

    def parse_file(self, sarif_path: Path) -> List[Vulnerability]:
        """
        解析单个SARIF文件

        Args:
            sarif_path: SARIF文件路径

        Returns:
            漏洞信息列表
        """
        logger.info(f"解析SARIF文件: {sarif_path}")

        try:
            with open(sarif_path, 'r', encoding='utf-8') as f:
                sarif_data = json.load(f)

            vulnerabilities = self._extract_vulnerabilities(sarif_data, sarif_path)
            self.vulnerabilities.extend(vulnerabilities)

            logger.info(f"从 {sarif_path.name} 中提取到 {len(vulnerabilities)} 个漏洞")
            return vulnerabilities

        except Exception as e:
            logger.error(f"解析SARIF文件失败 {sarif_path}: {str(e)}")
            return []

    def parse_directory(self, directory_path: Path) -> List[Vulnerability]:
        """
        批量解析目录中的SARIF文件

        Args:
            directory_path: SARIF文件目录路径

        Returns:
            所有漏洞信息列表
        """
        logger.info(f"批量解析SARIF文件目录: {directory_path}")

        all_vulnerabilities = []
        sarif_files = list(directory_path.glob("*.sarif"))

        for sarif_file in sarif_files:
            vulnerabilities = self.parse_file(sarif_file)
            all_vulnerabilities.extend(vulnerabilities)

        logger.info(f"总共解析 {len(sarif_files)} 个SARIF文件，提取到 {len(all_vulnerabilities)} 个漏洞")
        return all_vulnerabilities

    def _extract_vulnerabilities(self, sarif_data: Dict[str, Any], file_path: Path) -> List[Vulnerability]:
        """从SARIF数据中提取漏洞信息"""
        vulnerabilities = []

        # 从文件名提取工作流信息 (e.g., "argusSecurityBot#vwbench#1.sarif")
        workflow_number = self._extract_workflow_number(file_path.name)
        workflow_name = f"workflow_{workflow_number}"

        if "runs" not in sarif_data:
            return vulnerabilities

        for run in sarif_data["runs"]:
            if "results" not in run:
                continue

            for result in run["results"]:
                vulnerability = self._parse_result(result, workflow_name, file_path.name)
                if vulnerability:
                    vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _parse_result(self, result: Dict[str, Any], workflow_name: str, file_name: str) -> Optional[Vulnerability]:
        """解析单个漏洞结果"""
        try:
            # 提取基本信息
            rule_id = result.get("ruleId", "unknown")
            message = result.get("message", {}).get("text", "")
            level = result.get("level", "warning")

            # 解析位置信息
            location_info = self._parse_location(result, workflow_name)

            # 确定严重性等级
            severity = self._determine_severity(level, message)

            return Vulnerability(
                rule_id=rule_id,
                message=message,
                severity=severity,
                level=level,
                location=location_info,
                workflow_file=file_name
            )

        except Exception as e:
            logger.error(f"解析漏洞结果失败: {str(e)}")
            return None

    def _parse_location(self, result: Dict[str, Any], workflow_name: str) -> VulnerabilityLocation:
        """解析漏洞位置信息"""
        location = result.get("locations", [{}])[0]
        physical_location = location.get("physicalLocation", {})
        artifact_location = physical_location.get("artifactLocation", {})

        uri = artifact_location.get("uri", "")

        # 从URI中提取工作流信息
        # 格式: "workflow_name | Job : job_name | Step : step_name"
        job_name = None
        step_name = None

        if "|" in uri:
            parts = uri.split("|")
            if len(parts) >= 3:
                job_part = parts[1].strip()
                step_part = parts[2].strip()

                if "Job :" in job_part:
                    job_name = job_part.split("Job :")[1].strip()
                if "Step :" in step_part:
                    step_name = step_part.split("Step :")[1].strip()

        return VulnerabilityLocation(
            workflow_name=workflow_name,
            job_name=job_name,
            step_name=step_name
        )

    def _determine_severity(self, level: str, message: str) -> SeverityLevel:
        """根据级别和消息确定严重性"""
        message_upper = message.upper()

        if "[CRITICAL" in message_upper or level == "error":
            return SeverityLevel.CRITICAL
        elif "[HIGH" in message_upper:
            return SeverityLevel.HIGH
        elif "[MEDIUM" in message_upper:
            return SeverityLevel.MEDIUM
        elif "[LOW" in message_upper:
            return SeverityLevel.LOW
        else:
            # 根据level默认映射
            if level == "error":
                return SeverityLevel.HIGH
            elif level == "warning":
                return SeverityLevel.MEDIUM
            else:
                return SeverityLevel.LOW

    def _extract_workflow_number(self, file_name: str) -> str:
        """从文件名提取工作流编号"""
        # 格式: "argusSecurityBot#vwbench#1.sarif"
        parts = file_name.split("#")
        if len(parts) >= 3:
            return parts[2].replace(".sarif", "")
        return "unknown"

    def get_vulnerability_summary(self) -> Dict[str, Any]:
        """生成漏洞统计摘要"""
        if not self.vulnerabilities:
            return {"total": 0}

        # 按严重性统计
        severity_counts = {}
        rule_counts = {}
        workflow_counts = {}

        for vuln in self.vulnerabilities:
            # 严重性统计
            severity_counts[vuln.severity.value] = severity_counts.get(vuln.severity.value, 0) + 1

            # 规则统计
            rule_counts[vuln.rule_id] = rule_counts.get(vuln.rule_id, 0) + 1

            # 工作流统计
            workflow_counts[vuln.location.workflow_name] = \
                workflow_counts.get(vuln.location.workflow_name, 0) + 1

        return {
            "total": len(self.vulnerabilities),
            "by_severity": severity_counts,
            "by_rule": rule_counts,
            "by_workflow": workflow_counts,
            "vulnerabilities": [
                {
                    "rule_id": v.rule_id,
                    "severity": v.severity.value,
                    "message": v.message,
                    "workflow": v.location.workflow_name,
                    "job": v.location.job_name,
                    "step": v.location.step_name
                }
                for v in self.vulnerabilities
            ]
        }

    def filter_by_severity(self, min_severity: SeverityLevel) -> List[Vulnerability]:
        """按最低严重性过滤漏洞"""
        severity_order = {
            SeverityLevel.LOW: 0,
            SeverityLevel.MEDIUM: 1,
            SeverityLevel.HIGH: 2,
            SeverityLevel.CRITICAL: 3
        }

        min_level = severity_order[min_severity]

        filtered = [
            v for v in self.vulnerabilities
            if severity_order[v.severity] >= min_level
        ]

        logger.info(f"按严重性 {min_severity.value} 过滤，得到 {len(filtered)} 个漏洞")
        return filtered

    def export_to_json(self, output_path: Path) -> None:
        """导出漏洞信息到JSON文件"""
        summary = self.get_vulnerability_summary()

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)

        logger.info(f"漏洞信息已导出到: {output_path}")


if __name__ == "__main__":
    # 测试代码
    parser = SarifParser()

    # 解析示例SARIF文件
    scan_res_dir = Path("../VWBench/scan-res")
    if scan_res_dir.exists():
        vulnerabilities = parser.parse_directory(scan_res_dir)

        # 打印摘要
        summary = parser.get_vulnerability_summary()
        print("\n=== 漏洞统计摘要 ===")
        print(f"总漏洞数: {summary['total']}")
        print(f"按严重性分布: {summary['by_severity']}")
        print(f"按规则分布: {summary['by_rule']}")
        print(f"按工作流分布: {summary['by_workflow']}")

        # 导出到JSON
        output_file = Path("vulnerabilities_summary.json")
        parser.export_to_json(output_file)
    else:
        print(f"扫描结果目录不存在: {scan_res_dir}")
