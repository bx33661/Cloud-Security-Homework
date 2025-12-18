#!/usr/bin/env python3

import yaml
import re
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    CONTEXT_TO_SINK = "ContextToSink"
    UNSAFE_EXPRESSION = "UnsafeExpression"
    TOKEN_EXPOSURE = "TokenExposure"
    PRIVILEGE_ESCALATION = "PrivilegeEscalation"
    UNVALIDATED_INPUT = "UnvalidatedInput"
    INSECURE_COMMAND = "InsecureCommand"
    MISSING_CHECKS = "MissingChecks"


@dataclass
class SecurityPattern:
    pattern_type: VulnerabilityType
    name: str
    description: str
    severity: str
    regex_patterns: List[str]
    remediation: str


class WorkflowAnalyzer:
    def __init__(self):
        self.security_patterns = self._load_security_patterns()
        self.vulnerabilities = []

    def _load_security_patterns(self) -> List[SecurityPattern]:
        patterns = [
            SecurityPattern(
                pattern_type=VulnerabilityType.CONTEXT_TO_SINK,
                name="Context-to-Sink数据流",
                description="GitHub上下文数据直接流向可能不安全的操作",
                severity="high",
                regex_patterns=[
                    r'\${{.*github\.event\.\w+.*}}',
                    r'\${{.*github\.context\.\w+.*}}',
                    r'\${{.*github\.inputs\.\w+.*}}'
                ],
                remediation="使用中间变量或过滤函数，确保数据在传递前经过验证和清理"
            ),
            SecurityPattern(
                pattern_type=VulnerabilityType.UNSAFE_EXPRESSION,
                name="不安全的表达式求值",
                description="在shell脚本中直接使用未经验证的表达式",
                severity="medium",
                regex_patterns=[
                    r'exit\s+\${{.*}}',
                    r'echo\s+\${{.*github\.event\.\w+.*}}',
                    r'if\s+\[\s*.*\${{.*github\..*}}.*\s*\]'
                ],
                remediation="避免在shell命令中直接使用GitHub表达式，使用引号和验证"
            ),
            SecurityPattern(
                pattern_type=VulnerabilityType.TOKEN_EXPOSURE,
                name="Token泄露风险",
                description="敏感令牌或密钥可能被意外泄露",
                severity="critical",
                regex_patterns=[
                    r'secrets?\.\w+',
                    r'ZENKINS_SECRET',
                    r'GITHUB_TOKEN',
                    r'\${{.*secrets?\..*}}'
                ],
                remediation="确保所有密钥使用secret变量，并避免在日志或输出中暴露"
            ),
            SecurityPattern(
                pattern_type=VulnerabilityType.UNVALIDATED_INPUT,
                name="未验证的用户输入",
                description="直接使用用户输入而没有验证",
                severity="high",
                regex_patterns=[
                    r'github\.event\.issue\.title',
                    r'github\.event\.issue\.body',
                    r'github\.event\.comment\.body',
                    r'github\.event\.pull_request\.title'
                ],
                remediation="对所有用户输入进行验证和清理，使用allowlist验证"
            ),
            SecurityPattern(
                pattern_type=VulnerabilityType.INSECURE_COMMAND,
                name="不安全的命令执行",
                description="执行可能存在注入风险的命令",
                severity="high",
                regex_patterns=[
                    r'eval\s+.*\${{',
                    r'`.*\${{.*}}`',
                    r'sh\s+-c.*\${{',
                    r'bash\s+-c.*\${{'
                ],
                remediation="避免动态执行命令，使用安全的参数传递方式"
            )
        ]

        return patterns

    def analyze_workflow_file(self, workflow_path: Path) -> List[Dict[str, Any]]:
        logger.info(f"分析工作流文件: {workflow_path}")

        try:
            with open(workflow_path, 'r', encoding='utf-8') as f:
                workflow_content = f.read()

            workflow_data = yaml.safe_load(workflow_content)
            vulnerabilities = self._analyze_workflow_data(workflow_data, workflow_content, workflow_path)

            logger.info(f"在 {workflow_path.name} 中发现 {len(vulnerabilities)} 个潜在漏洞")
            return vulnerabilities

        except yaml.YAMLError as e:
            logger.error(f"YAML解析失败 {workflow_path}: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"工作流分析失败 {workflow_path}: {str(e)}")
            return []

    def analyze_workflow_directory(self, directory_path: Path) -> Dict[str, List[Dict[str, Any]]]:
        logger.info(f"批量分析工作流目录: {directory_path}")

        all_vulnerabilities = {}
        workflow_files = list(directory_path.glob("*.yml")) + list(directory_path.glob("*.yaml"))

        for workflow_file in workflow_files:
            vulnerabilities = self.analyze_workflow_file(workflow_file)
            if vulnerabilities:
                all_vulnerabilities[workflow_file.name] = vulnerabilities

        logger.info(f"总共分析 {len(workflow_files)} 个工作流，发现 {sum(len(v) for v in all_vulnerabilities.values())} 个漏洞")
        return all_vulnerabilities

    def _analyze_workflow_data(self, workflow_data: Dict[str, Any], content: str, file_path: Path) -> List[Dict[str, Any]]:
        vulnerabilities = []

        if not isinstance(workflow_data, dict):
            return vulnerabilities

        if "jobs" in workflow_data:
            vulnerabilities.extend(self._analyze_jobs(workflow_data["jobs"], content, file_path))

        if "on" in workflow_data:
            vulnerabilities.extend(self._analyze_triggers(workflow_data["on"], content, file_path))

        vulnerabilities.extend(self._analyze_overall_security(workflow_data, content, file_path))

        return vulnerabilities

    def _analyze_jobs(self, jobs: Dict[str, Any], content: str, file_path: Path) -> List[Dict[str, Any]]:
        vulnerabilities = []

        for job_name, job_data in jobs.items():
            if not isinstance(job_data, dict):
                continue

            if "steps" in job_data:
                step_vulnerabilities = self._analyze_steps(job_data["steps"], content, file_path, job_name)
                vulnerabilities.extend(step_vulnerabilities)

            job_vulnerabilities = self._analyze_job_security(job_data, content, file_path, job_name)
            vulnerabilities.extend(job_vulnerabilities)

        return vulnerabilities

    def _analyze_steps(self, steps: List[Dict[str, Any]], content: str, file_path: Path, job_name: str) -> List[Dict[str, Any]]:
        vulnerabilities = []

        for step_idx, step in enumerate(steps):
            if not isinstance(step, dict):
                continue

            step_name = step.get("name", f"step_{step_idx}")
            step_vulnerabilities = self._analyze_step_security(step, content, file_path, job_name, step_name, step_idx)
            vulnerabilities.extend(step_vulnerabilities)

        return vulnerabilities

    def _analyze_step_security(self, step: Dict[str, Any], content: str, file_path: Path,
                               job_name: str, step_name: str, step_idx: int) -> List[Dict[str, Any]]:
        vulnerabilities = []

        if "run" in step:
            run_content = step["run"]
            run_vulnerabilities = self._analyze_run_command(run_content, content, file_path, job_name, step_name, step_idx)
            vulnerabilities.extend(run_vulnerabilities)

        if "uses" in step:
            uses_content = step["uses"]
            uses_vulnerabilities = self._analyze_action_usage(uses_content, content, file_path, job_name, step_name, step_idx)
            vulnerabilities.extend(uses_vulnerabilities)

        return vulnerabilities

    def _analyze_run_command(self, run_content: str, full_content: str, file_path: Path,
                             job_name: str, step_name: str, step_idx: int) -> List[Dict[str, Any]]:
        vulnerabilities = []

        for pattern in self.security_patterns:
            matches = self._find_pattern_matches(run_content, pattern.regex_patterns)
            for match in matches:
                vulnerability = {
                    "type": pattern.pattern_type.value,
                    "name": pattern.name,
                    "description": pattern.description,
                    "severity": pattern.severity,
                    "remediation": pattern.remediation,
                    "file": str(file_path),
                    "job": job_name,
                    "step": step_name,
                    "step_index": step_idx,
                    "line_number": self._find_line_number(full_content, match),
                    "matched_content": match,
                    "context": self._extract_context(full_content, match)
                }
                vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _analyze_action_usage(self, uses_content: str, full_content: str, file_path: Path,
                              job_name: str, step_name: str, step_idx: int) -> List[Dict[str, Any]]:
        vulnerabilities = []

        insecure_actions = [
            "actions/cache@v1",
            "actions/checkout@v2",
            "docker://alpine",
            "marcelbperez/annotated-action@v1"
        ]

        for insecure_action in insecure_actions:
            if insecure_action in uses_content:
                vulnerability = {
                    "type": "InsecureAction",
                    "name": "使用不安全的Action版本",
                    "description": f"使用了已知存在安全问题的Action: {insecure_action}",
                    "severity": "high",
                    "remediation": "更新到最新稳定版本或使用经过安全审计的版本",
                    "file": str(file_path),
                    "job": job_name,
                    "step": step_name,
                    "step_index": step_idx,
                    "matched_content": uses_content,
                    "context": f"Action: {uses_content}"
                }
                vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _analyze_job_security(self, job_data: Dict[str, Any], content: str, file_path: Path, job_name: str) -> List[Dict[str, Any]]:
        vulnerabilities = []

        if "runs-on" in job_data:
            runs_on = job_data["runs-on"]
            if isinstance(runs_on, str) and "ubuntu-latest" not in runs_on:
                vulnerability = {
                    "type": "NonLatestImage",
                    "name": "使用非最新运行镜像",
                    "description": f"Job {job_name} 使用了可能过时的运行镜像",
                    "severity": "low",
                    "remediation": "考虑使用ubuntu-latest或指定明确的版本",
                    "file": str(file_path),
                    "job": job_name,
                    "matched_content": str(runs_on)
                }
                vulnerabilities.append(vulnerability)

        env = job_data.get("env", {})
        for key, value in env.items():
            if isinstance(value, str) and ("secret" in key.lower() or "token" in key.lower()):
                if not value.startswith("${{") or "secrets" not in value:
                    vulnerability = {
                        "type": "HardcodedSecret",
                        "name": "硬编码密钥",
                        "description": f"Job {job_name} 中可能存在硬编码的密钥: {key}",
                        "severity": "critical",
                        "remediation": "使用GitHub Secrets存储敏感信息",
                        "file": str(file_path),
                        "job": job_name,
                        "matched_content": f"{key}: {value}"
                    }
                    vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _analyze_triggers(self, triggers: Any, content: str, file_path: Path) -> List[Dict[str, Any]]:
        vulnerabilities = []

        if isinstance(triggers, dict):
            for trigger_name, trigger_config in triggers.items():
                if trigger_name in ["issue_comment", "pull_request_target"]:
                    vulnerability = {
                        "type": "UnsafeTrigger",
                        "name": "不安全的触发器",
                        "description": f"触发器 {trigger_name} 可能导致安全风险",
                        "severity": "medium",
                        "remediation": "确保在处理外部输入时进行适当的验证",
                        "file": str(file_path),
                        "trigger": trigger_name,
                        "matched_content": str(trigger_config)
                    }
                    vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _analyze_overall_security(self, workflow_data: Dict[str, Any], content: str, file_path: Path) -> List[Dict[str, Any]]:
        vulnerabilities = []

        if "secrets" in content:
            if "permissions" not in workflow_data:
                vulnerability = {
                    "type": "MissingPermissions",
                    "name": "缺少权限声明",
                    "description": "工作流使用了secrets但没有声明所需的最小权限",
                    "severity": "medium",
                    "remediation": "添加permissions字段声明最小权限",
                    "file": str(file_path)
                }
                vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _find_pattern_matches(self, text: str, patterns: List[str]) -> List[str]:
        matches = []
        for pattern in patterns:
            found = re.findall(pattern, text, re.IGNORECASE)
            matches.extend(found)
        return matches

    def _find_line_number(self, content: str, search_text: str) -> int:
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            if search_text in line:
                return i
        return -1

    def _extract_context(self, content: str, match: str, context_lines: int = 3) -> str:
        lines = content.split('\n')
        match_line = -1

        for i, line in enumerate(lines, 1):
            if match in line:
                match_line = i
                break

        if match_line == -1:
            return match

        start = max(0, match_line - context_lines - 1)
        end = min(len(lines), match_line + context_lines)

        context = '\n'.join(lines[start:end])
        return context

    def get_security_score(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        if not vulnerabilities:
            return 100.0

        severity_weights = {
            "low": 1,
            "medium": 3,
            "high": 7,
            "critical": 10
        }

        total_weight = sum(severity_weights.get(v.get("severity", "low"), 1) for v in vulnerabilities)
        max_possible_score = len(vulnerabilities) * 10

        score = max(0, 100 - (total_weight / max_possible_score * 100))
        return round(score, 2)

    def generate_security_report(self, vulnerabilities_by_file: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        all_vulnerabilities = []
        for vulnerabilities in vulnerabilities_by_file.values():
            all_vulnerabilities.extend(vulnerabilities)

        if not all_vulnerabilities:
            return {
                "total_vulnerabilities": 0,
                "security_score": 100.0,
                "summary": "未发现安全漏洞",
                "by_severity": {},
                "by_type": {},
                "recommendations": ["继续遵循安全最佳实践"]
            }

        by_severity = {}
        for vuln in all_vulnerabilities:
            severity = vuln.get("severity", "unknown")
            by_severity[severity] = by_severity.get(severity, 0) + 1

        by_type = {}
        for vuln in all_vulnerabilities:
            vtype = vuln.get("type", "unknown")
            by_type[vtype] = by_type.get(vtype, 0) + 1

        recommendations = self._generate_recommendations(all_vulnerabilities)

        return {
            "total_vulnerabilities": len(all_vulnerabilities),
            "security_score": self.get_security_score(all_vulnerabilities),
            "summary": f"发现 {len(all_vulnerabilities)} 个安全漏洞",
            "by_severity": by_severity,
            "by_type": by_type,
            "vulnerabilities_by_file": vulnerabilities_by_file,
            "recommendations": recommendations
        }

    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        recommendations = []

        types_seen = set(vuln.get("type") for vuln in vulnerabilities)

        if VulnerabilityType.CONTEXT_TO_SINK.value in types_seen:
            recommendations.append("对所有GitHub上下文数据进行输入验证和清理")

        if VulnerabilityType.TOKEN_EXPOSURE.value in types_seen:
            recommendations.append("确保所有敏感信息都通过GitHub Secrets管理")

        if VulnerabilityType.UNSAFE_EXPRESSION.value in types_seen:
            recommendations.append("避免在shell命令中直接使用GitHub表达式")

        if "MissingPermissions" in types_seen:
            recommendations.append("为工作流添加明确的权限声明")

        if "InsecureAction" in types_seen:
            recommendations.append("更新所有Action到最新稳定版本")

        recommendations.extend([
            "定期审查和更新工作流配置",
            "启用分支保护规则",
            "使用代码扫描工具持续监控安全问题"
        ])

        return recommendations


