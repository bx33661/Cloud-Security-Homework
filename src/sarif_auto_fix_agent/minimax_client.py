#!/usr/bin/env python3

import json
import logging
import sys
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class AIModel(Enum):
    MINIMAX_M2 = "MiniMax-M2"
    DEEPSEEK_CHAT = "deepseek-chat"
    DEEPSEEK_CODING = "deepseek-coder"
    ABAB6_CHAT = "abab6.5-chat"
    ABAB6_GPT = "abab6.5-gpt"


@dataclass
class AIRequest:
    model: AIModel
    messages: List[Dict[str, str]]
    temperature: float = 0.7
    max_tokens: int = 4000
    stream: bool = False


@dataclass
class AIResponse:
    content: str
    model: str
    usage: Dict[str, int]
    finish_reason: str
    chain_of_thought: Optional[str] = None


class ChainOfThoughtLogger:
    def __init__(self):
        self.thought_chain: List[Dict[str, Any]] = []
        self.current_step = 0

    def add_step(self, step_name: str, input_data: Any, output_data: Any,
                reasoning: str, confidence: float = 1.0, verbose: bool = False) -> None:
        step = {
            "step": self.current_step,
            "timestamp": time.time(),
            "step_name": step_name,
            "input": input_data,
            "output": output_data,
            "reasoning": reasoning,
            "confidence": confidence
        }
        self.thought_chain.append(step)
        self.current_step += 1

    def _make_serializable(self, obj: Any) -> Any:
        if isinstance(obj, AIResponse):
            return {
                "content": obj.content,
                "model": obj.model,
                "usage": obj.usage,
                "finish_reason": obj.finish_reason,
                "chain_of_thought": obj.chain_of_thought
            }
        elif isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [self._make_serializable(item) for item in obj]
        elif hasattr(obj, '__dict__'):
            return str(obj)
        else:
            return obj

    def export_to_dict(self) -> Dict[str, Any]:
        serializable_steps = [self._make_serializable(step) for step in self.thought_chain]

        return {
            "total_steps": len(self.thought_chain),
            "steps": serializable_steps
        }

    def export_to_json(self, file_path: str) -> None:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(self.export_to_dict(), f, indent=2, ensure_ascii=False)

        logger.info(f"思维链已导出到: {file_path}")


class MinimaxClient:
    def __init__(self, api_key: str, base_url: str = "https://api.minimaxi.com/v1/text/chatcompletion_v2",
                 model: AIModel = AIModel.MINIMAX_M2):
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.chain_logger = ChainOfThoughtLogger()

        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        logger.info(f"Minimax客户端初始化完成，使用模型: {model.value}")

    def chat(self, messages: List[Dict[str, str]], temperature: float = 0.7,
             max_tokens: int = 4000) -> AIResponse:
        user_msg = next((msg.get("content", "") for msg in messages if msg.get("role") == "user"), "")
        if user_msg:
            logger.info(f"💬 发送请求 ({self.model.value})...")

        self.chain_logger.add_step(
            "API请求准备",
            {"messages": messages, "messages_count": len(messages), "temperature": temperature, "max_tokens": max_tokens},
            {"model": self.model.value},
            "准备发送请求到Minimax API",
            confidence=1.0,
            verbose=False
        )

        request_data = {
            "model": self.model.value,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True
        }

        try:
            self.chain_logger.add_step(
                "发送API请求",
                {"url": self.base_url},
                "请求中...",
                "向Minimax API发送HTTP请求",
                confidence=1.0,
                verbose=False
            )

            response = self.session.post(
                self.base_url,
                headers=self.headers,
                json=request_data,
                timeout=60,
                stream=True
            )

            response.raise_for_status()

            content = ""
            usage = {}
            finish_reason = "stop"
            model_name = self.model.value

            logger.info("🤖 AI响应:")
            print("─" * 80)
            sys.stdout.flush()

            for line in response.iter_lines():
                if not line:
                    continue

                line_text = line.decode('utf-8')
                if line_text.startswith('data: '):
                    data_str = line_text[6:].strip()
                    if data_str == '[DONE]':
                        break

                    try:
                        data = json.loads(data_str)
                        if "choices" in data and len(data["choices"]) > 0:
                            choice = data["choices"][0]
                            delta = choice.get("delta", {})
                            if "content" in delta:
                                chunk = delta["content"]
                                content += chunk
                                sys.stdout.write(chunk)
                                sys.stdout.flush()

                            if "usage" in data:
                                usage.update(data["usage"])
                            if "finish_reason" in choice and choice["finish_reason"]:
                                finish_reason = choice["finish_reason"]
                            if "model" in data:
                                model_name = data["model"]
                    except json.JSONDecodeError as e:
                        continue

            print()
            print("─" * 80)
            sys.stdout.flush()

            self.chain_logger.add_step(
                "处理API响应",
                {"status_code": response.status_code},
                {"content_length": len(content)},
                "解析API流式响应数据",
                confidence=1.0,
                verbose=False
            )

            ai_response = AIResponse(
                content=content,
                model=model_name,
                usage=usage,
                finish_reason=finish_reason,
                chain_of_thought=self._extract_chain_of_thought(content)
            )

            self.chain_logger.add_step(
                "生成最终响应",
                {},
                ai_response,
                "构建AI响应对象并提取思维链",
                confidence=0.9,
                verbose=False
            )

            return ai_response

        except requests.exceptions.RequestException as e:
            error_msg = f"API请求失败: {str(e)}"
            logger.error(error_msg)
            self.chain_logger.add_step(
                "API请求错误",
                {"error": str(e)},
                None,
                "处理API请求异常",
                confidence=0.0
            )
            raise
        except Exception as e:
            error_msg = f"响应处理失败: {str(e)}"
            logger.error(error_msg)
            self.chain_logger.add_step(
                "响应处理错误",
                {"error": str(e)},
                None,
                "处理响应数据时发生异常",
                confidence=0.0
            )
            raise

    def _extract_chain_of_thought(self, content: str) -> Optional[str]:
        lines = content.split('\n')
        chain_parts = []

        in_thought_chain = False
        for line in lines:
            line = line.strip()
            if "思维链" in line or "推理过程" in line or "chain of thought" in line.lower():
                in_thought_chain = True
                continue
            elif line.startswith("---") or "结论" in line:
                if in_thought_chain:
                    break

            if in_thought_chain and line:
                chain_parts.append(line)

        return '\n'.join(chain_parts) if chain_parts else None

    def analyze_vulnerability(self, vulnerability_data: Dict[str, Any]) -> AIResponse:
        self.chain_logger.add_step(
            "漏洞分析开始",
            vulnerability_data,
            "分析中...",
            "开始使用AI分析漏洞详情",
            confidence=1.0,
            verbose=False
        )

        prompt = self._build_vulnerability_analysis_prompt(vulnerability_data)

        messages = [
            {
                "role": "system",
                "content": "你是GitHub Action安全专家，专注分析和修复工作流安全漏洞。输出简洁、专业、可执行。"
            },
            {
                "role": "user",
                "content": prompt
            }
        ]

        response = self.chat(messages, temperature=0.3, max_tokens=2000)

        self.chain_logger.add_step(
            "漏洞分析完成",
            vulnerability_data,
            response.content,
            f"完成漏洞分析，生成了{len(response.content)}字符的修复建议",
            confidence=0.9,
            verbose=False
        )

        return response

    def generate_fix_code(self, workflow_content: str, vulnerability_info: Dict[str, Any]) -> AIResponse:
        self.chain_logger.add_step(
            "修复代码生成开始",
            {"workflow_length": len(workflow_content), "vulnerability": vulnerability_info},
            "生成中...",
            "开始使用AI生成具体的修复代码",
            confidence=1.0,
            verbose=False
        )

        prompt = self._build_fix_code_prompt(workflow_content, vulnerability_info)

        messages = [
            {
                "role": "system",
                "content": "你是GitHub Action安全修复专家。输出完整、安全、可用的YAML代码，仅修复指定漏洞，保持原有功能。"
            },
            {
                "role": "user",
                "content": prompt
            }
        ]

        response = self.chat(messages, temperature=0.2, max_tokens=3000)

        self.chain_logger.add_step(
            "修复代码生成完成",
            {"workflow_length": len(workflow_content)},
            response.content,
            f"生成了{len(response.content)}字符的修复代码",
            confidence=0.9,
            verbose=False
        )

        return response

    def _build_vulnerability_analysis_prompt(self, vulnerability_data: Dict[str, Any]) -> str:
        return f"""分析GitHub Action安全漏洞并提供修复方案。

漏洞信息：
- 规则ID: {vulnerability_data.get('rule_id', 'unknown')}
- 严重性: {vulnerability_data.get('severity', 'unknown')}
- 描述: {vulnerability_data.get('message', 'unknown')}
- 位置: {vulnerability_data.get('workflow', 'unknown')}/{vulnerability_data.get('job', 'unknown')}/{vulnerability_data.get('step', 'unknown')}

输出要求：
1. 简要说明安全风险和攻击向量
2. 提供可行的修复方案
3. 评估修复优先级（P0/P1/P2）
4. 说明修复理由

请用简洁、结构化的方式输出。"""

    def _build_fix_code_prompt(self, workflow_content: str, vulnerability_info: Dict[str, Any]) -> str:
        return f"""修复以下GitHub Action工作流的安全漏洞：

当前工作流：
```yaml
{workflow_content}
```

漏洞信息：
- 类型: {vulnerability_info.get('rule_id', 'unknown')}
- 描述: {vulnerability_info.get('message', 'unknown')}
- 位置: {vulnerability_info.get('workflow', 'unknown')}/{vulnerability_info.get('job', 'unknown')}/{vulnerability_info.get('step', 'unknown')}

要求：
1. 仅修复指定漏洞，不改动其他代码
2. 保持原有功能不变
3. 使用安全的编码实践（输入验证、参数化查询等）
4. 输出完整修复后的YAML代码
5. 用注释说明修复理由

直接输出修复后的YAML代码（包含```yaml代码块）。"""

    def get_chain_of_thought(self) -> ChainOfThoughtLogger:
        return self.chain_logger

    def reset_chain_of_thought(self) -> None:
        self.chain_logger = ChainOfThoughtLogger()
