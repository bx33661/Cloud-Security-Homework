"""
SARIF自动修复Agent

基于SARIF漏洞报告的GitHub Action自动修复工具，集成Minimax AI。
"""

__version__ = "1.0.0"
__author__ = "Claude (Anthropic)"
__email__ = "noreply@anthropic.com"
__license__ = "MIT"

from .sarif_parser import SarifParser, Vulnerability, VulnerabilityLocation, SeverityLevel
from .minimax_client import MinimaxClient, AIModel, ChainOfThoughtLogger
from .auto_fix_engine import AutoFixEngine, FixResult
from .chain_of_thought_output import ChainOfThoughtOutput, ChainOfThoughtReport

__all__ = [
    "SarifParser",
    "Vulnerability",
    "VulnerabilityLocation",
    "SeverityLevel",
    "MinimaxClient",
    "AIModel",
    "ChainOfThoughtLogger",
    "AutoFixEngine",
    "FixResult",
    "ChainOfThoughtOutput",
    "ChainOfThoughtReport",
]
