# Re-export integration classes for backwards compatibility and test patching.
from .intel import ThreatIntelService
from .jira import create_jira_issue
from .scoring import ScoringEngine

__all__ = ["ThreatIntelService", "create_jira_issue", "ScoringEngine"]
