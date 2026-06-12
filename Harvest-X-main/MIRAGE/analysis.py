import re
from datetime import datetime
from typing import List, Dict, Any

class BehavioralAnalysisEngine:
    """
    Analyzes attacker inputs including command patterns, timing, and tool usage 
    to classify intent.
    """
    
    def __init__(self):
        self.sessions: Dict[str, Dict[str, Any]] = {}
        
    def add_event(self, session_id: str, event: Dict[str, Any]):
        """Process an event from Cowrie logs."""
        if session_id not in self.sessions:
            self.sessions[session_id] = {
                "src_ip": event.get("src_ip", "Unknown"),
                "commands": [],
                "start_time": datetime.fromisoformat(event.get('timestamp', datetime.utcnow().isoformat()).replace('Z', '+00:00')),
                "last_time": None,
                "tool_usage": set(),
                "classification": "UNKNOWN",
                "risk_score": 0
            }
            
        session = self.sessions[session_id]
        
        event_time = datetime.fromisoformat(event.get('timestamp', datetime.utcnow().isoformat()).replace('Z', '+00:00'))
        if session["last_time"]:
            time_diff = (event_time - session["last_time"]).total_seconds()
            # Fast automated tools typically execute commands very quickly
            if event.get("eventid") == "cowrie.command.input" and time_diff < 0.2:
                session["risk_score"] += 1
                
        session["last_time"] = event_time
        
        if event.get("eventid") == "cowrie.command.input":
            cmd = event.get("input", "").strip()
            if cmd:
                session["commands"].append(cmd)
                self._analyze_command(session, cmd)
                
        self._classify_session(session)
        
    def _analyze_command(self, session: Dict[str, Any], cmd: str):
        """Analyzes specific command patterns and tool usage."""
        tools = ['wget', 'curl', 'nmap', 'nc', 'tar', 'gcc', 'python', 'perl', 'bash']
        for tool in tools:
            if re.search(rf'\b{tool}\b', cmd):
                session["tool_usage"].add(tool)
                session["risk_score"] += 2
                
        # Look for reconnaissance patterns
        recon_patterns = [r'cat /etc/passwd', r'uname -a', r'id', r'whoami', r'ifconfig', r'netstat']
        for pattern in recon_patterns:
            if re.search(pattern, cmd):
                session["risk_score"] += 1
                
        # Look for exploitation/download patterns
        exploit_patterns = [r'chmod \+x', r'./', r'rm -rf']
        for pattern in exploit_patterns:
            if re.search(pattern, cmd):
                session["risk_score"] += 3

    def _classify_session(self, session: Dict[str, Any]):
        """Classifies the attacker based on accumulated data."""
        score = session["risk_score"]
        cmd_count = len(session["commands"])
        tools_used = len(session["tool_usage"])
        
        if cmd_count > 0:
            if score >= 10 or tools_used >= 3:
                session["classification"] = "ADVANCED_THREAT"
            elif score >= 5 or tools_used >= 1:
                session["classification"] = "AUTOMATED_BOT"
            elif score > 0:
                session["classification"] = "EXPLORATORY"
            else:
                session["classification"] = "BENIGN"

    def get_session_summary(self, session_id: str) -> Dict[str, Any]:
        """Returns the current summary of a session."""
        if session_id in self.sessions:
            summary = self.sessions[session_id].copy()
            summary["tool_usage"] = list(summary["tool_usage"]) # Convert set to list for JSON serialization
            return summary
        return {}
        
    def get_all_sessions(self) -> Dict[str, Any]:
        """Returns all sessions."""
        return {
            sid: self.get_session_summary(sid)
            for sid in self.sessions
        }
