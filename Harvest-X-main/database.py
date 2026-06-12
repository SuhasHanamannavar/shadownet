import pymongo
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import uuid
from models import AttackerType, SystemPersona

@dataclass
class AttackerSession:
    session_id: str
    ip_address: str
    user_agent: Optional[str]
    start_time: datetime
    end_time: Optional[datetime]
    final_attacker_type: str
    total_commands: int
    personas_used: List[str]
    attack_patterns: List[str]
    suspicious_commands: List[str]
    metadata: Dict[str, Any]

@dataclass
class CommandLog:
    session_id: str
    command: str
    timestamp: datetime
    response_time: float
    attacker_type: str
    current_persona: str
    response: str
    success: bool
    risk_score: float

class HoneypotDatabase:
    def __init__(self, connection_string: str = "mongodb://localhost:27017/", database_name: str = "honeypot_db"):
        self.connection_string = connection_string
        self.database_name = database_name
        self.client = None
        self.db = None
        self.sessions_collection = None
        self.commands_collection = None
        self.connect()
    
    def connect(self):
        try:
            self.client = pymongo.MongoClient(self.connection_string)
            self.db = self.client[self.database_name]
            self.sessions_collection = self.db.sessions
            self.commands_collection = self.db.commands
            
            # Create indexes for better performance
            self.sessions_collection.create_index("session_id", unique=True)
            self.sessions_collection.create_index("start_time")
            self.sessions_collection.create_index("final_attacker_type")
            
            self.commands_collection.create_index("session_id")
            self.commands_collection.create_index("timestamp")
            self.commands_collection.create_index("attacker_type")
            self.commands_collection.create_index("risk_score")
            
            print(f"Connected to MongoDB: {self.database_name}")
            
        except Exception as e:
            print(f"Failed to connect to MongoDB: {e}")
            raise
    
    def create_session(self, ip_address: str, user_agent: str = None) -> str:
        session_id = str(uuid.uuid4())
        
        session = AttackerSession(
            session_id=session_id,
            ip_address=ip_address,
            user_agent=user_agent,
            start_time=datetime.utcnow(),
            end_time=None,
            final_attacker_type=AttackerType.HUMAN.value,
            total_commands=0,
            personas_used=[SystemPersona.LINUX_SERVER.value],
            attack_patterns=[],
            suspicious_commands=[],
            metadata={}
        )
        
        self.sessions_collection.insert_one(asdict(session))
        return session_id
    
    def log_command(self, session_id: str, command: str, response: str, 
                   response_time: float, attacker_type: AttackerType, 
                   current_persona: SystemPersona, success: bool = True):
        
        risk_score = self._calculate_risk_score(command, attacker_type)
        
        command_log = CommandLog(
            session_id=session_id,
            command=command,
            timestamp=datetime.utcnow(),
            response_time=response_time,
            attacker_type=attacker_type.value,
            current_persona=current_persona.value,
            response=response[:1000],  # Limit response size
            success=success,
            risk_score=risk_score
        )
        
        self.commands_collection.insert_one(asdict(command_log))
        
        # Update session with command count and patterns
        self.sessions_collection.update_one(
            {"session_id": session_id},
            {
                "$inc": {"total_commands": 1},
                "$addToSet": {"personas_used": current_persona.value},
                "$push": {"attack_patterns": self._extract_attack_pattern(command)},
                "$push": {"suspicious_commands": command if risk_score > 0.7 else None}
            }
        )
    
    def update_session_classification(self, session_id: str, attacker_type: AttackerType):
        self.sessions_collection.update_one(
            {"session_id": session_id},
            {"$set": {"final_attacker_type": attacker_type.value}}
        )
    
    def end_session(self, session_id: str):
        self.sessions_collection.update_one(
            {"session_id": session_id},
            {"$set": {"end_time": datetime.utcnow()}}
        )
    
    def get_session_stats(self, session_id: str) -> Dict:
        session = self.sessions_collection.find_one({"session_id": session_id})
        if not session:
            return {}
        
        command_stats = self.commands_collection.aggregate([
            {"$match": {"session_id": session_id}},
            {"$group": {
                "_id": "$attacker_type",
                "count": {"$sum": 1},
                "avg_response_time": {"$avg": "$response_time"},
                "avg_risk_score": {"$avg": "$risk_score"}
            }}
        ])
        
        session['command_stats'] = list(command_stats)
        return session
    
    def get_attacker_summary(self, hours: int = 24) -> Dict:
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        pipeline = [
            {"$match": {"start_time": {"$gte": cutoff_time}}},
            {"$group": {
                "_id": "$final_attacker_type",
                "count": {"$sum": 1},
                "avg_commands": {"$avg": "$total_commands"},
                "unique_ips": {"$addToSet": "$ip_address"}
            }},
            {"$project": {
                "attacker_type": "$_id",
                "count": 1,
                "avg_commands": {"$round": ["$avg_commands", 2]},
                "unique_ips": {"$size": "$unique_ips"}
            }}
        ]
        
        return list(self.sessions_collection.aggregate(pipeline))
    
    def get_high_risk_commands(self, hours: int = 24, min_risk: float = 0.7) -> List[Dict]:
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        return list(self.commands_collection.find({
            "timestamp": {"$gte": cutoff_time},
            "risk_score": {"$gte": min_risk}
        }).sort("risk_score", -1).limit(50))
    
    def get_attack_patterns(self, hours: int = 24) -> Dict:
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        pipeline = [
            {"$match": {"timestamp": {"$gte": cutoff_time}}},
            {"$unwind": "$attack_patterns"},
            {"$group": {
                "_id": "$attack_patterns",
                "count": {"$sum": 1}
            }},
            {"$sort": {"count": -1}},
            {"$limit": 20}
        ]
        
        return list(self.commands_collection.aggregate(pipeline))
    
    def _calculate_risk_score(self, command: str, attacker_type: AttackerType) -> float:
        risk = 0.0
        
        # High-risk command patterns
        high_risk_patterns = [
            'wget', 'curl', 'nc', 'telnet', 'ssh', 'ftp',
            'sudo', 'su', 'passwd', 'crontab', 'systemctl',
            'rm -rf', 'chmod 777', 'chown', 'find -exec',
            'python -c', 'perl -e', 'bash -c', 'sh -c'
        ]
        
        for pattern in high_risk_patterns:
            if pattern in command.lower():
                risk += 0.3
        
        # Attacker type risk
        if attacker_type == AttackerType.ADVANCED:
            risk += 0.4
        elif attacker_type == AttackerType.BOT:
            risk += 0.2
        
        # Command complexity
        if len(command.split()) > 5:
            risk += 0.1
        if ';' in command or '&&' in command or '||' in command:
            risk += 0.2
        
        return min(1.0, risk)
    
    def _extract_attack_pattern(self, command: str) -> str:
        cmd_parts = command.lower().split()
        if not cmd_parts:
            return "unknown"
        
        base_cmd = cmd_parts[0]
        
        # Categorize commands
        if base_cmd in ['wget', 'curl']:
            return "download"
        elif base_cmd in ['cat', 'less', 'more', 'head', 'tail']:
            return "file_read"
        elif base_cmd in ['find', 'grep', 'locate']:
            return "search"
        elif base_cmd in ['cd', 'pwd', 'ls']:
            return "navigation"
        elif base_cmd in ['chmod', 'chown', 'chgrp']:
            return "permission"
        elif base_cmd in ['sudo', 'su']:
            return "privilege_escalation"
        elif base_cmd in ['ps', 'top', 'htop']:
            return "process_info"
        elif base_cmd in ['netstat', 'ss', 'lsof']:
            return "network_info"
        elif base_cmd in ['systemctl', 'service']:
            return "service_management"
        elif base_cmd in ['rm', 'rmdir', 'unlink']:
            return "file_deletion"
        elif base_cmd in ['mkdir', 'touch', 'echo']:
            return "file_creation"
        else:
            return base_cmd
    
    def get_dashboard_data(self, hours: int = 24) -> Dict:
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Session overview
        total_sessions = self.sessions_collection.count_documents({"start_time": {"$gte": cutoff_time}})
        active_sessions = self.sessions_collection.count_documents({
            "start_time": {"$gte": cutoff_time},
            "end_time": None
        })
        
        # Command statistics
        total_commands = self.commands_collection.count_documents({"timestamp": {"$gte": cutoff_time}})
        
        # Top attacker types
        attacker_breakdown = self.get_attacker_summary(hours)
        
        # Recent high-risk activity
        recent_high_risk = self.get_high_risk_commands(hours, 0.5)[:10]
        
        # Attack patterns
        patterns = self.get_attack_patterns(hours)
        
        return {
            "overview": {
                "total_sessions": total_sessions,
                "active_sessions": active_sessions,
                "total_commands": total_commands,
                "timeframe_hours": hours
            },
            "attacker_breakdown": attacker_breakdown,
            "recent_high_risk": recent_high_risk,
            "attack_patterns": patterns
        }
    
    def close(self):
        if self.client:
            self.client.close()

# Import timedelta for the time calculations
from datetime import timedelta
