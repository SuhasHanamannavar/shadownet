import time
import random
import re

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from database import HoneypotDatabase
from models import AttackerType, SystemPersona

@dataclass
class CommandHistory:
    command: str
    timestamp: datetime
    response_time: float
    success: bool

class AttackerClassifier:
    def __init__(self):
        self.command_history: List[CommandHistory] = []
        self.typical_bot_commands = {
            'wget', 'curl', 'nc', 'telnet', 'ssh', 'ftp', 'scanner',
            'nmap', 'masscan', 'dirb', 'gobuster', 'nikto', 'sqlmap'
        }
        self.typical_human_commands = {
            'ls', 'cd', 'pwd', 'cat', 'whoami', 'ps', 'top', 'nano',
            'vim', 'mkdir', 'rm', 'cp', 'mv', 'chmod', 'chown'
        }
        self.model = None
        try:
            import joblib
            import os
            if os.path.exists('model.pkl'):
                self.model = joblib.load('model.pkl')
        except Exception as e:
            print(f"[ML Classifier] Error loading model: {e}")
        
    def add_command(self, command: str, response_time: float, success: bool):
        self.command_history.append(
            CommandHistory(command, datetime.now(), response_time, success)
        )
        if len(self.command_history) > 100:
            self.command_history.pop(0)
    
    def classify_attacker(self) -> AttackerType:
        if len(self.command_history) < 3:
            return AttackerType.HUMAN
        
        recent_commands = self.command_history[-10:]
        
        if self.model is not None:
            try:
                dur = (datetime.now() - self.command_history[0].timestamp).total_seconds()
                spkts = len(self.command_history)
                sbytes = sum(len(c.command) for c in self.command_history)
                rate = spkts / max(dur, 0.1)
                
                # Suppress sklearn warnings about feature names by providing DataFrame or array with no warnings
                # but passing 2D list is usually fine.
                prediction = self.model.predict([[dur, spkts, sbytes, rate]])[0]
                
                if prediction == 'BOT':
                    return AttackerType.BOT
                elif prediction == 'ADVANCED':
                    return AttackerType.ADVANCED
                else:
                    return AttackerType.HUMAN
            except Exception:
                pass
        
        bot_score = self._calculate_bot_score(recent_commands)
        advanced_score = self._calculate_advanced_score(recent_commands)
        
        if bot_score > 0.7:
            return AttackerType.BOT
        elif advanced_score > 0.6:
            return AttackerType.ADVANCED
        else:
            return AttackerType.HUMAN
    
    def _calculate_bot_score(self, commands: List[CommandHistory]) -> float:
        bot_command_ratio = sum(1 for cmd in commands 
                               if any(bot_cmd in cmd.command.lower() 
                                    for bot_cmd in self.typical_bot_commands)) / len(commands)
        
        avg_response_time = sum(cmd.response_time for cmd in commands) / len(commands)
        speed_score = 1.0 if avg_response_time < 0.1 else 0.5
        
        consistency_score = self._calculate_timing_consistency(commands)
        
        return (bot_command_ratio * 0.5 + speed_score * 0.3 + consistency_score * 0.2)
    
    def _calculate_advanced_score(self, commands: List[CommandHistory]) -> float:
        advanced_patterns = [
            r'find.*-exec', r'grep.*-r', r'python.*-c', r'bash.*-c',
            r'sudo.*su', r'crontab.*-e', r'systemctl.*status'
        ]
        
        advanced_commands = sum(1 for cmd in commands 
                              if any(re.search(pattern, cmd.command) 
                                   for pattern in advanced_patterns))
        
        exploration_score = self._calculate_exploration_score(commands)
        
        return (advanced_commands / len(commands) * 0.6 + exploration_score * 0.4)
    
    def _calculate_timing_consistency(self, commands: List[CommandHistory]) -> float:
        if len(commands) < 2:
            return 0.0
        
        timings = [cmd.response_time for cmd in commands]
        avg_time = sum(timings) / len(timings)
        variance = sum((t - avg_time) ** 2 for t in timings) / len(timings)
        
        return 1.0 / (1.0 + variance)
    
    def _calculate_exploration_score(self, commands: List[CommandHistory]) -> float:
        unique_dirs = set()
        file_ops = 0
        
        for cmd in commands:
            if 'cd' in cmd.command:
                unique_dirs.add(cmd.command.split()[-1] if len(cmd.command.split()) > 1 else '')
            elif any(op in cmd.command for op in ['cat', 'ls', 'find', 'grep']):
                file_ops += 1
        
        return min(1.0, (len(unique_dirs) + file_ops) / len(commands))

class ResponseEngine:
    def __init__(self):
        self.personas = {
            SystemPersona.LINUX_SERVER: self._init_linux_server_persona(),
            SystemPersona.IOT_DEVICE: self._init_iot_device_persona(),
            SystemPersona.ENTERPRISE_SERVER: self._init_enterprise_server_persona()
        }
        self.current_persona = SystemPersona.LINUX_SERVER
        
    def _init_linux_server_persona(self) -> Dict:
        return {
            'prompt': 'user@linux-server:~$ ',
            'hostname': 'linux-server',
            'username': 'user',
            'os_info': 'Linux linux-server 4.15.0-142-generic #146-Ubuntu SMP',
            'fake_files': {
                '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:user:/home/user:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin',
                '/etc/shadow': 'root:$6$rounds=656000$...:18593:0:99999:7:::\nuser:$6$rounds=656000$...:18593:0:99999:7:::',
                '/home/user/.bash_history': 'ls -la\ncd /var/www\nsudo systemctl status nginx\nnano config.php',
                '/proc/version': 'Linux version 4.15.0-142-generic (buildd@lcy01-amd64-014)',
                '/etc/issue': 'Ubuntu 18.04.5 LTS \\n \\l'
            },
            'fake_processes': ['nginx', 'mysql', 'sshd', 'cron', 'systemd'],
            'fake_services': ['nginx', 'mysql', 'ssh', 'ufw']
        }
    
    def _init_iot_device_persona(self) -> Dict:
        return {
            'prompt': 'admin@iot-device:~$ ',
            'hostname': 'iot-device',
            'username': 'admin',
            'os_info': 'Linux iot-device 3.10.14 #1 SMP Wed Aug 7 15:30:00 UTC 2019 armv7l',
            'fake_files': {
                '/etc/passwd': 'root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000:admin:/home/admin:/bin/sh',
                '/etc/shadow': 'root:$1$...:18593:0:99999:7:::\nadmin:$1$...:18593:0:99999:7:::',
                '/proc/version': 'Linux version 3.10.14 (build@build-server)',
                '/etc/issue': 'OpenWrt 19.07.7 r11206-9508f3b6c2',
                '/etc/config/network': 'config interface \'loopback\'\n\toption ifname \'lo\'\n\toption proto \'static\'\n\toption ipaddr \'127.0.0.1\'\n\toption netmask \'255.0.0.0\''
            },
            'fake_processes': ['dropbear', 'dnsmasq', 'uhttpd'],
            'fake_services': ['dropbear', 'dnsmasq', 'firewall']
        }
    
    def _init_enterprise_server_persona(self) -> Dict:
        return {
            'prompt': 'admin@corp-server:~$ ',
            'hostname': 'corp-server',
            'username': 'admin',
            'os_info': 'Linux corp-server 3.10.0-1160.el7.x86_64 #1 SMP Mon Nov 9 15:04:24 UTC 2020 x86_64',
            'fake_files': {
                '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:admin:/home/admin:/bin/bash\noracle:x:54321:54321:Oracle:/home/oracle:/bin/bash\napache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin',
                '/etc/shadow': 'root:$6$rounds=656000$...:18593:0:99999:7:::\nadmin:$6$rounds=656000$...:18593:0:99999:7:::',
                '/proc/version': 'Linux version 3.10.0-1160.el7.x86_64 (mockbuild@x86-040.build.eng.bos.redhat.com)',
                '/etc/issue': 'CentOS Linux release 7.9.2009 (Core)',
                '/etc/redhat-release': 'CentOS Linux release 7.9.2009 (Core)'
            },
            'fake_processes': ['httpd', 'mysqld', 'sshd', 'crond', 'systemd', 'oracle'],
            'fake_services': ['httpd', 'mysqld', 'ssh', 'firewalld', 'network']
        }
    
    def switch_persona(self, persona: SystemPersona):
        self.current_persona = persona
    
    def generate_response(self, command: str, attacker_type: AttackerType) -> Tuple[str, float]:
        start_time = time.time()
        
        persona = self.personas[self.current_persona]
        
        response = self._handle_command(command, persona, attacker_type)
        
        response_time = time.time() - start_time
        
        if attacker_type == AttackerType.BOT:
            response_time *= 0.5
        elif attacker_type == AttackerType.ADVANCED:
            response_time *= 1.2
        
        return response, response_time
    
    def _handle_command(self, command: str, persona: Dict, attacker_type: AttackerType) -> str:
        cmd_parts = command.strip().split()
        if not cmd_parts:
            return ""
        
        base_cmd = cmd_parts[0].lower()
        
        if base_cmd in ['ls', 'dir']:
            return self._handle_ls(cmd_parts, persona)
        elif base_cmd == 'cd':
            return self._handle_cd(cmd_parts, persona)
        elif base_cmd == 'cat':
            return self._handle_cat(cmd_parts, persona)
        elif base_cmd == 'pwd':
            return self._handle_pwd(persona)
        elif base_cmd == 'whoami':
            return persona['username']
        elif base_cmd == 'ps':
            return self._handle_ps(persona)
        elif base_cmd == 'uname':
            return self._handle_uname(cmd_parts, persona)
        elif base_cmd in ['wget', 'curl']:
            return self._handle_download(cmd_parts, persona)
        elif base_cmd in ['find', 'grep']:
            return self._handle_search(cmd_parts, persona, attacker_type)
        elif base_cmd == 'sudo':
            return self._handle_sudo(cmd_parts, persona, attacker_type)
        elif base_cmd in ['systemctl', 'service']:
            return self._handle_service(cmd_parts, persona)
        elif base_cmd == 'ifconfig':
            return self._handle_ifconfig(persona)
        elif base_cmd == 'netstat':
            return self._handle_netstat(persona)
        else:
            return f"{base_cmd}: command not found"
    
    def _handle_ls(self, cmd_parts: List[str], persona: Dict) -> str:
        if '-la' in cmd_parts or '-l' in cmd_parts:
            return f"total 24\ndrwxr-xr-x 3 {persona['username']} {persona['username']} 4096 Dec 10 14:32 .\ndrwxr-xr-x 3 root root 4096 Dec 10 14:30 ..\n-rw------- 1 {persona['username']} {persona['username']}  220 Dec 10 14:30 .bash_logout\n-rw------- 1 {persona['username']} {persona['username']} 3771 Dec 10 14:30 .bashrc\n-rw------- 1 {persona['username']} {persona['username']}  807 Dec 10 14:30 .profile\ndrwxr-xr-x 2 {persona['username']} {persona['username']} 4096 Dec 10 14:32 documents"
        else:
            return "documents  .bashrc  .profile  .bash_logout"
    
    def _handle_cd(self, cmd_parts: List[str], persona: Dict) -> str:
        if len(cmd_parts) > 1:
            target = cmd_parts[1]
            if target == '..':
                return ""
            elif target in ['/', '/home', f'/home/{persona["username"]}']:
                return ""
            elif target == 'documents':
                return ""
            else:
                return f"cd: {target}: No such file or directory"
        return ""
    
    def _handle_cat(self, cmd_parts: List[str], persona: Dict) -> str:
        if len(cmd_parts) > 1:
            filepath = cmd_parts[1]
            return persona['fake_files'].get(filepath, f"cat: {filepath}: No such file or directory")
        return "cat: missing file operand"
    
    def _handle_pwd(self, persona: Dict) -> str:
        return f"/home/{persona['username']}"
    
    def _handle_ps(self, persona: Dict) -> str:
        processes = persona['fake_processes']
        result = "  PID TTY          TIME CMD\n"
        for i, proc in enumerate(processes[:5], 1):
            result += f" {i:3d} pts/0    00:00:01 {proc}\n"
        return result.strip()
    
    def _handle_uname(self, cmd_parts: List[str], persona: Dict) -> str:
        if '-a' in cmd_parts:
            return persona['os_info']
        elif '-r' in cmd_parts:
            return persona['os_info'].split()[2]
        else:
            return "Linux"
    
    def _handle_download(self, cmd_parts: List[str], persona: Dict) -> str:
        if len(cmd_parts) > 1:
            url = cmd_parts[1]
            filename = url.split('/')[-1] if '/' in url else 'downloaded_file'
            return f"--2023-12-10 14:32:15--  {url}\nResolving {url.split('/')[2]}... 192.168.1.100\nConnecting to {url.split('/')[2]}|192.168.1.100|:80... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 1024 [application/octet-stream]\nSaving to: '{filename}'\n\n{filename}             100%[====================================>]  1024  --.-KB/s   in 0s\n\n2023-12-10 14:32:15 (-- KB/s) - '{filename}' saved [1024/1024]"
        return f"{cmd_parts[0]}: missing URL"
    
    def _handle_search(self, cmd_parts: List[str], persona: Dict, attacker_type: AttackerType) -> str:
        if attacker_type == AttackerType.ADVANCED:
            return "/home/user/documents/config.txt\n/etc/nginx/nginx.conf\n/var/log/access.log"
        else:
            return "/home/user/documents/config.txt"
    
    def _handle_sudo(self, cmd_parts: List[str], persona: Dict, attacker_type: AttackerType) -> str:
        if attacker_type == AttackerType.ADVANCED:
            return "[sudo] password for user: \nsudo: 1 incorrect password attempt"
        else:
            return "[sudo] password for user: \nSorry, try again.\n[sudo] password for user: \nsudo: 1 incorrect password attempt"
    
    def _handle_service(self, cmd_parts: List[str], persona: Dict) -> str:
        if len(cmd_parts) >= 3:
            service = cmd_parts[1]
            action = cmd_parts[2]
            if service in persona['fake_services']:
                if action in ['status', 'start', 'stop', 'restart']:
                    return f"● {service}.service - {service.title()} daemon\n   Loaded: loaded (/lib/systemd/system/{service}.service; enabled; vendor preset: enabled)\n   Active: active (running) since Mon 2023-12-10 14:30:00 UTC; 2min 32s ago\n Main PID: 1234 ({service})\n    Tasks: 2 (limit: 4915)\n   Memory: 5.2M\n   CGroup: /system.slice/{service}.service\n           └─1234 /usr/sbin/{service}"
        return f"Failed to {cmd_parts[2] if len(cmd_parts) > 2 else 'start'} {cmd_parts[1] if len(cmd_parts) > 1 else 'service'}: Unit not found."
    
    def _handle_ifconfig(self, persona: Dict) -> str:
        return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n        inet6 fe80::a00:27ff:fe2b:c701  prefixlen 64  scopeid 0x20<link>\n        ether 08:00:27:2b:c7:01  txqueuelen 1000  (Ethernet)\n        RX packets 1234  bytes 123456 (123.4 KiB)\n        RX errors 0  dropped 0  overruns 0  frame 0\n        TX packets 567  bytes 78901 (78.9 KiB)\n        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0"
    
    def _handle_netstat(self, persona: Dict) -> str:
        return "Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State      \ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     \ntcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     \ntcp        0      0 127.0.0.1:3306         0.0.0.0:*               LISTEN     \ntcp6       0      0 :::22                   :::*                    LISTEN     \ntcp6       0      0 :::80                   :::*                    LISTEN     "

class HoneypotAI:
    def __init__(self, db_connection_string: str = "mongodb://localhost:27017/", 
                 db_name: str = "honeypot_db", ip_address: str = "127.0.0.1", 
                 user_agent: str = None):
        self.classifier = AttackerClassifier()
        self.response_engine = ResponseEngine()
        self.session_start = datetime.now()
        self.command_count = 0
        self.db = HoneypotDatabase(db_connection_string, db_name)
        self.session_id = self.db.create_session(ip_address, user_agent)
        
    def process_command(self, command: str) -> str:
        start_time = time.time()
        self.command_count += 1
        
        attacker_type = self.classifier.classify_attacker()
        
        if self.command_count % 10 == 0:
            self._adapt_persona(attacker_type)
        
        response, response_time = self.response_engine.generate_response(command, attacker_type)
        
        self.classifier.add_command(command, response_time, True)
        
        # Log command to database
        try:
            self.db.log_command(
                session_id=self.session_id,
                command=command,
                response=response,
                response_time=response_time,
                attacker_type=attacker_type,
                current_persona=self.response_engine.current_persona,
                success=True
            )
            
            # Update session classification if it changed
            self.db.update_session_classification(self.session_id, attacker_type)
            
        except Exception as e:
            print(f"Database logging error: {e}")
        
        if response and not response.endswith('\n'):
            response += '\n'
        
        return response
    
    def _adapt_persona(self, attacker_type: AttackerType):
        if attacker_type == AttackerType.BOT:
            personas = [SystemPersona.LINUX_SERVER, SystemPersona.IOT_DEVICE]
            self.response_engine.switch_persona(random.choice(personas))
        elif attacker_type == AttackerType.ADVANCED:
            self.response_engine.switch_persona(SystemPersona.ENTERPRISE_SERVER)
        else:
            self.response_engine.switch_persona(SystemPersona.LINUX_SERVER)
    
    def get_prompt(self) -> str:
        return self.response_engine.personas[self.response_engine.current_persona]['prompt']
    
    def get_attacker_classification(self) -> str:
        return self.classifier.classify_attacker().value
    
    def get_session_stats(self) -> Dict:
        local_stats = {
            'session_duration': (datetime.now() - self.session_start).total_seconds(),
            'command_count': self.command_count,
            'current_persona': self.response_engine.current_persona.value,
            'attacker_type': self.classifier.classify_attacker().value,
            'session_id': self.session_id
        }
        
        try:
            db_stats = self.db.get_session_stats(self.session_id)
            return {**local_stats, 'database_stats': db_stats}
        except Exception as e:
            print(f"Error getting database stats: {e}")
            return local_stats
    
    def end_session(self):
        try:
            self.db.end_session(self.session_id)
            self.db.close()
        except Exception as e:
            print(f"Error ending session: {e}")
    
    def get_dashboard_data(self, hours: int = 24) -> Dict:
        try:
            return self.db.get_dashboard_data(hours)
        except Exception as e:
            print(f"Error getting dashboard data: {e}")
            return {}

if __name__ == "__main__":
    import socket
    
    # Get local IP for session tracking
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
    except:
        local_ip = "127.0.0.1"
    
    honeypot = HoneypotAI(ip_address=local_ip, user_agent="Honeypot CLI")
    
    print("Honeypot AI Engine Started")
    print("Type commands to test (or 'quit' to exit)")
    print(f"Session ID: {honeypot.session_id}")
    print(f"Current prompt: {honeypot.get_prompt()}")
    
    try:
        while True:
            try:
                command = input(honeypot.get_prompt()).strip()
                
                if command.lower() in ['quit', 'exit']:
                    break
                
                if command:
                    response = honeypot.process_command(command)
                    print(response)
                    
                    if honeypot.command_count % 5 == 0:
                        stats = honeypot.get_session_stats()
                        print(f"[DEBUG] Session: {stats['session_id'][:8]}..., Attacker: {stats['attacker_type']}, Persona: {stats['current_persona']}")
                        
            except KeyboardInterrupt:
                break
    except Exception as e:
        print(f"Error starting honeypot: {e}")
    finally:
        honeypot.end_session()

    print("\nFinal session stats:")
    final_stats = honeypot.get_session_stats()
    for key, value in final_stats.items():
        if key != 'database_stats':
            print(f"  {key}: {value}")

    # Show dashboard summary
    try:
        dashboard = honeypot.get_dashboard_data()
        if dashboard:
            print("\nRecent Activity Dashboard:")
            overview = dashboard.get('overview', {})
            print(f"  Total sessions: {overview.get('total_sessions', 0)}")
            print(f"  Active sessions: {overview.get('active_sessions', 0)}")
            print(f"  Total commands: {overview.get('total_commands', 0)}")
            
            attacker_breakdown = dashboard.get('attacker_breakdown', [])
            if attacker_breakdown:
                print("  Attacker types:")
                for item in attacker_breakdown:
                    print(f"    {item.get('attacker_type', 'unknown')}: {item.get('count', 0)} sessions")
    except Exception as e:
        print(f"Error getting dashboard: {e}")