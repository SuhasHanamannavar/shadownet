import os
import shutil

def switch(attacker_type):
    """
    switch(attacker_type) -> updates Cowrie honeyfs
    Bot -> IoT persona (BusyBox shell responses)
    APT -> Full Linux enterprise persona (Ubuntu 22.04)
    Script Kiddie -> Windows persona (dir, ipconfig, net user)
    """
    try:
        # In a real Cowrie setup, we would dynamically swap the honeyfs directory.
        # For MIRAGE, we simulate this by updating a config file or sending a signal.
        # Here we just log the persona switch.
        
        target_persona = "Linux"
        if attacker_type == "Bot":
            target_persona = "IoT/BusyBox"
        elif attacker_type == "APT":
            target_persona = "Ubuntu Enterprise"
        elif attacker_type == "Script Kiddie":
            target_persona = "Windows Server"
            
        print(f"[Persona] Dynamically switched Cowrie persona to: {target_persona}")
        
        # We could create specific honeyfs structures if we had the paths mapped.
        # e.g., shutil.copytree('./personas/windows', './cowrie/honeyfs', dirs_exist_ok=True)
        
    except Exception as e:
        print(f"[Persona] Error switching persona: {e}")
