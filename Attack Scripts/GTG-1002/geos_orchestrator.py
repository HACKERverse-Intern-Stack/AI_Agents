#!/usr/bin/env python3
"""
GTG-1002 Attack Campaign Orchestrator
Orchestrates a realistic attack chain against target infrastructure
"""

import subprocess
import json
import sys
import os
from datetime import datetime
from pathlib import Path

class AttackOrchestrator:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.results = {
            "campaign": "GTG-1002",
            "target": target_ip,
            "timestamp": datetime.now().isoformat(),
            "attacks": []
        }
        
    def run_script(self, script_path, phase, description):
        """Execute a script and capture results"""
        print(f"\n{'='*60}")
        print(f"[{phase}] Executing: {description}")
        print(f"Script: {script_path}")
        print(f"{'='*60}")
        
        # Check if file exists
        if not os.path.exists(script_path):
            print(f"\n✗ ERROR - Script not found: {script_path}")
            self.results["attacks"].append({
                "phase": phase,
                "script": script_path,
                "description": description,
                "success": False,
                "error": "Script file not found",
                "timestamp": datetime.now().isoformat()
            })
            return False, "File not found"
        
        try:
            # Run the script with target IP as argument
            result = subprocess.run(
                [sys.executable, script_path, self.target_ip],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout per script
            )
            
            success = result.returncode == 0
            output = result.stdout if result.stdout else result.stderr
            
            attack_result = {
                "phase": phase,
                "script": script_path,
                "description": description,
                "success": success,
                "return_code": result.returncode,
                "output": output.strip(),
                "timestamp": datetime.now().isoformat()
            }
            
            self.results["attacks"].append(attack_result)
            
            status = "✓ SUCCESS" if success else "✗ FAILED"
            print(f"\nStatus: {status}")
            print(f"Output: {output[:500]}...")  # Print first 500 chars
            
            return success, output
            
        except subprocess.TimeoutExpired:
            print(f"\n✗ TIMEOUT - Script exceeded 5 minute limit")
            self.results["attacks"].append({
                "phase": phase,
                "script": script_path,
                "description": description,
                "success": False,
                "error": "Timeout exceeded",
                "timestamp": datetime.now().isoformat()
            })
            return False, "Timeout"
            
        except Exception as e:
            print(f"\n✗ ERROR - {str(e)}")
            self.results["attacks"].append({
                "phase": phase,
                "script": script_path,
                "description": description,
                "success": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            })
            return False, str(e)
    
    def execute_campaign(self):
        """Execute the full attack campaign in realistic order"""
        
        print(f"\n{'#'*60}")
        print(f"# GTG-1002 ATTACK CAMPAIGN ORCHESTRATOR")
        print(f"# Target: {self.target_ip}")
        print(f"# Start Time: {self.results['timestamp']}")
        print(f"{'#'*60}")
        
        # PHASE 1: RECONNAISSANCE
        print("\n\n*** PHASE 1: RECONNAISSANCE ***")
        self.run_script("TA0007 - Discovery/T0842_lnk_creation.py", "Reconnaissance", "Link file creation for reconnaissance")
        self.run_script("TA0007 - Discovery/T1012_query_registry.py", "Reconnaissance", "Query system registry")
        self.run_script("TA0007 - Discovery/T1046_network_service_scanning.py", "Reconnaissance", "Network service scanning")
        self.run_script("TA0007 - Discovery/T1082_system_info_discovery.py", "Reconnaissance", "System information discovery")
        self.run_script("TA0007 - Discovery/T1087_account_discovery.py", "Reconnaissance", "Account discovery")
        self.run_script("TA0043 - Reconnaissance/T1590_gather_host_info.py", "Reconnaissance", "Gather victim host information")
        self.run_script("TA0043 - Reconnaissance/T1593_search_open_websites.py", "Reconnaissance", "Search open websites/domains")
        self.run_script("TA0043 - Reconnaissance/T1595_active_scanning.py", "Reconnaissance", "Active scanning")
        
        # PHASE 2: INITIAL ACCESS
        print("\n\n*** PHASE 2: INITIAL ACCESS ***")
        success, _ = self.run_script("TA0001 - Initial Access/T1190_exploit_public_app.py", "Initial Access", "Exploit public-facing application")
        
        if not success:
            print("\n[!] Initial access failed. Attempting alternative methods...")
            self.run_script("TA0001 - Initial Access/T1078_valid_accounts.py", "Initial Access", "Valid accounts access")
        
        # PHASE 3: EXECUTION
        print("\n\n*** PHASE 3: EXECUTION ***")
        self.run_script("TA0002 - Execution/T1059_command_interpreter.py", "Execution", "Command interpreter execution")
        self.run_script("TA0002 - Execution/T1105_ingress_tool_transfer.py", "Execution", "Ingress tool transfer")
        self.run_script("TA0002 - Execution/T1204_user_execution.py", "Execution", "User execution")
        
        # PHASE 4: PERSISTENCE
        print("\n\n*** PHASE 4: PERSISTENCE ***")
        self.run_script("TA0003 - Persistence/T1078_valid_accounts.py", "Persistence", "Maintain valid accounts")
        self.run_script("TA0003 - Persistence/T1505_install_service.py", "Persistence", "Install persistent service")
        
        # PHASE 5: PRIVILEGE ESCALATION
        print("\n\n*** PHASE 5: PRIVILEGE ESCALATION ***")
        self.run_script("TA0004 - Privilege Escalation/T1068_privilege_escalation.py", "Privilege Escalation", "Exploit for privilege escalation")
        self.run_script("TA0004 - Privilege Escalation/T1078_004_cloud_accounts.py", "Privilege Escalation", "Cloud accounts privilege escalation")
        
        # PHASE 6: DEFENSE EVASION
        print("\n\n*** PHASE 6: DEFENSE EVASION ***")
        self.run_script("TA0005 - Defense Evasion/T1027_obfuscation.py", "Defense Evasion", "Obfuscate files/information")
        self.run_script("TA0005 - Defense Evasion/T1036_masquerading.py", "Defense Evasion", "Masquerading")
        self.run_script("TA0005 - Defense Evasion/T1078_valid_accounts.py", "Defense Evasion", "Valid accounts for evasion")
        
        # PHASE 7: CREDENTIAL ACCESS
        print("\n\n*** PHASE 7: CREDENTIAL ACCESS ***")
        self.run_script("TA0006 - Credential Access/T1003_credential_dumping.py", "Credential Access", "Credential dumping")
        self.run_script("TA0006 - Credential Access/T1110_brute_force.py", "Credential Access", "Brute force authentication")
        
        # PHASE 8: LATERAL MOVEMENT
        print("\n\n*** PHASE 8: LATERAL MOVEMENT ***")
        self.run_script("TA0008 - Lateral Movement/T1021_rdp_login.py", "Lateral Movement", "Remote desktop protocol")
        self.run_script("TA0008 - Lateral Movement/T1078_valid_accounts.py", "Lateral Movement", "Valid accounts for lateral movement")
        
        # PHASE 9: COLLECTION
        print("\n\n*** PHASE 9: COLLECTION ***")
        self.run_script("TA0009 - Collection/T1039_steal_from_share.py", "Collection", "Data from network shared drive")
        self.run_script("TA0009 - Collection/T1114_email_collection.py", "Collection", "Email collection")
        self.run_script("TA0009 - Collection/T1119_automated_collection.py", "Collection", "Automated collection")
        self.run_script("TA0009 - Collection/T1203_dll_hijack.py", "Collection", "DLL hijacking for collection")
        
        # PHASE 10: COMMAND AND CONTROL
        print("\n\n*** PHASE 10: COMMAND AND CONTROL ***")
        self.run_script("TA0011 - Command and Control/C2_server.py", "Command and Control", "C2 server setup")
        self.run_script("TA0010 - Exfiltration/T1041_exfiltrate_via_http.py", "Command and Control", "Exfiltration over HTTP")
        self.run_script("TA0011 - Command and Control/T1071_dns_c2_exfiltrate.py", "Command and Control", "Application layer protocol (DNS)")
        self.run_script("TA0011 - Command and Control/T1071.001_http_c2_connection.py", "Command and Control", "HTTP C2 connection")
        self.run_script("TA0011 - Command and Control/T1090_proxy_handler.py", "Command and Control", "Proxy handler")
        self.run_script("TA0010 - Exfiltration/T1537_exfil_cloud.py", "Command and Control", "Cloud infrastructure exfil")
        self.run_script("TA0010 - Exfiltration/T1567_exfil_http.py", "Command and Control", "Exfiltration over web service")
        self.run_script("TA0011 - Command and Control/dns_receiver.py", "Command and Control", "DNS receiver")
        
        # PHASE 11: EXFILTRATION
        print("\n\n*** PHASE 11: EXFILTRATION ***")
        self.run_script("TA0010 - Exfiltration/upload_reciever.py", "Exfiltration", "Upload receiver")
        
        # Save results
        self.save_results()
        self.print_summary()
        
    def save_results(self):
        """Save results to JSON file"""
        output_file = f"gtg1002_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n\n{'='*60}")
        print(f"Results saved to: {output_file}")
        print(f"{'='*60}")
    
    def print_summary(self):
        """Print campaign summary"""
        total = len(self.results["attacks"])
        successful = sum(1 for a in self.results["attacks"] if a.get("success", False))
        failed = total - successful
        
        print(f"\n\n{'#'*60}")
        print(f"# CAMPAIGN SUMMARY")
        print(f"{'#'*60}")
        print(f"Total Attacks: {total}")
        print(f"Successful: {successful} ({successful/total*100:.1f}%)")
        print(f"Failed: {failed} ({failed/total*100:.1f}%)")
        print(f"\nPhase Breakdown:")
        
        phases = {}
        for attack in self.results["attacks"]:
            phase = attack.get("phase", "Unknown")
            if phase not in phases:
                phases[phase] = {"total": 0, "success": 0}
            phases[phase]["total"] += 1
            if attack.get("success", False):
                phases[phase]["success"] += 1
        
        for phase, stats in phases.items():
            success_rate = stats["success"]/stats["total"]*100 if stats["total"] > 0 else 0
            print(f"  {phase}: {stats['success']}/{stats['total']} ({success_rate:.1f}%)")
        
        print(f"{'#'*60}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python orchestrator.py <target_ip>")
        print("Example: python orchestrator.py 10.0.1.244")
        sys.exit(1)
    
    target = sys.argv[1] if len(sys.argv) > 1 else "10.0.1.244"
    
    orchestrator = AttackOrchestrator(target)
    orchestrator.execute_campaign()