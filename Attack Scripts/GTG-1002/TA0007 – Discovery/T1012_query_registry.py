#!/usr/bin/env python3
"""
MITRE ATT&CK T1012 - NetExec SMB Registry Query
Using netexec smb -M reg-query format for comprehensive Windows registry enumeration.

Author: HackerAI
Date: 2026-01-01
"""

import subprocess
import json
import argparse
import sys
import os
import re
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path

class NetExecSMBT1012:
    def __init__(self, target: str, username: str, password: str = None, 
                 hashes: str = None, domain: str = None):
        self.target = target
        self.username = username
        self.password = password
        self.hashes = hashes
        self.domain = domain
        self.results = {}
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # COMPLETE T1012 REGISTRY PATHS & KEYS
        self.t1012_registry = {
            # PERSISTENCE - RUN KEYS (T1547.001)
            "Run_Programs": {
                "path": "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                "key": "RegisteredOwner"
            }
        }

    def build_nxc_cmd(self, category: str) -> list:
        """Build netexec smb command for reg-query module"""
        reg_info = self.t1012_registry[category]
        
        cmd = [
            'nxc', 'smb', self.target,
            '-u', self.username
        ]
        
        if self.password:
            cmd.extend(['-p', self.password])
        elif self.hashes:
            cmd.extend(['--hashes', self.hashes])
        
        if self.domain:
            cmd.extend(['-d', self.domain])
        
        cmd.extend([
            '-M', 'reg-query',
            '-o', f"PATH='{reg_info['path']}'",
            f"KEY='{reg_info['key']}'"
        ])

        return cmd

    def parse_reg_query_output(self, output: str, category: str) -> Dict[str, Any]:
        """Parse netexec reg-query module output"""
        result = {
            'category': category,
            'path': self.t1012_registry[category]['path'],
            'key': self.t1012_registry[category]['key'],
            'values': [],
            'subkeys': [],
            'raw_output': output.strip(),
            'success': True
        }
        
        # Extract registry values
        value_pattern = r'^\s*([A-Za-z0-9_\-\.\\]+)\s+REG_([A-Z_]+)\s+(0x[0-9a-fA-F]+|\d+|".*?"|\(.*?\))\s*$'
        for line in output.split('\n'):
            match = re.match(value_pattern, line)
            if match:
                name, reg_type, data = match.groups()
                result['values'].append({
                    'name': name,
                    'type': reg_type,
                    'data': data.strip('"').strip('()')
                })
        
        # Extract subkeys (if enumerated)
        subkey_pattern = r'^\s*([A-Za-z0-9_\-\.\\]+)\\?\s*$'
        for line in output.split('\n'):
            match = re.match(subkey_pattern, line)
            if match and len(match.group(1).split('\\')) > 1:
                result['subkeys'].append(match.group(1))
        
        result['value_count'] = len(result['values'])
        result['subkey_count'] = len(result['subkeys'])
        
        return result

    def query_registry_key(self, category: str) -> bool:
        """Query single registry key using netexec smb reg-query"""
        print(f"[+] {category:<25} {self.t1012_registry[category]['key'][:60]}")
        
        cmd = self.build_nxc_cmd(category)

        print(" ".join(cmd))
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            print(result)
            
            if result.returncode == 0 and "reg-query" in result.stdout:
                parsed = self.parse_reg_query_output(result.stdout, category)
                self.results[category] = parsed
                print(f"    ✅ {parsed['value_count']} values, {parsed['subkey_count']} subkeys")
                return True
            else:
                error_msg = result.stderr or result.stdout or "Command failed"
                self.results[category] = {
                    'category': category,
                    'path': self.t1012_registry[category]['path'],
                    'key': self.t1012_registry[category]['key'],
                    'error': error_msg.strip(),
                    'success': False
                }
                print(f"    ❌ {error_msg[:60]}...")
                return False
                
        except subprocess.TimeoutExpired:
            self.results[category] = {
                'category': category,
                'path': self.t1012_registry[category]['path'],
                'key': self.t1012_registry[category]['key'],
                'error': 'Timeout (60s)',
                'success': False
            }
            print("    ❌ Timeout")
            return False
        except FileNotFoundError:
            print("❌ netexec not found. Install: pipx install netexec")
            sys.exit(1)
        except Exception as e:
            self.results[category] = {
                'category': category,
                'path': self.t1012_registry[category]['path'],
                'key': self.t1012_registry[category]['key'],
                'error': str(e),
                'success': False
            }
            print(f"    ❌ {str(e)[:50]}")
            return False

    def test_smb_access(self) -> bool:
        """Test SMB access before full scan"""
        print(f"[+] Testing SMB access to {self.target}...")
        cmd = ['netexec', 'smb', self.target, '-u', self.username]
        
        if self.password:
            cmd.extend(['-p', self.password])
        elif self.hashes:
            cmd.extend(['--hashes', self.hashes])
        if self.domain:
            cmd.extend(['-d', self.domain])
        
        cmd.extend(['--shares'])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                print("✅ SMB ACCESS CONFIRMED")
                return True
            print(f"❌ SMB ACCESS DENIED: {result.stderr[:100]}")
            return False
        except:
            print("❌ SMB connection failed")
            return False

    def run_complete_t1012_scan(self):
        """Execute ALL T1012 registry queries"""
        print("🎯 MITRE ATT&CK T1012.001 - Registry Run Keys Query")
        print(f"Target: {self.target} | User: {self.username}")
        print(f"Total Paths: {len(self.t1012_registry)}")
        print("-" * 80)
        
        if not self.test_smb_access():
            print("\n💥 Cannot proceed without SMB access")
            return
        
        print("\n🔍 ENUMERATING REGISTRY...\n")
        
        success_count = 0
        for category in self.t1012_registry:
            if self.query_registry_key(category):
                success_count += 1
        
        print("\n" + "="*80)
        print(f"✅ COMPLETE: {success_count}/{len(self.t1012_registry)} SUCCESSFUL")
        print(f"📊 {len(self.results)} total queries executed")
        self.save_comprehensive_results()

    def save_comprehensive_results(self):
        """Save detailed JSON + summary"""
        summary_stats = {
            'timestamp': self.timestamp,
            'target': self.target,
            'username': self.username,
            'domain': self.domain,
            'total_paths': len(self.t1012_registry),
            'successful': len([r for r in self.results.values() if r.get('success')]),
            'failed': len([r for r in self.results.values() if not r.get('success')]),
            'persistence_paths': len([k for k in self.results if k.startswith('HK') and 'Run' in k]),
            'discovery_paths': len(self.results) - len([k for k in self.results if k.startswith('HK') and 'Run' in k]),
            'results': self.results
        }
        
        # JSON output
        safe_target = re.sub(r'[^\w\-_.]', '_', self.target)
        json_file = f"t1012_smb_{safe_target}_{self.username}.json"
        with open(json_file, 'w') as f:
            json.dump(summary_stats, f, indent=2, default=str)
        
        # Summary TXT
        txt_file = f"t1012_smb_{safe_target}_{self.username}_summary.txt"
        with open(txt_file, 'w') as f:
            f.write(f"T1012 SMB Registry Enumeration - {self.target}\n")
            f.write("="*70 + "\n\n")
            f.write(f"Timestamp: {self.timestamp}\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"User: {self.username}\n")
            f.write(f"Domain: {self.domain or 'N/A'}\n\n")
            f.write(f"SUCCESS: {summary_stats['successful']}/{summary_stats['total_paths']}\n\n")
            
            f.write("📋 PERSISTENCE LOCATIONS:\n")
            for cat, data in self.results.items():
                if 'Run' in cat or 'Winlogon' in cat or 'Session' in cat:
                    status = "✅" if data.get('success') else "❌"
                    f.write(f"  {status} {cat:<25} [{data.get('value_count', 0)} vals]\n")
            
            f.write("\n🔍 DISCOVERY LOCATIONS:\n")
            for cat, data in self.results.items():
                if not any(x in cat for x in ['Run', 'Winlogon', 'Session']):
                    status = "✅" if data.get('success') else "❌"
                    f.write(f"  {status} {cat:<25} [{data.get('value_count', 0)} vals]\n")
        
        print(f"\n💾 RESULTS SAVED:")
        print(f"   📄 {json_file}")
        print(f"   📝 {txt_file}")

def main():
    parser = argparse.ArgumentParser(description="T1012 Registry Enumeration with netexec smb -M reg-query")
    parser.add_argument('target', help="Target IP/hostname")
    parser.add_argument('-u', '--username', required=True, help="Username")
    parser.add_argument('-p', '--password', help="Password")
    parser.add_argument('-H', '--hashes', help="NTLM hashes (lm:nt)")
    parser.add_argument('-d', '--domain', help="Domain")
    
    args = parser.parse_args()
    
    if not args.password and not args.hashes:
        print("❌ Error: Provide -p PASSWORD or -H HASHES")
        sys.exit(1)
    
    scanner = NetExecSMBT1012(
        target=args.target,
        username=args.username,
        password=args.password,
        hashes=args.hashes,
        domain=args.domain
    )
    
    scanner.run_complete_t1012_scan()

if __name__ == "__main__":
    main()