#!/usr/bin/env python3
import os
os.environ["RUN_LLM"] = "1"
import sys
import subprocess

def main():
    print("========================================")
    print(" 🛡️  SafeShell Interactive REPL")
    print(" Type 'exit' or 'quit' to leave.")
    print("========================================")
    
    while True:
        try:
            cwd = os.getcwd()
            # Try to get the prompt to look like a normal shell
            prompt = f"\033[1;36msafeshell\033[0m:\033[1;34m{cwd}\033[0m$ "
            cmd = input(prompt).strip()
            
            if not cmd:
                continue
                
            if cmd in ('exit', 'quit'):
                break
                
            # Handle 'cd' internally so the REPL process changes directory
            if cmd.startswith('cd '):
                target = cmd[3:].strip()
                if target == '~':
                    target = os.path.expanduser('~')
                try:
                    os.chdir(target)
                except Exception as e:
                    print(f"cd: {e}")
                continue
                
            # Clear screen helper
            if cmd == 'clear':
                os.system('clear')
                continue
                

            # Pass-through read-only or harmless shell commands
            read_only_cmds = ('ls', 'll', 'la', 'pwd', 'echo', 'cat', 'grep', 'find', 'tail', 'head', 'less', 'more', 'whoami', 'history')
            base_cmd = cmd.split()[0]
            if base_cmd in read_only_cmds:
                os.system(cmd)
                continue
                
            # Pass everything else to safeshell run

            # We use subprocess to run the CLI directly
            subprocess.run([sys.executable, "-m", "safeshell", "run", cmd])
            
        except (KeyboardInterrupt, EOFError):
            print("")
            break

if __name__ == '__main__':
    main()
