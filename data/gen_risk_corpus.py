"""SafeShell Phase 3 - Synthetic Risk Corpus Generator.

Generates a dataset of synthetic shell commands, featurizes them, and labels them
via the deterministic rules engine.
"""

import random
import csv
import os

from safeshell.parser import parse_command
from safeshell.classifier import featurize, rules_tier, FAMILY_TABLE
from safeshell.schemas import RiskLevel

random.seed(1337)

SAFE_PATHS = [
    './build', './tmp', '~/project', '/tmp/test', 'file.txt', 'dir/', 'a', 'b', 'f'
]
CRITICAL_PATHS = [
    '/', '/etc', '/var', '/boot', '/dev', '/usr', '~', '/*', '/etc/hosts', '/dev/sda'
]
FLAGS = ['-r', '-f', '-R', '--recursive', '']
SYSTEMCTL_VERBS = ['start', 'stop', 'restart', 'enable', 'disable', 'status']

def generate_command():
    # 10% sudo
    use_sudo = random.random() < 0.1
    # 10% compound
    use_compound = random.random() < 0.1
    # 5% pipe to shell
    use_pipe_shell = random.random() < 0.05
    # 8% redirect
    use_redirect = random.random() < 0.08
    
    cmd_parts = []
    if use_sudo:
        cmd_parts.append('sudo')
        
    executable = random.choice(FAMILY_TABLE)
    cmd_parts.append(executable)
    
    # Flags
    flag = random.choice(FLAGS)
    if flag:
        cmd_parts.append(flag)
        
    # Arguments / paths
    if executable == 'systemctl':
        cmd_parts.append(random.choice(SYSTEMCTL_VERBS))
        cmd_parts.append('nginx')
    elif executable == 'dd':
        if random.random() < 0.5:
            cmd_parts.append('if=/dev/zero')
            cmd_parts.append('of=/dev/sda')
        else:
            cmd_parts.append('if=input.img')
            cmd_parts.append('of=output.img')
    elif executable in ('curl', 'wget'):
        cmd_parts.append('http://example.com/script.sh')
    else:
        # standard paths
        num_paths = random.randint(1, 2)
        for _ in range(num_paths):
            path_pool = CRITICAL_PATHS if random.random() < 0.2 else SAFE_PATHS
            path = random.choice(path_pool)
            if random.random() < 0.1: # wildcard
                path += '*'
            cmd_parts.append(path)
            
    cmd_str = " ".join(cmd_parts)
    
    if use_redirect:
        if random.random() < 0.2:
            cmd_str += " > /dev/sda"
        else:
            cmd_str += " > out.log"
            
    if use_pipe_shell:
        cmd_str += " | bash"
    elif random.random() < 0.1:
        cmd_str += " | grep foo"
        
    if use_compound:
        cmd_str += " && echo done"
        
    # Inject some explicit critical rules like fork bomb occasionally
    if random.random() < 0.01:
        cmd_str = ":(){ :|:& };:"
        
    return cmd_str

def main():
    print("Generating corpus...")
    num_samples = 5500
    
    header = [
        'recursive', 'force', 'wildcards', 'pipe_to_shell', 'redirect_write', 'priv_esc',
        'path_etc', 'path_boot', 'path_dev', 'path_var', 'path_usr', 'directory_target',
        'compound_ops', 'unknown_effects', 'deletes_count', 'creates_count', 'modifies_count',
        'permissions_count', 'service_count', 'network_count', 'target_file_count', 'exec_family_id',
        'label', 'labeled_critical'
    ]
    
    output_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'synthetic_risk_corpus.csv')
    
    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        
        for _ in range(num_samples):
            cmd = generate_command()
            parsed = parse_command(cmd)
            features = featurize(parsed, cmd)
            
            r_tier, _ = rules_tier(parsed, cmd)
            label = r_tier.value
            labeled_critical = str(r_tier == RiskLevel.critical)
            
            row = features + [label, labeled_critical]
            writer.writerow(row)
            
    print(f"Corpus generated at {output_path}")

if __name__ == "__main__":
    main()
