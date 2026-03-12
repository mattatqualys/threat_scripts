import os
import re
import subprocess
import sys
import time
import ast
import logging

# Clear previous logs
open('execution.log', 'w').close()

# Bold & colored print functions
def print_bold_green(text):
    print(f"\033[1;1;32m{text}\033[0m")

def print_bold_blue(text):
    print(f"\033[1;1;34m{text}\033[0m")

def print_bold_red(text):
    print(f"\033[1;1;31m{text}\033[0m")

# Setup logging
logging.basicConfig(
    filename='execution.log',
    filemode='a',
    format='%(asctime)s [%(levelname)s] %(message)s',
    level=logging.INFO
)

DEPLOYMENT_DIR = "victim_deployment"
BASE_IMAGE = "angelrita/base-ubuntu:latest"

os.makedirs(DEPLOYMENT_DIR, exist_ok=True)

def normalize_name(title):
    title = title.lower().replace(" ", "-").replace("_", "-")
    title = re.sub(r'[^a-z0-9-]', '', title)
    title = re.sub(r'-+', '-', title)
    return title.strip('-')

def parse_threat_commands(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()

    command_map = {}
    rule_title = None
    command_num = None
    command_lines = []
    image = None
    args_override = None

    for line in lines:
        line = line.rstrip()

        if line.strip().startswith("Rule_title"):
            if command_num is not None and command_lines and rule_title:
                full_command = '\n'.join(command_lines).replace('\\', '').strip()
                command_map[int(command_num)] = (rule_title, full_command, image, args_override)
                command_lines = []
                command_num = None
                image = None
                args_override = None

            rule_title = line.split("=", 1)[-1].strip()

        elif re.match(r'^\d+\.\s*command\s*=', line):
            if command_num is not None and command_lines and rule_title:
                full_command = '\n'.join(command_lines).replace('\\', '').strip()
                command_map[int(command_num)] = (rule_title, full_command, image, args_override)

            command_num = int(re.match(r'^(\d+)\.', line).group(1))
            command_lines = []
            image = None
            args_override = None

        elif "docker_image=" in line:
            image = line.split("=", 1)[-1].strip()

        elif "args:" in line:
            try:
                args_override = ast.literal_eval(line.split(":", 1)[-1].strip())
            except Exception as e:
                logging.warning(f"Failed to parse args line '{line}': {e}")
                args_override = None

        elif command_num is not None and not line.strip().startswith("#"):
            command_lines.append(line.strip())

    # Final save
    if command_num is not None and command_lines and rule_title:
        full_command = '\n'.join(command_lines).replace('\\', '').strip()
        command_map[int(command_num)] = (rule_title, full_command, image, args_override)

    return command_map

def load_specific_deployments_txt(filepath="imagespecifcthreatd.txt"):
    if not os.path.exists(filepath):
        return {}

    deployments = {}
    current_title = None
    collecting = False
    current_yaml = []

    with open(filepath, 'r') as f:
        for line in f:
            line = line.rstrip()

            if line.startswith("Rule_title="):
                if current_title and current_yaml:
                    deployments[current_title] = "\n".join(current_yaml).strip()
                current_title = line.split("=", 1)[1].strip()
                current_yaml = []
                collecting = False

            elif line.strip() == "DeploymentYAML=":
                collecting = True
                current_yaml = []

            elif collecting:
                current_yaml.append(line)

        if current_title and current_yaml:
            deployments[current_title] = "\n".join(current_yaml).strip()

    return deployments

SPECIFIC_DEPLOYMENTS = load_specific_deployments_txt()
def create_deployment_yaml(rule_title, deployment_name, custom_image=None, args_override=None):
    if rule_title in SPECIFIC_DEPLOYMENTS:
        yaml_content = SPECIFIC_DEPLOYMENTS[rule_title]
        yaml_content = re.sub(r'(name:\s*)([^\s]+)', f'\\1{deployment_name}', yaml_content, count=1)
        yaml_content = re.sub(r'(app:\s*)([^\s]+)', f'\\1{deployment_name}', yaml_content)
    else:
        image = custom_image if custom_image else BASE_IMAGE

        # Build the single command string to pass into /bin/sh -c "..."
        if args_override:
            full_command = " ".join(args_override)
            args_section = f'        - {full_command}'
        else:
            args_section = '        - while true; do sleep 30; done;'

        yaml_content = f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: {deployment_name}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: {deployment_name}
  template:
    metadata:
      labels:
        app: {deployment_name}
    spec:
      containers:
      - name: {deployment_name}
        image: {image}
        command:
          - /bin/sh
          - -c
        args:
{args_section}
        securityContext:
          runAsUser: 0
          runAsGroup: 0
          allowPrivilegeEscalation: true
          privileged: true
"""

    filepath = os.path.join(DEPLOYMENT_DIR, f"{deployment_name}.yaml")
    with open(filepath, 'w') as f:
        f.write(yaml_content)

    logging.info(f"Created deployment YAML file: {filepath}")
    logging.info(f"Using args_override: {args_override}")
    print_bold_green(f" YAML file created: {filepath}")
    return filepath

def apply_deployment(yaml_file):
    logging.info(f"Applying deployment YAML: {yaml_file}")
    print_bold_green(f" Deploying pod from YAML: {yaml_file}")
    result = subprocess.run(['kubectl', 'apply', '-f', yaml_file], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Error applying deployment: {result.stderr.strip()}")
    logging.info(result.stdout.strip())

def wait_for_pod(deployment_name, timeout=60):
    logging.info(f"Waiting for pod from deployment '{deployment_name}' to be running...")
    print_bold_blue(f" Waiting for pod to become Running: {deployment_name}")
    for _ in range(timeout):
        result = subprocess.run(
            ['kubectl', 'get', 'pods', '-l', f'app={deployment_name}', '-o', 'jsonpath={.items[0].status.phase}'],
            capture_output=True, text=True
        )
        if result.stdout.strip() == "Running":
            get_name = subprocess.run(
                ['kubectl', 'get', 'pods', '-l', f'app={deployment_name}', '-o', 'jsonpath={.items[0].metadata.name}'],
                capture_output=True, text=True
            )
            return get_name.stdout.strip()
        time.sleep(2)
    raise TimeoutError(f"Timed out waiting for pod from deployment {deployment_name}")

def execute_command_in_pod(pod_name, command):
    logging.info(f"========== Executing Commands in Pod: {pod_name} ==========")
    print_bold_blue(f"Executing command in pod {pod_name}...")

    command_lines = [
        line.strip()
        for line in command.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

    for line in command_lines:
        logging.info(f"→ Running: {line}")
        print_bold_blue(f"→ Executing: {line}")
        try:
            result = subprocess.run(
                ['kubectl', 'exec', pod_name, '--', 'sh', '-c', line],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                logging.error(f"[ERROR] Command failed in pod {pod_name}: {line}\n{result.stderr.strip()}")
                print_bold_red(f"[ERROR] {line}:\n{result.stderr.strip()}")
            else:
                logging.info(f"[OUTPUT] {line}:\n{result.stdout.strip()}")
                print_bold_green(f"[OUTPUT] {line}:\n{result.stdout.strip()}")
        except Exception as e:
            logging.exception(f"[EXCEPTION] while executing '{line}' in pod {pod_name}: {e}")
            print_bold_red(f"[EXCEPTION] {line}: {str(e)}")

        time.sleep(1)

    logging.info(f"========== Finished Executing Commands in Pod: {pod_name} ==========")

def main():
    command_map = parse_threat_commands('threatcommand.txt')

    if len(sys.argv) == 1:
        numbers = sorted(command_map.keys())
    elif len(sys.argv) == 2:
        try:
            start = int(sys.argv[1])
            end = start
        except ValueError:
            print_bold_red("Error: command numbers must be integers.")
            sys.exit(1)
        numbers = range(start, end + 1)
    elif len(sys.argv) == 3:
        try:
            start = int(sys.argv[1])
            end = int(sys.argv[2])
        except ValueError:
            print_bold_red("Error: command numbers must be integers.")
            sys.exit(1)
        numbers = range(start, end + 1)
    else:
        print_bold_red("Usage: python3 threatdetectiontest.py [<start> [<end>]]")
        sys.exit(1)

    print_bold_green("===== Starting Threat Command Execution =====")
    for number in numbers:
        if number not in command_map:
            logging.warning(f"Command {number} not found.")
            print_bold_red(f"Skipping missing command #{number}")
            continue

        rule_title, command, image, args_override = command_map[number]
        deployment_name = normalize_name(rule_title)
        yaml_path = create_deployment_yaml(rule_title, deployment_name, image, args_override)

        logging.info(f"\n--- Processing command #{number}: {rule_title} ---")
        print_bold_blue(f"--- Processing command #{number}: {rule_title} ---")

        try:
            apply_deployment(yaml_path)  # Deploy pod based on the correct YAML
            pod_name = wait_for_pod(deployment_name)  # Wait for the specific pod of the current command
            execute_command_in_pod(pod_name, command)  # Execute the command in the correct pod
            print_bold_green(f"✔️ Finished command #{number}")
        except Exception as e:
            logging.error(f"Failed for command {number}: {e}")
            print_bold_red(f"❌ Failed command #{number}: {e}")

    print_bold_green("===== Completed All Commands =====")

if __name__ == "__main__":
    main()
