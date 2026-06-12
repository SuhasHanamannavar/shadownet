import os
import shutil
import docker
import config

sandbox_dir = "./sandbox"
os.makedirs(sandbox_dir, exist_ok=True)

try:
    docker_client = docker.from_env()
except Exception:
    docker_client = None

def capture(file_path):
    """
    capture(file_path) -> copies file to ./sandbox/
    """
    try:
        if os.path.exists(file_path):
            filename = os.path.basename(file_path)
            dest = os.path.join(sandbox_dir, filename)
            shutil.copy2(file_path, dest)
            return dest
    except Exception as e:
        print(f"[Sandbox] Capture error: {e}")
    return None

def detonate(file_path):
    """
    detonate(file_path) -> runs file in Docker container:
    docker run --rm --network none ubuntu:22.04
    Returns stdout/stderr output safely
    """
    if not docker_client:
        return "[Sandbox] Docker daemon not available."
        
    try:
        if not os.path.exists(file_path):
            return "[Sandbox] File not found."
            
        filename = os.path.basename(file_path)
        dest = os.path.join(sandbox_dir, filename)
        if not os.path.exists(dest):
            dest = capture(file_path)
            
        # We mount the sandbox dir into the container and execute it
        abs_sandbox = os.path.abspath(sandbox_dir)
        container_cmd = f"chmod +x /sandbox/{filename} && /sandbox/{filename}"
        
        container = docker_client.containers.run(
            config.DOCKER_SANDBOX_IMAGE,
            command=["sh", "-c", container_cmd],
            volumes={abs_sandbox: {'bind': '/sandbox', 'mode': 'ro'}},
            network_mode='none',
            remove=True,
            detach=False,
            stdout=True,
            stderr=True,
            mem_limit="100m",
            cpu_quota=50000,
            # We cannot do an internal timeout easily with docker-py run in blocking mode 
            # without detaching, but we can wrap it or just rely on a command timeout.
            # For MIRAGE we use `timeout 10` inside the container:
            entrypoint=["timeout", "10s"]
        )
        
        return container.decode('utf-8')
    except docker.errors.ContainerError as e:
        return f"[Sandbox] Execution error/timeout: {e.stderr.decode('utf-8') if e.stderr else 'unknown'}"
    except Exception as e:
        return f"[Sandbox] Detonate error: {e}"
