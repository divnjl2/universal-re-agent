"""
SSH helper for remote command execution via paramiko.
Avoids SSH agent issues on Windows.
"""
import paramiko
import os
import sys
import time

HOST = "144.31.164.254"
USER = "Administrator"
PASS = "rR1fX1wN0kgS"


def get_client():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(HOST, username=USER, password=PASS, timeout=15,
                allow_agent=False, look_for_keys=False)
    return ssh


def run(cmd, timeout=120):
    """Execute command and return stdout."""
    ssh = get_client()
    try:
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode('utf-8', errors='replace')
        err = stderr.read().decode('utf-8', errors='replace')
        code = stdout.channel.recv_exit_status()
        return out, err, code
    finally:
        ssh.close()


def upload(local_path, remote_path):
    """Upload file via SFTP."""
    ssh = get_client()
    try:
        sftp = ssh.open_sftp()
        sftp.put(local_path, remote_path)
        sftp.close()
    finally:
        ssh.close()


def download(remote_path, local_path):
    """Download file via SFTP."""
    ssh = get_client()
    try:
        sftp = ssh.open_sftp()
        sftp.get(remote_path, local_path)
        sftp.close()
    finally:
        ssh.close()


def upload_dir(local_dir, remote_dir):
    """Upload directory recursively via SFTP."""
    ssh = get_client()
    try:
        sftp = ssh.open_sftp()
        for root, dirs, files in os.walk(local_dir):
            rel = os.path.relpath(root, local_dir)
            remote_sub = remote_dir + "/" + rel.replace("\\", "/") if rel != "." else remote_dir
            try:
                sftp.mkdir(remote_sub)
            except IOError:
                pass
            for f in files:
                local_file = os.path.join(root, f)
                remote_file = remote_sub + "/" + f
                sftp.put(local_file, remote_file)
        sftp.close()
    finally:
        ssh.close()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        cmd = " ".join(sys.argv[1:])
        out, err, code = run(cmd)
        print(out)
        if err:
            print("STDERR:", err, file=sys.stderr)
        sys.exit(code)
    else:
        out, err, code = run("whoami && hostname && python --version 2>&1")
        print(out)
