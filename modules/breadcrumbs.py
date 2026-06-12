import os

def plant():
    """
    plant() -> creates fake files in Cowrie honeyfs:
    /home/admin/.ssh/id_rsa (fake private key)
    /etc/passwd (fake users: admin, root, dev, jenkins)
    /var/www/html/config.php (fake DB: mysql://admin:P@ssw0rd)
    /home/admin/.bash_history (fake command history)
    /opt/app/.env (fake AWS keys + JWT secrets)
    """
    honeyfs_dir = "./cowrie/honeyfs"
    
    files = {
        "/home/admin/.ssh/id_rsa": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...fake...key...\n-----END RSA PRIVATE KEY-----",
        "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:admin:/home/admin:/bin/bash\ndev:x:1001:1001:dev:/home/dev:/bin/bash\njenkins:x:1002:1002:jenkins:/var/lib/jenkins:/bin/bash",
        "/var/www/html/config.php": "<?php\n$db_host = 'localhost';\n$db_user = 'admin';\n$db_pass = 'P@ssw0rd';\n$db_name = 'mirage_prod';\n?>",
        "/home/admin/.bash_history": "ls -la\ncd /var/www/html\nnano config.php\nsudo systemctl restart apache2\nexit",
        "/opt/app/.env": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nJWT_SECRET=super_secret_jwt_key_123!"
    }
    
    try:
        for path, content in files.items():
            # Strip leading slash to make it relative to honeyfs
            rel_path = path.lstrip('/')
            full_path = os.path.join(honeyfs_dir, rel_path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, 'w') as f:
                f.write(content)
        print("[Breadcrumbs] Successfully planted fake files in honeyfs.")
    except Exception as e:
        print(f"[Breadcrumbs] Error planting files: {e}")
