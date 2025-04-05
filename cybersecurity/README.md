**🚀 Instant Linux Forensics Triage – Powered by ChatGPT-4o**

This lightweight Bash script, crafted with the help of ChatGPT-4o, is your go-to tool for rapid forensics triage on potentially compromised Linux systems.

**🛡️ What It Does:**

The script runs a comprehensive set of checks and gathers key indicators of compromise, then compiles everything into a detailed, easy-to-read report.

**⚡ How to Use:**

Just download the script, navigate to its directory, and run:

$ chmod u+x linux_forensics_triage_v1.sh && sudo ./linux_forensics_triage_v1.sh

No dependencies. No fuss. Just fast, actionable insights. Perfect for incident response, DFIR, or peace of mind. The script runs the following checks for you:

- collect_system_info
- collect_installed_packages
- collect_users_and_groups
- collect_login_history
- collect_process_info
- collect_network_info
- collect_autoruns
- collect_file_integrity
- collect_recent_changes
- collect_hidden_world_writable_files
- collect_unusual_binary_paths
- collect_kernel_modules
- collect_suid_sgid_files
- collect_bash_history
- collect_persistence_mechanisms
- collect_open_files
- collect_ssh_keys_and_hosts
- run_rootkit_scanner
