#!/bin/bash
#
# Kali VM Preparation Script - Local Execution
# This script runs ON each Kali VM to prepare it for competition
#
# Usage (run on each Kali VM after SSH'ing in):
#   bash <(curl -sL https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/kali-prep.sh)
#
# What it does:
#   1. Creates new user with admin privileges
#   2. Sets up SSH key for new user
#   3. Clears all system logs
#

set -e

# ============================================
# CONFIGURATION - EDIT THESE VALUES
# ============================================

# New user configuration
NEW_USER="ansibled"
NEW_PASSWORD="WinningCDT!"

# Root password
ROOT_PASSWORD="WinningCDT1!"

# SSH Public Key (will be installed for root, redteam, and ansibled)
# Get this from: cat ~/.ssh/id_rsa.pub
# Or generate new key: ssh-keygen -t rsa -b 4096 -C "competition@kali"
SSH_PUBLIC_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC6ro2EmU1T+DALRPur0HBsCkaWb0EnwRpTUoiNaAyD/2ts96umhnonvuYHWGBHwGBi/7yZwcNMCweMhKZmHI2mg0ecq4AaBEP0arHcNL3tx1ptT01TuK/s86ODgcGjfg8Rrz4t9uZzK22RaD5pnYasEjNQSQwjU/6dLPFIJswfew7gtF+2LYOGrwNea1WTOjOGiWtfVDPxN4ClnUZ2kRPT1bLfeJXUSCi1fD1AQwe5hPL2Z/S4vxoznmk6Ttrq40N7lpJSZIgLhekDN0LEct/JtxcvNee6k6fOqbtQwgmLl0lO5JzRpTs/XUQ2Fcr/evdkq/7KCOqWWzlvkMp7/pzP+FOK2BcDSSOcql5hcCqxwmmIQQeStouTE2zQwz1WY884v2aowaPY0f1MAjregzTaGY5e4A2kK7IWzQk64VQCBR/XkWPhZKQmhbmtLD1hZ0Awclbgrf9UOLLEAEk28LRVMN9rL0ZDzvhLi60Jv4+qNZR+PW4tFNilxqGHcsfLlXVgvGjgCVKEjmeMfH6wOxAmlaa3XSF17M7WhCoZsGkA4xa6JniZH8V+eJXPursIQKS2ajyKDu97cKUcsN2yTfmGmIUWhXES3TDyYCNds/YENyr51SXe62z6NTUrysgGC4nAiNZCUBVk0Z94NzR9MJaAPpc5JTMfgfNbS/s9nVkQqw== kali@kali"

# Set to "true" to install SSH key, "false" to skip
INSTALL_SSH_KEY="true"

# Get current user and password (will use sudo)
CURRENT_USER=$(whoami)

# ============================================
# COLOR CODES
# ============================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ============================================
# FUNCTIONS
# ============================================

print_banner() {
    echo -e "${CYAN}"
    echo "=========================================="
    echo "   Kali VM Preparation Script"
    echo "   Running on: $(hostname)"
    echo "   IP Address: $(hostname -I | awk '{print $1}')"
    echo "=========================================="
    echo -e "${NC}"
}

run_sudo() {
    sudo "$@" 2>/dev/null || sudo -S "$@" 2>/dev/null
}

# ============================================
# MAIN EXECUTION
# ============================================

main() {
    print_banner
    
    echo -e "${CYAN}=== Starting VM Preparation ===${NC}\n"
    
    # Check if running as root or with sudo capability
    if [ "$CURRENT_USER" != "root" ] && ! sudo -n true 2>/dev/null; then
        echo -e "${YELLOW}This script requires sudo access.${NC}"
        echo -e "${YELLOW}You may be prompted for your password.${NC}\n"
    fi
    
    # ============================================
    # CREATE USER
    # ============================================
    
    echo -e "${CYAN}[1/4]${NC} Creating user ${NEW_USER}..."
    
    if id "$NEW_USER" &>/dev/null; then
        echo -e "${YELLOW}User $NEW_USER already exists, updating password...${NC}"
        echo "$NEW_USER:$NEW_PASSWORD" | run_sudo chpasswd
    else
        # Try different user creation methods
        if run_sudo useradd -m -s /bin/bash "$NEW_USER" 2>/dev/null; then
            echo "$NEW_USER:$NEW_PASSWORD" | run_sudo chpasswd
        elif run_sudo adduser --disabled-password --gecos "" "$NEW_USER" 2>/dev/null; then
            echo "$NEW_USER:$NEW_PASSWORD" | run_sudo chpasswd
        else
            echo -e "${RED}Failed to create user${NC}"
            exit 1
        fi
        echo -e "${GREEN}✓ User created${NC}"
    fi
    
    # ============================================
    # GRANT SUDO PRIVILEGES
    # ============================================
    
    echo -e "\n${CYAN}[2/4]${NC} Granting admin privileges..."
    
    # Add to sudo group
    run_sudo usermod -aG sudo "$NEW_USER" 2>/dev/null || run_sudo usermod -aG wheel "$NEW_USER" 2>/dev/null || true
    
    # Create sudoers file
    echo "$NEW_USER ALL=(ALL) NOPASSWD:ALL" | run_sudo tee "/etc/sudoers.d/$NEW_USER" > /dev/null
    run_sudo chmod 0440 "/etc/sudoers.d/$NEW_USER"
    
    echo -e "${GREEN}✓ Admin privileges granted (sudo NOPASSWD)${NC}"
    
    # ============================================
    # CHANGE ROOT PASSWORD
    # ============================================
    
    echo -e "\n${CYAN}[3/6]${NC} Setting root password..."
    
    echo "root:$ROOT_PASSWORD" | run_sudo chpasswd
    echo -e "${GREEN}✓ Root password set${NC}"
    
    # ============================================
    # ENABLE ROOT SSH WITH PASSWORD
    # ============================================
    
    echo -e "\n${CYAN}[4/6]${NC} Enabling root SSH access..."
    
    # Backup sshd_config
    run_sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak 2>/dev/null || true
    
    # Enable root login with password
    run_sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
    run_sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
    
    # Restart SSH service
    run_sudo systemctl restart sshd 2>/dev/null || run_sudo systemctl restart ssh 2>/dev/null || run_sudo service ssh restart 2>/dev/null || true
    
    echo -e "${GREEN}✓ Root SSH access enabled${NC}"
    
    # ============================================
    # SETUP SSH KEYS
    # ============================================
    
    if [ "$INSTALL_SSH_KEY" = "true" ] && [ -n "$SSH_PUBLIC_KEY" ] && [ "$SSH_PUBLIC_KEY" != "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC... your-public-key-here competition@kali" ]; then
        echo -e "\n${CYAN}[5/6]${NC} Installing SSH keys..."
        
        # Install SSH key for ansibled user
        run_sudo mkdir -p "/home/$NEW_USER/.ssh"
        run_sudo chmod 700 "/home/$NEW_USER/.ssh"
        echo "$SSH_PUBLIC_KEY" | run_sudo tee "/home/$NEW_USER/.ssh/authorized_keys" > /dev/null
        run_sudo chmod 600 "/home/$NEW_USER/.ssh/authorized_keys"
        run_sudo chown -R "$NEW_USER:$NEW_USER" "/home/$NEW_USER/.ssh"
        echo -e "${GREEN}  ✓ SSH key installed for $NEW_USER${NC}"
        
        # Install SSH key for root
        run_sudo mkdir -p /root/.ssh
        run_sudo chmod 700 /root/.ssh
        echo "$SSH_PUBLIC_KEY" | run_sudo tee /root/.ssh/authorized_keys > /dev/null
        run_sudo chmod 600 /root/.ssh/authorized_keys
        echo -e "${GREEN}  ✓ SSH key installed for root${NC}"
        
        # Install SSH key for redteam user (if exists)
        if id "redteam" &>/dev/null; then
            run_sudo mkdir -p /home/redteam/.ssh
            run_sudo chmod 700 /home/redteam/.ssh
            echo "$SSH_PUBLIC_KEY" | run_sudo tee /home/redteam/.ssh/authorized_keys > /dev/null
            run_sudo chmod 600 /home/redteam/.ssh/authorized_keys
            run_sudo chown -R redteam:redteam /home/redteam/.ssh
            echo -e "${GREEN}  ✓ SSH key installed for redteam${NC}"
        fi
        
        echo -e "${GREEN}✓ SSH keys installed${NC}"
    else
        echo -e "\n${CYAN}[5/6]${NC} ${YELLOW}Skipping SSH key setup${NC}"
        if [ "$INSTALL_SSH_KEY" = "true" ]; then
            echo -e "${YELLOW}   (No valid SSH key provided in script)${NC}"
        fi
    fi
    
    # ============================================
    # CLEAR LOGS
    # ============================================
    
    echo -e "\n${CYAN}[6/6]${NC} Clearing system logs..."
    
    # Clear authentication logs
    run_sudo truncate -s 0 /var/log/auth.log* 2>/dev/null || true
    run_sudo truncate -s 0 /var/log/secure* 2>/dev/null || true
    
    # Clear system logs
    run_sudo truncate -s 0 /var/log/syslog* 2>/dev/null || true
    run_sudo truncate -s 0 /var/log/messages* 2>/dev/null || true
    
    # Clear login logs
    run_sudo truncate -s 0 /var/log/wtmp 2>/dev/null || true
    run_sudo truncate -s 0 /var/log/btmp 2>/dev/null || true
    run_sudo truncate -s 0 /var/log/lastlog 2>/dev/null || true
    
    # Clear other logs
    run_sudo truncate -s 0 /var/log/kern.log* 2>/dev/null || true
    run_sudo truncate -s 0 /var/log/daemon.log* 2>/dev/null || true
    run_sudo truncate -s 0 /var/log/user.log* 2>/dev/null || true
    run_sudo truncate -s 0 /var/log/audit/audit.log 2>/dev/null || true
    run_sudo truncate -s 0 /var/log/cloud-init*.log 2>/dev/null || true
    
    # Clear bash history for all users
    run_sudo find /home -name ".bash_history" -exec truncate -s 0 {} \; 2>/dev/null || true
    run_sudo find /root -name ".bash_history" -exec truncate -s 0 {} \; 2>/dev/null || true
    
    # Clear systemd journal
    run_sudo journalctl --vacuum-time=1s 2>/dev/null || true
    
    # Clear current session history
    history -c 2>/dev/null || true
    
    echo -e "${GREEN}✓ Logs cleared${NC}"
    
    # ============================================
    # SUMMARY
    # ============================================
    
    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}   VM Preparation Complete!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo -e "\nHost: ${CYAN}$(hostname)${NC}"
    echo -e "IP: ${CYAN}$(hostname -I | awk '{print $1}')${NC}"
    echo -e "\n${CYAN}New User Credentials:${NC}"
    echo "  Username: ${GREEN}${NEW_USER}${NC}"
    echo "  Password: ${GREEN}${NEW_PASSWORD}${NC}"
    echo "  Sudo: ${GREEN}NOPASSWD (full access)${NC}"
    
    if [ "$INSTALL_SSH_KEY" = "true" ] && [ -n "$SSH_PUBLIC_KEY" ] && [ "$SSH_PUBLIC_KEY" != "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC... your-public-key-here competition@kali" ]; then
        echo "  SSH Key: ${GREEN}Installed${NC}"
    fi
    
    echo -e "\n${CYAN}Test the new user:${NC}"
    echo "  ssh ${NEW_USER}@$(hostname -I | awk '{print $1}')"
    echo -e "\n${GREEN}========================================${NC}"
    
    # Exit and don't add to history
    exit 0
}

# Run main function
main