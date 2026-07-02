# Set strong passwords for all users (excluding root)
awk -F: '$3 >= 1000 && $1 != "root" {print $1}' /etc/passwd | xargs -I {} sudo chpasswd <<< "{}:EnterPasswordHere" 
