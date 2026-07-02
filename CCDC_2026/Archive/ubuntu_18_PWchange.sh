#!/bin/bash

# Remove all users except root
for username in $(awk -F: '$3 >= 1000 && $1 != "root" {print $1}' /etc/passwd); do
    userdel -r $username
done

# Change root password
echo "root:AlexTech2024CCDC!" | chpasswd

# Change password for other system accounts if needed
# echo "username:new_password" | chpasswd

echo "User removal and password change completed."
