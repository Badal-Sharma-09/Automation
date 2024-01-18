#!/bin/bash

#colors
red=`tput setaf 1`
green=`tput setaf 2`
yellow=`tput setaf 3`
blue=`tput setaf 4`
magenta=`tput setaf 5`
reset=`tput sgr0`

read -p "Enter the Domain name : " domain

if [ -d ~/Documents ]
then
  echo " "
else
  mkdir ~/Documents
fi

if [ -d ~/Documents/Subdomain_automation ]
then
  echo " "
else
  mkdir ~/Documents/Subdomain_automation

fi

if [ -d ~/Documents/Subdomain_automation/$domain ]
then
  echo " "
else
  mkdir ~/Documents/Subdomain_automation/$domain

fi

if [ -d ~/Documents/Subdomain_automation/$domain/Subdomain_discovery ]
then
  echo " "
else
  mkdir ~/Documents/Subdomain_automation/$domain/Subdomain_discovery

#ferocbuster
if [[ C:/Users/HP/feroxbuster/feroxbuster.exe ]]; then
feroxbuster.exe -u https://$domain -x php asp aspx jsp py txt conf config bak backup swp old db zip sql -w C:/Users/HP/Documents/Automation/common.txt -o C:/Users/HP/Documents/Subdomain_automation/$domain/Subdomain_discovery/content_discovery_result.txt
ekse
echo "not found"
fi

echo "${blue} ===============================================================================${reset}"
echo "${blue} [+] Succesfully saved as content_discovery_result.txt ${reset}"
echo "${blue} ===============================================================================${reset}"echo " "

echo "${magenta} [+] Sorting According to Status Codes ${reset}"
cat ~/Documents/Subdomain_automation/$domain/Subdomain_discovery/content_discovery_result.txt | grep 200 | awk '{print $2}' > ~/Documents/Subdomain_automation/$domain/Subdomain_discovery/result_content_discovery/status_code_200.txt  
cat ~/Documents/Subdomain_automation/$domain/Subdomain_discovery/content_discovery_result.txt | grep 204 | awk '{print $2}' > ~/Documents/Subdomain_automation/$domain/Subdomain_discovery/result_content_discovery/status_code_204.txt
cat ~/Documents/Subdomain_automation/$domain/Subdomain_discovery/content_discovery_result.txt | grep 301 | awk '{print $2}' > ~/Documents/Subdomain_automation/$domain/Subdomain_discovery/result_content_discovery/status_code_301.txt
cat ~/Documents/Subdomain_automation/$domain/Subdomain_discovery/content_discovery_result.txt | grep 302 | awk '{print $2}' > ~/Documents/Subdomain_automation/$domain/Subdomain_discovery/result_content_discovery/status_code_302.txt
cat ~/Documents/Subdomain_automation/$domain/Subdomain_discovery/content_discovery_result.txt | grep 307 | awk '{print $2}' > ~/Documents/Subdomain_automation/$domain/Subdomain_discovery/result_content_discovery/status_code_307.txt
cat ~/Documents/Subdomain_automation/$domain/Subdomain_discovery/content_discovery_result.txt | grep 308 | awk '{print $2}' > ~/Documents/Subdomain_automation/$domain/Subdomain_discovery/result_content_discovery/status_code_308.txt
cat ~/Documents/Subdomain_automation/$domain/Subdomain_discovery/content_discovery_result.txt | grep 401 | awk '{print $2}' > ~/Documents/Subdomain_automation/$domain/Subdomain_discovery/result_content_discovery/status_code_401.txt
cat ~/Documents/Subdomain_automation/$domain/Subdomain_discovery/content_discovery_result.txt | grep 403 | awk '{print $2}' > ~/Documents/Subdomain_automation/$domain/Subdomain_discovery/result_content_discovery/status_code_403.txt
cat ~/Documents/Subdomain_automation/$domain/Subdomain_discovery/content_discovery_result.txt | grep 405 | awk '{print $2}' > ~/Documents/Subdomain_automation/$domain/Subdomain_discovery/result_content_discovery/status_code_405.txt

echo "${blue} ===============================================================================${reset}"
echo "${blue} [+] Succesfully saved the results according to their status codes ${reset}"
echo "${blue} ===============================================================================${reset}"
