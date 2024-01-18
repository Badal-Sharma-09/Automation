#!/bin/bash
#!/bin/bash

#colors
red=`tput setaf 1`
green=`tput setaf 2`
yellow=`tput setaf 3`
blue=`tput setaf 4`
magenta=`tput setaf 5`
reset=`tput sgr0`

read -p "Enter the Domain name : " domain
read -p "Enter the Domain name : " url


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

if [ -d ~/Documents/Subdomain_automation/$domain/github_dorks ]
then
  echo " "
else
  mkdir ~/Documents/Subdomain_automation/$domain/github_dorks

fi


#github dorking

echo "${yellow} ---------------------------------- xxxxxxxx ---------------------------------- ${reset}"
echo " "
echo "${blue} [+] Checking for dependencies ${reset}"
if [ -f /Users/HP/trufflehog  ]
then
  echo "${blue} [+] Installing trufflehog  ${reset}"
  git clone https://github.com/trufflesecurity/trufflehog.git
  cd trufflehog
  go install
else
  echo "${magenta} [+] Already installed trufflehog ${reset}"
  trufflehog --regex --max_depth $url 

fi

########################
#complete github dorking
########################

echo "${yellow} ---------------------------------- xxxxxxxx ---------------------------------- ${reset}"

