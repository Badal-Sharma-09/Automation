#!/bin/bash

echo "${blue} ===============================================================================${reset}"
echo -e " MADE BY BADAL SHARMA "
echo "${blue} ===============================================================================${reset}"


#colors
red=`tput setaf 1`
green=`tput setaf 2`
yellow=`tput setaf 3`
blue=`tput setaf 4`
magenta=`tput setaf 5`
reset=`tput sgr`

echo "${blue} =================================================================================${reset}"
read -p "Enter the Domain name : " domain
echo "${blue} =================================================================================${reset}"

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

if [ -d ~/Documents/Subdomain_automation/$domain/Subdomains ]
then
  echo " "
else
  mkdir ~/Documents/Subdomain_automation/$domain/Subdomains

fi

if [ -d ~/Documents/Subdomain_automation/$domain/Visual_Recon ]
then
  echo " "
else
  mkdir ~/Documents/Subdomain_automation/$domain/Visual_Recon

fi

if [ -d ~/Documents/Subdomain_automation/$domain/Subdomain_discovery ]
then
  echo " "
else
  mkdir ~/Documents/Subdomain_automation/$domain/Subdomain_discovery

fi

if [ -d ~/Documents/Subdomain_automation/$domain/Archivescan ]
then
  echo " "
else
  mkdir ~/Documents/Subdomain_automation/$domain/Archivescan

fi

if [ -d ~/Documents/Subdomain_automation/$domain/JSscan ]
then
  echo " "
else
  mkdir ~/Documents/Subdomain_automation/$domain/JSscan

fi

if [ -d ~/Documents/Subdomain_automation/$domain/API ]
then
  echo " "
else
  mkdir ~/Documents/Subdomain_automation/$domain/API

fi

if [[ -d ~/Documents/Subdomain_automation/$domain/vulnerbility ]]
then 
  echo " "
else
  mkdir ~/Documents/Subdomain_automation/$domain/vulnerbility
fi

if [[ -d ~/Documents/Subdomain_automation/$domain/vulnerbility/Package_Dependency_Confusion ]]
  then 
    echo " "
else
  mkdir ~/Documents/Subdomain_automation/$domain/vulnerbility/Package_Dependency_Confusion
fi

echo "${blue} =============================================================================${reset}"
echo "${blue} [+] Starting Visual Recon ${reset}"
echo "${blue} =============================================================================${reset}"

#amass
echo "${yellow} ---------------------------------- xxxxxxxx ------------------------------ ${reset}"

if [ -f C:/Users/HP/amass.exe ]
then
  echo "${magenta} [+] Running Amass for subdomain enumeration${reset}"
  amass.exe enum --passive -d $domain > ~/Documents/Subdomain_automation/$domain/Subdomains/amass.txt
elif [ -f C:/Users/HP/amass.exe ]
then
 echo "${blue} [+] Installing Amass ${reset}"
 echo "${blue} [+] This may take few minutes hang tight... ${reset}"
 go get -u github.com/OWASP/Amass/...
 echo "${magenta} [+] Running Amass for subdomain enumeration${reset}"
 amass enum --passive -d $domain > ~/Documents/Subdomain_automation/$domain/Subdomains/amass.txt
else 
docker run -i caffix/amass:latest enum -d $domain  | tee -a ~/Documents/Subdomain_automation/$domain/Subdomains/amass.txt
fi

echo "${blue} [+] Succesfully saved as amass.txt  ${reset}"

#assetfinder
echo "${yellow} ---------------------------------- xxxxxxxx ---------------------------------- ${reset}"

if [ -f C:/Users/HP/assetfinder.exe ]
then
  echo "${magenta} [+] Running Assetfinder for subdomain enumeration${reset}"
  assetfinder.exe -subs-only $domain >> ~/Documents/Subdomain_automation/$domain/Subdomains/assetfinder.txt 
else
 docker run -i lotuseatersec/assetfinder:latest -subs-only $domain >> ~/Documents/Subdomain_automation/$domain/Subdomains/asset_finder.txt
fi

echo "${blue} [+] Succesfully saved as assetfinder.txt  ${reset}"

#subfinder
echo "${yellow} ---------------------------------- xxxxxxxx ---------------------------------- ${reset}"

if [ -f C:/Users/HP/subfinder.exe ]
then
  echo "${magenta} [+] Running Subfinder for subdomain enumeration${reset}"
  subfinder -d $domain -o ~/Documents/Subdomain_automation/$domain/Subdomains/subfinder.txt
else 
  docker run -i projectdiscovery/subfinder -d $domain -o ~/Documents/Subdomain_automation/$domain/Subdomains/subfinder.txt
fi


echo "${blue} [+] Succesfully saved as subfinder.txt  ${reset}"

#uniquesubdomains
echo "${yellow} ---------------------------------- xxxxxxxx ---------------------------------- ${reset}"

echo "${magenta} [+] Fetching unique domains ${reset}"

cat ~/Documents/Subdomain_automation/$domain/Subdomains/*.txt | sort -u >> ~/Documents/Subdomain_automation/$domain/Subdomains/unique.txt
echo "${blue} [+] Succesfully saved as unique.txt ${reset}"

#sorting alive subdomains
echo "${yellow} ---------------------------------- xxxxxxxx ---------------------------------- ${reset}"

echo "${magenta} [+] Running Httprobe for sorting alive subdomains${reset}"
cat ~/Documents/Subdomain_automation/$domain/Subdomains/unique.txt | httprobe.exe >> ~/Documents/Subdomain_automation/$domain/Subdomains/all-alive-subs.txt
cat ~/Documents/Subdomain_automation/$domain/Subdomains/all-alive-subs.txt | sed 's/http\(.?*\)*:\/\///g' >> ~/Documents/Subdomain_automation/$domain/Subdomains/final-all-alive-subs.txt


echo "${blue} [+] Successfully saved the results"

echo "${red} ---------------------------------- xxxxxxxx ---------------------------------- ${reset}"
 
#screenshotting
echo "${yellow} ---------------------------------- xxxxxxxx ---------------------------------- ${reset}"

if [ -f C:/Users/HP/aquatone.exe ]
then
  echo "${magenta} [+] Running Aquatone for screenshotting alive subdomains${reset}"
 cat ~/Documents/Subdomain_automation/$domain/Subdomains/Final-all-alive-subs.txt | aquatone.exe -http-timeout 10000 -scan-timeout 300 -ports xlarge -chrome-path C:/Users/HP/AppData/Local/Chromium/Application/chrome.exe -out  ~/Documents/Subdomain_automation/$domain/Visual_Recon
else
  echo "${blue} [+] Installing Aquatone ${reset}"
  go get github.com/michenriksen/aquatone
  echo "${magenta} [+] Running Aquatone for screenshotting alive subdomains${reset}"
 cat ~/Documents/Subdomain_automation/$domain/Subdomains/Final-all-alive-subs.txt | aquatone.exe -http-timeout 10000 -scan-timeout 300 -ports xlarge -chrome-path C:/Users/HP/AppData/Local/Chromium/Application/chrome.exe -out  ~/Documents/Subdomain_automation/$domain/Visual_Recon
fi
echo "${yellow} ---------------------------------- xxxxxxxx ---------------------------------- ${reset}"

echo "${blue} [+] Successfully saved the results"

#Finding for source/backup files

if [[ C:/Users/HP/fuzzuli.exe ]]; then
  fuzzuli -f $domain -w 32 -ex .rar,.zip -es "tesla|twitter" -dl 11 -p | tee -a ~/Documents/Subdomain_automation/$domain/backup_files.txt
fi

echo "${blue} ===============================================================================${reset}"
echo "${blue} [+] Started Scanning for JS files ${reset}"
echo "${blue} ===============================================================================${reset}"


#wayback_URL
echo "${yellow} ---------------------------------- xxxxxxxx ---------------------------------- ${reset}"

if [ -f C:/Users/HP/waybackurls.exe ] 
then
 echo "${magenta} [+] Already installed Waybackurls ${reset}"
else
 echo "${blue} [+] Installing Waybackurls ${reset}"
 go get -u github.com/tomnomnom/waybackurls
fi

if [ -f ~/Documents/Subdomain_automation/$domain/Archivescan/waybackurls.txt ]
then
 echo "${magenta} [+] Already done Waybackurls ${reset}"
else
 echo "${blue} [+] Running Waybackurls for finding archive based assets${reset}"
 cat ~/Documents/Subdomain_automation/$domain/Subdomains/all-alive-subs.txt | waybackurls >> ~/Documents/Subdomain_automation/$domain/Archivescan/waybackurls.txt 
 #Extract URLs from Source Code
curl "$domain" | grep -oP '(https*.//|www\.)[^]*' >> "file"/Extract-Urls/source_code_urls.txt
 echo "${blue} [+] Succesfully saved as waybackurls.txt ${reset}"
fi

#Gau
echo "${yellow} ---------------------------------- xxxxxxxx ---------------------------------- ${reset}"

if [ -f C:/Users/HP/guu.exe ]
then
 echo "${magenta} [+] Already installed Gau ${reset}"
else
 echo "${blue} [+] Installing Gau ${reset}"
 go get -u github.com/lc/gau

fi

echo "${yellow} ---------------------------------- xxxxxxxx ---------------------------------- ${reset}"

if [ -f ~/Documents/Subdomain_automation/$domain/Archivescan/gau.txt ]
then
 echo "${magenta} [+] Already done Gau ${reset}"
else
 echo "${blue} [+] Running Gau for finding archive based assets${reset}"
 cat C:/Users/HP/Documents/Subdomain_automation/zip.co/Subdomains/all-alive-subs.txt | gau >> ~/Documents/Subdomain_automation/$domain/Archivescan/gau.txt
 echo "${blue} [+] Succesfully saved as gau.txt ${reset}"
fi

if [ -f C:/Users/HP/katana.exe ]
then
  echo "${magenta} [+] Already done katana ${reset}"
else 
  cat C:/Users/HP/Documents/Subdomain_automation/zip.co/Subdomains/all-alive-subs.txt | katana -u $domain -headless -jc -aff -kf -c 50 -fs dn -o ~/Documents/Subdomain_automation/$domain/Archivescan/katana.txt
echo "${blue} [+] Succesfully saved as katana.txt ${reset}"
fi   

#uniquesubdomains

echo "${yellow} ---------------------------------- xxxxxxxx ---------------------------------- ${reset}"

if [ -f ~/Documents/Subdomain_automation/$domain/Archivescan/sorted.txt ]
then
 echo "finding"
else
 cat ~/Documents/Subdomain_automation/$domain/Archivescan/waybackurls.txt ~/Documents/Subdomain_automation/$domain/Archivescan/gau.txt ~/Documents/Subdomain_automation/$domain/Archivescan/katana.txt | sort -u >> ~/Documents/Subdomain_automation/$domain/Archivescan/sorted.txt
 echo "${blue} [+] Succesfully saved as sorted.txt ${reset}"
fi

#Gathering Js Files
echo "${yellow} ---------------------------------- xxxxxxxx ---------------------------------- ${reset}"

echo "${blue} [+] Checking for dependencies ${reset}"
if [ -f C:/Users/HP/httpx.exe ]
then
   echo "${magenta} [+] Already installed httpx ${reset}"
 else
  echo "${blue} [+] Installing httpx ${reset}"
  go get -u github.com/projectdiscovery/httpx/cmd/httpx
fi

if [ -f C:/Users/HP/anew.exe ]
then
  echo "${magenta} [+] Already installed anew ${reset}"
else
   echo "${blue} [+] Installing anew ${reset}"
  go get -u github.com/tomnomnom/anew
fi

if [ -f C:/Users/HP/subjs.exe ]
then
 echo "${magenta} [+] Already installed subjs ${reset}"
else
  echo "${blue} [+] Installing subjs ${reset}"
  go get -u github.com/lc/subjs
fi
if [[ C:/Users/HP/katana.exe ]]; then
   echo "${magenta} [+] Already installed katana ${reset}" 
else
  echo "${blue} [+] Installing katana ${reset}"
  go install github.com/projectdiscovery/katana/cmd/katana@latest
fi

echo "${blue} [+] Started Gathering Live JsFiles-links ${reset}"
echo ""
cat ~/Documents/Subdomain_automation/$domain/Archivescan/sorted.txt | grep -iE "\.js$" | uniq | sort >> ~/Documents/Subdomain_automation/$domain/JSscan/mixed_jsfile_links_from_archives.txt
cat ~/Documents/Subdomain_automation/$domain/JSscan/mixed_jsfile_links_from_archives.txt | httpx -silent >> ~/Documents/Subdomain_automation/$domain/JSscan/jsfile_links_from_archives.txt
cat ~/Documents/Subdomain_automation/$domain/Subdomains/Final-all-alive-subs.txt |  httpx -silent | subjs | anew | tee -a ~/Documents/Subdomain_automation/$domain/JSscan/jsfile_links_from_subjs.txt
rm -rf ~/Documents/Subdomain_automation/$domain/JSscan/mixed_jsfile_links_from_archives.txt
cat ~/Docums/Subdomain_automation/$domain/JSscan/jsfile_links_from_archives.txt ~/Documents/Subdomain_automation/$domain/JSscan/jsfile_links_from_subjs.txt | sort -u > ~/Documents/Subdomain_automation/$domain/JSscan/js_scan_result.txt

##############################
#END OF JSscan
##############################

#js secretfinding 

cat C:/Users/HP/Documents/Subdomain_automation/zip.co/js_scan_result.txt | xargs -I@ sh -c 'python C:/Users/HP/secretfinder/SecretFinder.py -i @'

echo "${yellow} ---------------------------------- xxxxxxxx ---------------------------------- ${reset}"
echo ""
echo "${blue} [+] Successfully saved the results"
echo ""
echo "${yellow} ---------------------------------- xxxxxxxx ---------------------------------- ${reset}"

#website info. gathering
whatweb -a 3 $domain | tee -a ~/Documents/Subdomain_automation/$domain/website_info.txt

echo "${yellow} ---------------------------------- xxxxxxxx ---------------------------------- ${reset}"

echo "${red} ---------------------------------- xxxxxxxx ---------------------------------- ${reset}"


if [[ C:/Users/HP/pinkerton/main.go ]]; then
  python C:/Users/HP/pinkerton/main.go -u https://$domain
fi

#API

echo "${yellow} ---------------------------------- xxxxxxxx ---------------------------------- ${reset}"
#Package Dependency Confusion Vulnerability

#automatic mathod

nuclei -I ~/Documents/Subdomain_automation/$domain/Subdomains/all-alive-subs.txt -t C:/Users/HP/nuclei/nuclei-templates/exposures/configs/package-json.yaml -o C:/Users/HP/Documents/Subdomain_automation/ro.co/vulnerbility/Package_Dependency_Confusion/pakages.txt
cat C:/Users/HP/Documents/Subdomain_automation/ro.co/vulnerbility/Package_Dependency_Confusion/pakages.txt | cut -d ' ' -f6 | C:/Users/HP/fff/fff.exe -s 200 -o C:/Users/HP/Documents/Subdomain_automation/ro.co/vulnerbility/Package_Dependency_Confusion

#github manual method

if [ -f C:/Users/HP/ghorg/ghorg.exe]
then
C:/Users/HP/ghorg/ghorg.exe clone -t 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
find . -type f -name package.json | xargs -n1 -I{} cat {} | jq -r '.dependencies + .devDependencies' | cut -d : -f 1 | tr -d '"|}|{' | sort -u | tr -s "     " | sort -u | xargs -n1 -I{} echo "https://registry.npmjs.org/{}" | grep -v "@" | httpx -status-code -silent -content-length -mc 404
else
  echo "not found try again....."
fi

#source ~/.bash_profile

echo “Currently waybackurls extract is in progress!!”
 cat  ~/Documents/Subdomain_automation/$domain/Subdomains/unique.txt | gau >> ~/Documents/Subdomain_automation/$domain/API/allfiles.txt
 cat  ~/Documents/Subdomain_automation/$domain/Subdomains/unique.txt | waybackurls >> ~/Documents/Subdomain_automation/$domain/API/allfiles.txt
echo “Waybackurls extraction is complete!!”
sort -ru  ~/Documents/Subdomain_automation/$domain/API/allfiles.txt >> ~/Documents/Subdomain_automation/$domain/API/uniq_files.txt
echo “Uniq file also created. please check [uniq_files.txt]”
echo “Now, we need to extract only html files from the list”
grep -iv -E — ‘.js|.png|.jpg|.gif|.ico|.img|.css’ ~/Documents/Subdomain_automation/$domain/API/uniq_files.txt >> ~/Documents/Subdomain_automation/$domain/API/wayback_only_html.txt
echo “We have extracted all html files.Please check [wayback_only_html.txt]”
echo “Next is to extracct js files from the list”
cat ~/Documents/Subdomain_automation/$domain/API/uniq_files.txt | grep “\.js” | uniq | sort >> ~/Documents/Subdomain_automation/$domain/API/wayback_js_files.txt
cat ~/Documents/Subdomain_automation/$domain/API/uniq_files.txt | grep “\.json” | uniq | sort >> ~/Documents/Subdomain_automation/$domain/API/wayback_json_files.txt
echo “Js files have been successfully extracted **************[wayback_js_files.txt]**************”
echo “Json files have been successfully extracted **************[wayback_json_files.txt]**************”
echo “Now extracting important urls from **************[wayback_only_html.txt]**************”
grep — color=always -i -E — ‘admin|auth|api|jenkins|corp|dev|stag|stg|prod|sandbox|swagger|aws|azure|uat|test|vpn|cms’ ~/Documents/Subdomain_automation/$domain/API/wayback_only_html.txt >> ~/Documents/Subdomain_automation/$domain/API/important_http_urls.txt
echo “Please check file **************[important_http_urls.txt]*************”
grep — color=always -i -E — ‘aws|s3’ ~/Documents/Subdomain_automation/$domain/API/uniq_files.txt >> ~/Documents/Subdomain_automation/$domain/API/aws_s3_files.txt
echo “Please check file **************aws_s3_files.txt]*************”
echo “Process is complete”
echo “Now start takin screensots selectively”
echo “The command:”
echo “ — — — — — — — “
echo “cat ~/Documents/Subdomain_automation/$domain/API/wayback_only_html.txt | aquatone -threads 20” >> ~/Documents/Subdomain_automation/$domain/API/

#Delete extra files

rm -f ~/Documents/Subdomain_automation/$domain/API/allfiles.txt ~/Documents/Subdomain_automation/$domain/API/uniq_files.txt ~/Documents/Subdomain_automation/$domain/API/wayback_only_html.txt ~/Documents/Subdomain_automation/$domain/API/wayback_js_files.txt ~/Documents/Subdomain_automation/$domain/API/wayback_httprobe_file.txt  
rm C:/Users/HP/Documents/Subdomain_automation/$domain/Subdomains/asset_finder.txt 
rm C:/Users/HP/Documents/Subdomain_automation/$domain/Subdomains/subfinder_finder.txt
rm C:/Users/HP/Documents/Subdomain_automation/$domain/Subdomains/amass.txt 
rm ~/Documents/Subdomain_automation/$domain/Archivescan/gau.txt
rm ~/Documents/Subdomain_automation/$domain/Archivescan/waybackurls.txt
rm ~/Docums/Subdomain_automation/$domain/JSscan/jsfile_links_from_archives.txt 
rm ~/Documents/Subdomain_automation/$domain/JSscan/jsfile_links_from_subjs.txt

########################
#END OF RECON
########################