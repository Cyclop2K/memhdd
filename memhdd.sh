#!/bin/bash
#Name: Michael White 
# Colors for the scripts
red='\033[0;31m'
green='\033[0;32m'
blue='\033[0;34m'
default='\033[39;49;0m'
redbold='\033[31;40;1m'
greenbold='\033[32;40;1m'
cyanbold='\033[36;1m'
yellow='\033[33;49m'
blackbold='\033[30;49;1m'
# Check if the current user is root
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root."
    exit 1
fi

# Create a directory to save extracted data
output_directory="extracted_data"
mkdir -p "$output_directory/Vol"
mkdir -p "$output_directory"
mkdir -p "$output_directory/Strings"
mkdir -p "$output_directory/Binwalk"
# Allow user to specify the filename and check if it exists
read -p "[*]Please enter the memory file or the HDD image file name:" filename
echo -e "[*] The following file was provided: ${blue}$filename${default}"
read -p "[*]Select M[memory dump file] or H[HDD image file]:" CHOICE

# Check if the file exists
if [ -e "$filename" ]; then
   echo "[*]File '$filename' exists."
else
   echo -e "${red}[?]File '$filename' does not exist.${default}"
   exit 1
fi

# Function to install missing forensics tools
install_forensics_tools() {
    echo "${green}[*]Installing forensics tools...${default}"
    apt-get update
    if apt-get install -y bulk-extractor binwalk; then
        echo "${green}[*]Forensics tools installed.${default}"
    else
        echo "${red}[!]Failed to install forensics tools.${default}"
        exit 1
    fi
}
# installing vol
echo -e "${cyanbold}----[*]Installing Volatility----${default}"
cd /home/kali/Desktop
wget http://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_lin64_standalone.zip 2>/dev/null && sudo chmod 777 -R volatility_2.6_lin64_standalone.zip 2>/dev/null
sudo unzip volatility_2.6_lin64_standalone.zip 2>/dev/null && chmod 777 -R volatility_2.6_lin64_standalone 2>/dev/null && cd volatility_2.6_lin64_standalone 2>/dev/null && mv volatility_2.6_lin64_standalone vol 2>/dev/null
cd /home/kali/Desktop/volatility_2.6_lin64_standalone
mv -t /home/kali/Desktop vol
cd /home/kali/Desktop
echo -e "${cyanbold}----[*]Volatility Installed----${default}"

# Check if forensics tools are installed, if not, install them
if ! command -v bulk_extractor &> /dev/null || ! command -v binwalk &> /dev/null; then
    install_forensics_tools
fi

# Function to Use Vol only when using a Memory File type
function Vol() {
    profiles=$(./vol -f "$filename" imageinfo | grep "Suggested Profile" | awk '{gsub(",", ""); print $4}'
)

    for profile in $profiles; do
        echo -e "${green}[*] Running Volatility analysis with profile: $profile${default}"
        
        # Save memory profile into a variable
        memory_profile="$profile"
        
        # Display running processes
        echo -e "profile=${redbold}$memory_profile${default}, filename=${redbold}$filename${default}"
        echo -e "${blackbold}************************************************************${default}"
        ./vol -f "$filename" --profile="$memory_profile" pslist > "$output_directory/Vol/running_processes_$profile" 2>&1
        
        # Display network connections
        ./vol -f "$filename" --profile="$memory_profile" connections > "$output_directory/Vol/network_connections_$profile" 2>&1
        
        # Extract registry information
        ./vol -f "$filename" --profile="$memory_profile" printkey -K "Software\\Microsoft\\Windows\\CurrentVersion\\Run" > "$output_directory/Vol/registry_run_keys_$profile" 2>&1
        
        echo -e "${green}[*] Volatility analysis completed for profile: $profile${default}"
    done
}



#### FUNCTIONS (choice) between M / H (memory / HDD)
case "$CHOICE" in
    M)
        echo -e "${green}[+] $filename is a Memory dump file${default}"
        echo -e "${blackbold}************************************************************${default}"
        echo -e "${green}[*] Extracting data...${default}"
        Vol
        ;;
    H)
        echo -e "${green}[+] $filename is a HDD image file${default}"
        echo -e "${blackbold}************************************************************${default}"
        echo -e "${green}[*] Extracting data...${default}"
        ;;
    *)
        echo -e "${red}You entered the wrong choice. Please start again and choose M or H.${default}"
        exit 1
        ;;
esac

# Use different carvers to extract data
echo -e "${blackbold}************************************************************${default}"
# bulk-extractor
bulk_extractor -o "$output_directory/bulk" "$filename" > /dev/null 2>&1
echo -e "${yellow}[*]Carving with Bulk.${default}"
# strings
strings -a "$filename" > "$output_directory/Strings/strings_output.txt" 2>/dev/null
echo -e "${yellow}[*]Running Strings.${default}"
# binwalk
binwalk "$filename" > "$output_directory/Binwalk/binwalk_results"
echo -e "${yellow}[*]binwalk completed.${default}"

# Show Location and size of extracted network traffic
network_traffic_dir="$output_directory/bulk"
if [ -d "$network_traffic_dir" ]; then
    network_pcap_files=("$network_traffic_dir"/*.pcap)
    if [ "${#network_pcap_files[@]}" -gt 0 ]; then
        for pcap_file in "${network_pcap_files[@]}"; do
            echo -e "${yellow}[*]Network traffic extracted. Location: $pcap_file${default}"
            echo -e "${yellow}Size: $(du -h "$pcap_file" | cut -f1)${default}"
        done
    else
        echo -e "${red}[!]No network traffic pcap files were extracted by bulk-extractor.${default}"
    fi
else
    echo -e "${red}[!]No network traffic pcap files were extracted by bulk-extractor.${default}"
fi
# Check for human-readable data
grep -r -E 'password|username|\.exe' "$output_directory" > "$output_directory/human_readable_info.txt" 2>/dev/null
echo -e "${yellow}[*]human-readable file extraction completed${default}"

echo -e "${blackbold}************************************************************${default}"
# Display general statistics
analysis_time=$(date)
bulk_num=$(find "$output_directory/bulk" -type f | wc -l)
binwalk_num=$(find "$output_directory/Binwalk" -type f | wc -l)
vol_num=$(find "$output_directory/Vol" -type f | wc -l)
strings_num=$(find "$output_directory/Strings" -type f | wc -l)
echo -e "${green}[*]Analysis time: $analysis_time${default}"
echo -e "${blue}[$]Bulk FIles:[$bulk_num]" "[$]Strings FIles:[$strings_num]" "[$]Binwalk FIles:[$binwalk_num]" "[$]Vol Files:[$vol_num]${default}"


# Save results into a report
report_file="$output_directory/analysis_report.txt"
echo "Analysis Report" > "$report_file"
echo "Analysis time: $analysis_time" >> "$report_file"
echo "Number of extracted files: [$]Bulk FIles:[$bulk_num]" "[$]Strings FIles:[$strings_num]" "[$]Binwalk FIles:[$binwalk_num]" "[$]Vol Files:[$vol_num]" >> "$report_file"
echo -e "${blackbold}************************************************************${default}"
# Zip the extracted files and the report
zip -r "$output_directory.zip" "$output_directory" "$report_file" > /dev/null 2>&1
echo -e "${green}[*]Results saved in '$output_directory.zip'.${default}"
echo -e "${blackbold}************************************************************${default}"
echo -e "${greenbold}[***]Script completed[***].${default}"
