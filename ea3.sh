#!/bin/ksh
##########################################################################################################
#
# ea3.sh - apalyzer: APache Access_Log analYZER - Version v1502
#
# Purpose:     Help to analyze the apache access_log and is geared towards
#              EBusiness Suite logs
#
# Author:      Dimas Chbane (dchbane1@yahoo.com)
#
# Copyright:   (c) Dimas Chbane - http://dimas-chbane.net - All rights reserved.
#
# Disclaimer:  This script is provided "as is", so no warranties or guarantees are
#              made about its correctness, reliability and safety. Use it at your
#              own risk!
#
# License:     This script is protected by the GNU General Public License listed in 
#              http://www.gnu.org/licenses/gpl.txt
#              In summary:
#              1) You may use this script for your (or your businesses) purposes for free
#              2) You may modify this script as you like for your own (or your businesses) purpose,
#                 but you must always leave this script header (the entire comment section), including the
#                 author, copyright and license sections as the first thing in the beginning of this file
#              3) You may NOT publish or distribute this script or any variation of it PUBLICLY
#                 (including, but not limited to uploading it to your public website or ftp server),
#                 instead just link to its location in dimas-chbane.net 
#              4) You may distribute this script INTERNALLY in your company, for internal use only,
#                 for example when building a standard DBA toolset to be deployed to all
#                 servers or DBA workstations 
#
# Note:        If you make any modification that you believe that would also benefit others,
#              please let me know and I will consider adding that to the orignal script and share
#              the credits.
#
# Config file: Review the config_ea3.sh file and select the appropriate type of installation
#
###########################################################################################################

usage(){
	print ea3.sh - apache access_log analyzer
	print "usage:  ea3.sh filename"
}

# Set access_log, removing any eventual "./" in the file name
ACCESSLOG=${1//.\/}

# Check if there is only 1 file name passed and if the file exists
if [ $# -ne 1 ]  
then
    print ERROR: Wrong number of input parameters
    echo ""
    usage
    exit 1
fi

if [ ! -f $ACCESSLOG ]
then
    echo "ERROR: File" $ACCESSLOG "not found"
    echo "" 
    usage
    exit 1
fi

BASE_DIR=$(dirname $0)

# Source config file
. $BASE_DIR/ea3_config.sh

# Remove old files
rm -f ea3_out*.txt ea3_out*.html 

print "Analyzing file" $ACCESSLOG

# Get initial and end timestamp of the file
echo "File name: " $ACCESSLOG >> ea3_out_log_info.txt
echo "Start time: "`head -1 $ACCESSLOG | awk '{ print substr($4,2,20) } ' ` >> ea3_out_log_info.txt
echo "End time  : "`tail -1 $ACCESSLOG | awk '{ print substr($4,2,20) } ' ` >> ea3_out_log_info.txt

awk -v dir=$BASE_DIR '
    BEGIN { print "Timestamp, Request and time taken in seconds\n" >> "ea3_out_gt30_requests_details.txt";
            print "--- Requests with errors 5XX" >> "ea3_out_error_500.txt";
            print "--- Requests with errors 4XX" >> "ea3_out_error_400.txt";
            FS=" "; f=0; nf=0; long_req_counter=0; al=0; all=0; alout=0  } 
 
# Initialize variables
     {
     log_time_stamp=substr($4,2,14);
     log_time_taken=$11;
     log_request_details=substr($6 " " $7,1,50)}

# Count number of requests per hour and zero counters if the first timestamp
     {total_number_req_histo[log_time_stamp]++;
      if (total_number_req_histo[log_time_stamp]==1){
           AppsLogin_histo[log_time_stamp]=0;
           AppsLocalLogin_histo[log_time_stamp]=0;
           AppsLogout_histo[log_time_stamp]=0;
           bytes_returned[log_time_stamp]=0}}i

     {ip_address[log_time_stamp " " $1]++}
     
# Separate forms from non forms entries
     forms = /servlet/ {fhourly_count_histo[log_time_stamp]++; f+=1} \
                !forms {nfhourly_count_histo[log_time_stamp]++; nf+=1};

# Count Logins and Logout
     /AppsLogin/ {AppsLogin_histo[log_time_stamp]++; al +=1}
     /AppsLocalLogin/ {AppsLocalLogin_histo[log_time_stamp]++; all +=1}
     /AppsLogout/ {AppsLogout_histo[log_time_stamp]++; alout+=1}

# If the request took more than 30 sec
     $11 > 30 { total_long_req [log_time_stamp]++;
                long_request_histo[log_request_details]++; 
                long_req_counter +=1
                print log_time_stamp, $6, $7, $11 >> "ea3_out_gt30_requests_details.txt"};

# Get 400 and 500 errors
      combinedformat = /HTTP/ {code[$9]++; bytes_returned[log_time_stamp] +=$10;
                               if ($9 > 499) { print log_time_stamp, $6, $7, $9, $10, $11 >> "ea3_out_error_500.txt"} \
                               else if ($9 > 399) { print log_time_stamp, $6, $7, $9, $10, $11 >> "ea3_out_error_400_temp.txt"}} \
      !combinedformat {code[$8]++; bytes_returned[log_time_stamp] +=$9;
                              if ($8 > 499) { print log_time_stamp, $6, $7, $9, $10, $11 >> "ea3_out_error_500.txt"} \
                              else if ($8 > 399) { print log_time_stamp, $6, $7, $9, $10, $11 >> "ea3_out_error_400_temp.txt"}}

     END \
     {print "\nWriting Reports..\n";

     print "--- Total number of requests ", f+nf >> "ea3_out_total_number_requests.txt"
     print "\n--- Number of requests per hour" >> "ea3_out_total_number_requests.txt"
     for (i in total_number_req_histo) {print i,  total_number_req_histo[i] >> "ea3_out_total_number_requests.txt";
                                        print "[\x27", i, "\x27," total_number_req_histo[i], "]"  >> "ea3_out_total_number_requests_temp.txt" };

     print "\n--- Average of Bytes Returned per hour (KB/s)" >> "ea3_out_bytes_returned.txt"
     for (i in bytes_returned) {print i,  bytes_returned[i]/(3600*1024) >> "ea3_out_bytes_returned.txt";
                                print "[\x27", i, "\x27," bytes_returned[i]/(3600*1024), "]"  >> "ea3_out_bytes_returned_temp.txt" };

     print "--- Number of Forms requests ", f >> "ea3_out_forms_requests.txt"
     print "\n--- Number of Forms requests per hour" >> "ea3_out_forms_requests.txt"
     for (i in fhourly_count_histo) { print i, fhourly_count_histo[i] >> "ea3_out_forms_requests.txt";
                                      print "[\x27", i, "\x27," fhourly_count_histo[i], "]" >> "ea3_out_forms_requests_temp.txt"};

     print "--- Number of Non-Forms requests ", nf >> "ea3_out_non_forms_requests.txt" 
     print "\n--- Number of Forms requests per hour" >> "ea3_out_non_forms_requests.txt"
     for (i in nfhourly_count_histo) { print i,  nfhourly_count_histo[i] >> "ea3_out_non_forms_requests.txt";
                                       print "[\x27", i, "\x27," nfhourly_count_histo[i], "]" >> "ea3_out_non_forms_requests_temp.txt"};

     print "--- Number of AppsLogin requests ", al >> "ea3_out_AppsLogin_requests.txt"
     print "\n--- Number of AppsLogin requests per hour" >> "ea3_out_AppsLogin_requests.txt"
     for (i in AppsLogin_histo) { print i,  AppsLogin_histo[i] >> "ea3_out_AppsLogin_requests.txt";
                                  print "[\x27", i, "\x27," AppsLogin_histo[i], "]" >> "ea3_out_AppsLogin_requests_temp.txt"};

     print "\n--- Number of AppsLocalLogin requests ", all >> "ea3_out_AppsLocalLogin_requests.txt"
     print "\n--- Number of AppsLocalLogin requests per hour" >> "ea3_out_AppsLocalLogin_requests.txt" 
     for (i in AppsLocalLogin_histo) { print i,  AppsLocalLogin_histo[i] >> "ea3_out_AppsLocalLogin_requests.txt";
                                       print "[\x27", i, "\x27," AppsLocalLogin_histo[i], "]" >> "ea3_out_AppsLocalLogin_requests_temp.txt"};

     print "\n--- Number of AppsLogout requests ", alout >> "ea3_out_AppsLogout_requests.txt"
     print "\n--- Number of AppsLogout requests per hour" >> "ea3_out_AppsLogout_requests.txt"
     for (i in AppsLogout_histo) { print i,  AppsLogout_histo[i]  >> "ea3_out_AppsLogout_requests.txt";
                                   print "[\x27", i, "\x27," AppsLogout_histo[i], "]" >> "ea3_out_AppsLogout_requests_temp.txt"};

     print "\n--- Number of AppsLogin, AppsLocalLogin and AppsLogout requests " >> "ea3_out_Login_Logout_requests.txt"
     for (i in total_number_req_histo) { printf ("%s  %10d  %10d  %10d\n", i, AppsLogin_histo[i], AppsLocalLogin_histo[i], AppsLogout_histo[i])  >> "ea3_out_Login_Logout_requests.txt";
                                         print "[\x27", i, "\x27," ,AppsLogin_histo[i], ",", AppsLocalLogin_histo[i], "," AppsLogout_histo[i] "]" >> "ea3_out_Login_Logout_requests_temp.txt"};

     print "\n--- Number of requests that took more than 30 sec:", long_req_counter >> "ea3_out_gt30_requests.txt";
     print "\n--- Number of requests that took more than 30 sec per hour" >> "ea3_out_gt30_requests.txt";
     for (i in total_long_req) { print i, total_long_req[i] >> "ea3_out_gt30_requests.txt";
                                 print "[\x27", i, "\x27," total_long_req[i], "]" >> "ea3_out_gt30_requests_temp.txt"};

     for (i in long_request_histo) {print long_request_histo[i], i >> "ea3_out_gt30_requests_histo_temp.txt"}

     for (i in code) { print i, code[i] >> "ea3_out_return_code_temp1.txt";
                       print "[\x27", i, "\x27," code[i], "]" >> "ea3_out_return_code_temp2.txt"};

     for (i in ip_address) { printf ("%-32s %10d\n", i, ip_address[i]) >> "ea3_out_ip_temp.txt"}

     }' $ACCESSLOG


# Create pie chart for forms
FR=`head -n 1 ea3_out_forms_requests.txt| awk '{ print $6 }'`
NFR=`head -n 1 ea3_out_non_forms_requests.txt| awk '{ print $6 }'`
$BASE_DIR/source/ea3_draw_pie_chart_2_entries.sh $FR $NFR "Type of Requests" "Requests" "Type of Requests" "Forms" "Non-Forms" "ea3_out_forms_pie_chart.html"

# Create bar chart for Total number of requests
$BASE_DIR/source/ea3_draw_bar_chart.sh ea3_out_total_number_requests_temp.txt "Date/Hour" "Total Number of Requests per Hour (KB/s)" "Total Number of Requests per Hour (KB/s)" ea3_out_total_number_requests_bar_chart.html

# Create bar chart for Average of Bytes Returned
$BASE_DIR/source/ea3_draw_bar_chart.sh ea3_out_bytes_returned_temp.txt "Date/Hour" "Bytes Returned (KB/s)" "Average of Bytes Returned per Hour (KB/s)" ea3_out_bytes_returned_bar_chart.html

# Create bar chart for forms requests
$BASE_DIR/source/ea3_draw_bar_chart.sh ea3_out_forms_requests_temp.txt "Date/Hour" "Number of Forms Requests" "Number of Forms Requests per Hour" ea3_out_forms_requests_bar_chart.html

# Create bar chart for non-forms requests
$BASE_DIR/source/ea3_draw_bar_chart.sh ea3_out_non_forms_requests_temp.txt "Date/Hour" "Number of Non-Forms Requests" "Number of Non-Forms Requests per Hour" ea3_out_non_forms_requests_bar_chart.html

# Create bar chart for Login/Logout activities
$BASE_DIR/source/ea3_draw_bar_chart.sh ea3_out_AppsLogin_requests_temp.txt "Date/Hour" "Number of AppsLogin Requests" "Number of AppsLogin Requests per Hour" ea3_out_AppsLogin_requests_bar_chart.html
$BASE_DIR/source/ea3_draw_bar_chart.sh ea3_out_AppsLocalLogin_requests_temp.txt "Date/Hour" "Number of AppsLocalLogin Requests" "Number of AppsLocalLogin Requests per Hour" ea3_out_AppsLocalLogin_requests_bar_chart.html
$BASE_DIR/source/ea3_draw_bar_chart.sh ea3_out_AppsLogout_requests_temp.txt "Date/Hour" "Number of AppsLogout Requests" "Number of AppsLogout Requests per Hour" ea3_out_AppsLogout_requests_bar_chart.html
$BASE_DIR/source/ea3_draw_3bars_chart.sh ea3_out_Login_Logout_requests_temp.txt "Date/Hour" "AppsLogin" "AppsLocalLogin" "AppsLogout" "Number of Logins/Logouts per Hour" ea3_out_Login_Logout_requests_bar_chart.html 

# Create bar chart for requests that took more than 30 sec
$BASE_DIR/source/ea3_draw_bar_chart.sh ea3_out_gt30_requests_temp.txt "Date/Hour" "Number of Requests that took more than 30" "Number of Requests that took more thatn 30 sec per Hour" ea3_out_gt30_requests_bar_chart.html

# Sort details about the requests that took more than 30 sec
print "--- Requests taking more than 30 sec, grouped by the first 50 characters\n"  >> "ea3_out_gt30_requests_histo.txt"
sort -nr ea3_out_gt30_requests_histo_temp.txt >> ea3_out_gt30_requests_histo.txt

# Sort return code
print "--- Number of requests per return code" >> "ea3_out_return_code.txt";
sort -n ea3_out_return_code_temp1.txt >> ea3_out_return_code.txt

# Create bar chart for return code
sort -n ea3_out_return_code_temp2.txt >> ea3_out_return_code_temp.txt
$BASE_DIR/source/ea3_draw_bar_chart.sh ea3_out_return_code_temp.txt "Return code" "Number of Requests per Return Code" "Number of Requests per Return Code" ea3_out_return_code_bar_chart.html

# Filter common 400 errors
print "Filter applied to list of errors: " $ERROR40X_FILTER "\n" >> ea3_out_error_400.txt
cat ea3_out_error_400_temp.txt | eval $ERROR40X_FILTER >> ea3_out_error_400.txt

# Sort ip addresses
print "Requests order by time" >> ea3_out_ip_bytime.txt
sort -k 1 ea3_out_ip_temp.txt >> ea3_out_ip_bytime.txt

print "Requests order by ip address" >> ea3_out_ip_byip.txt
sort -k 2 ea3_out_ip_temp.txt >> ea3_out_ip_byip.txt

print "Requests order by number of requests" >> ea3_out_ip_byrequests.txt
sort -n -k 3 ea3_out_ip_temp.txt >> ea3_out_ip_byrequests.txt

# Get OS related processes
ps -ef| grep -v awk | awk ' NR == 1 {print $0 >> "ea3_out_forms_procs.txt"; print $0 >> "ea3_out_httpd_procs.txt"; print $0 >> "ea3_out_java_procs.txt"}
             /frmweb/ {print $0 >> "ea3_out_java_procs.txt"}
              /httpd/ {print $0 >> "ea3_out_httpd_procs.txt"}
               /java/ {print $0 >> "ea3_out_java_procs.txt"}'

# Copy config files according to version (see ea3_config.sh)
case $EBS_VERSION in
  "NONE") cp $EBS_NONE/*.conf . ;;
  "11.5") cp $EBS_115/*.conf . ;;
  "12.1") cp $EBS_121/*.conf . ;;
  "12.2") cp $EBS_122/*.conf . ;;
esac
# Renaming files to avoid mime error conversion in the browser
rename conf txt *conf

# Copy html START_HERE file
cp $BASE_DIR/source/*START_HERE* .

# Rename the files to add the access_log file to the name and change the START_HERE file
rename ea3_out_ ea3_out_$ACCESSLOG"_" ea3_out_*.txt
rename ea3_out_ ea3_out_$ACCESSLOG"_" ea3_out_*.html
sed -i.bak s/ea3_out_/ea3_out_$ACCESSLOG"_"/g *START_HERE*

# Delete temp files and generate final zip file
rm -f ea3_out*temp* ea3_out*.bak 
zip -qm ea3_out_$ACCESSLOG.zip ea3_out_START*.html ea3_out*txt ea3_out*.html  *.txt

print "File ea3_out_$ACCESSLOG.zip generated. Done!"

exit 0
