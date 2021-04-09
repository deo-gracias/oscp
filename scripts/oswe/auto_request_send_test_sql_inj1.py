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


files_to_check='''/about.php
/admin/cron.php
/bounce.php
/browse.php
/confirm.php
/contact_instructor.php
/get_acheck.php
/get_course_icon.php
/get_custom_logo.php
/get_profile_img.php
/get_rss.php
/go.php
/help/accessibility.php
/help/contact_support.php
/help/index.php
/inbox/export.php
/inbox/index.php
/inbox/send_message.php
/inbox/sent_messages.php
/include/securimage/securimage_play.php
/include/securimage/securimage_show.php
/include/vitals.inc.php
/login.php
/logout.php
/mods/_core/imscc/ims_export.php
/mods/_core/imscp/ims_export.php
/mods/_core/languages/translate_atutor.php
/mods/_standard/calendar/change_view.php
/mods/_standard/calendar/export.php
/mods/_standard/calendar/file_import.php
/mods/_standard/calendar/getlanguage.php
/mods/_standard/calendar/google_calendarlist.php
/mods/_standard/calendar/google_calendar_db_sync.php
/mods/_standard/calendar/google_calendar_update.php
/mods/_standard/calendar/google_connect_disconnect.php
/mods/_standard/calendar/index.php
/mods/_standard/calendar/index_mystart.php
/mods/_standard/calendar/index_public.php
/mods/_standard/calendar/json-events-gcal.php
/mods/_standard/calendar/json-events.php
/mods/_standard/calendar/send_mail.php
/mods/_standard/calendar/update_personal_event.php
/mods/_standard/photos/addComment.php
/mods/_standard/photos/albums.php
/mods/_standard/photos/create_album.php
/mods/_standard/photos/delete_album.php
/mods/_standard/photos/delete_comment.php
/mods/_standard/photos/delete_photo.php
/mods/_standard/photos/edit_album.php
/mods/_standard/photos/edit_comment.php
/mods/_standard/photos/edit_photos.php
/mods/_standard/photos/get_photo.php
/mods/_standard/photos/index.php
/mods/_standard/photos/photo.php
/mods/_standard/photos/profile_album.php
/mods/_standard/photos/search.php
/mods/_standard/photos/set_profile_picture.php
/mods/_standard/social/activities.php
/mods/_standard/social/applications.php
/mods/_standard/social/basic_profile.php
/mods/_standard/social/connections.php
/mods/_standard/social/edit_profile.php
/mods/_standard/social/groups/create.php
/mods/_standard/social/groups/delete.php
/mods/_standard/social/groups/edit.php
/mods/_standard/social/groups/get_sgroup_logo.php
/mods/_standard/social/groups/index.php
/mods/_standard/social/groups/invitation_handler.php
/mods/_standard/social/groups/invite.php
/mods/_standard/social/groups/join.php
/mods/_standard/social/groups/list.php
/mods/_standard/social/groups/search.php
/mods/_standard/social/groups/view.php
/mods/_standard/social/index.php
/mods/_standard/social/index_mystart.php
/mods/_standard/social/index_public.php
/mods/_standard/social/lib/OAuth/authorize.php
/mods/_standard/social/privacy_settings.php
/mods/_standard/social/profile_picture.php
/mods/_standard/social/settings.php
/mods/_standard/social/set_prefs.php
/mods/_standard/social/sprofile.php
/password_reminder.php
/registration.php
/search.php
'''

#files_to_check='''/mods/_standard/social/index_public.php'''



"""

for current_file in files_to_check.splitlines():
    get_var = {}
    post_var = {}
    print(current_file)
    complement=current_file.split("/")[len(current_file.split("/"))-1].split(".")[0]
    
    for i, line in enumerate(open('/media/deo-gracias/Data/Pen/OSWE/ATutor'+current_file)):
        for match in re.finditer(pattern, line):
            parameter_method = match.group(1)
            parameter_var = match.group(2)
            #print("hello " + current_file.split("/")[len(current_file.split("/"))-1].split(".")[0])
            #input()

            if (parameter_method.upper() == 'GET'):
                if not (parameter_var in get_var.keys()):
                    get_var.update({parameter_var:parameter_var+"_"+complement+"'"})

            elif (parameter_method.upper() == 'POST'):
               if not (parameter_var in post_var.keys()):
                    post_var.update({parameter_var:parameter_var+"_"+complement+"'"})

            
            print('Found on line %s: method: %s variable: %s' % (i+1, parameter_method, parameter_var))




    print("post var is ")
    print(post_var)


    r = requests.post('http://atutor/ATutor'+current_file, params=post_var, verify=False)

    print(format_text('r.status_code is: ',r.status_code))
    #print(format_text('r.headers is: ',r.headers))


    #print(format_text('r.cookies is: ',r.cookies))
    #print(format_text('r.text is: ',r.text))


    print("get var is ")
    print(get_var)


    r = requests.get('http://atutor/ATutor'+current_file, params=get_var, verify=False)

    print(format_text('r.status_code is: ',r.status_code))
    #print(format_text('r.headers is: ',r.headers))


    #print(format_text('r.cookies is: ',r.cookies))
    #print(format_text('r.text is: ',r.text))
    #time.sleep(1)
"""



for i, line in enumerate(open(mysql_log_file)):
    for match in re.finditer(pattern_mysql, line):    
        print('Found on line %s: %s' % (i+1, match.group()))


