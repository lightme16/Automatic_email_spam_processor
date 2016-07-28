# EMAIL AUTOMATION SCRIPT INSTRUCTIONS

This script will helps you automate your daily routine work with classification of spam letter in mailbox. Comparable with Gmail, Yahoo and Outlook. 

## How to use it? 


First of all, you need to set up config file named “imap_monitor.ini”. You shouldn’t edit any source code, because you can set script only with this file. It text file and you can open in from Notepad. Here is an example of imap_monitor.ini:

```h
[imap]
;    Outlook
;host = imap-mail.outlook.com
;smtp_server = smtp-mail.outlook.com
;
;    Gmail
;host = imap.gmail.com
;smtp_server = smtp.gmail.com
;
;    Yahoo
;host = imap.mail.yahoo.com
;smtp_server = smtp.mail.yahoo.com
host = imap.gmail.com
smtp_server = smtp.gmail.com
username = your_login@gmail.com
password = 
ssl = True
folder = work

[autoreply]
reply_address = your_friend@gmail.com

[path]
download = C:\Users\Alex\PycharmProjects\email_manager\downloads
```


##### To start work you have to do several tasks:
1) Enter IMAP and STMP address of your mailbox. There are examples addresses for Gmail, Yahoo and Outlook , so you just need to pick up one. In general, the script is ought to support all most popular mailboxes, so if you need to add another one, you just need to paste right data in the config. NOTE: some email providers don’t allow use IMAP and STMP by defaulf. In this case, you need to manually turn on it on the settings of your mailbox.
2) Enter your login and password.
3) Choose the folder name you are going to track. Note, that folders names are case sensitive! 
4) Important! You need to create 3 additional folders in your mailbox with names legit, phishing and spam. The script will moves emails to thease folers and if one of them isn’t exists you will get an error! Note, that folders names are case sensitive! 
5) Insert am email address which will be autorepied. Enter only one!
6) Enter the path where attachment should be downloaded. 

How it works?
The script enter into infinite loop
1) in loop in tries to login into mail account
2) check for new messages
3) if new messages exist it pass it one by one to the processing function. All manipulations happens there

More about processing function:

1) parses sender and subject 
2) check whether sender and subject  are already in database(txt file)
  2.1) IF True: autoreply to the email address you specified in the config file with template like  
                 "ANALISYS. Email from steven@upwork.com with subject 'Scripts Expert' is _ legit". 
   Then script go to another new email
3) Saves attachments to the scientific folder.(API check could be developed in the future)
4)  Parses all URLs from email to check with VirusTotal. Gets the results
5) Grab the result and ask you for a conformation in command line.
6)  Copies an email in specific folder on you mailbox according your decision. 
7) Saves your mark, sender and subject to the database 

all this manipulations is applied to the every new message. 
In no new messages in the folder then script just check it for new ones with a delay(you can set it)

Download script data and extract to any folder.
Install Python 2.7 and pip.
Install all dependencies by doing next: ```$pip install -r /YOUR/PATH/TO/requirements.txt ```
Run the script ```$python main.py```
