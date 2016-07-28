import os
import imaplib2 as imaplib
import os.path as path
import sys
import traceback
import logging
from logging.handlers import RotatingFileHandler
import ConfigParser
import email
import time
import re
import VirusTotal
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText


# Setup the log handlers to stdout and file.
log = logging.getLogger('Logger')
log.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    '%(asctime)s | %(name)s | %(levelname)s | %(message)s'
)
handler_stdout = logging.StreamHandler(sys.stdout)
handler_stdout.setLevel(logging.DEBUG)
handler_stdout.setFormatter(formatter)
log.addHandler(handler_stdout)
handler_file = RotatingFileHandler(
    'logger.log',
    mode='a',
    maxBytes=1048576,
    backupCount=9,
    encoding='UTF-8',
    delay=True
)
handler_file.setLevel(logging.DEBUG)
handler_file.setFormatter(formatter)
log.addHandler(handler_file)

# mail_servers_data = {'outlook': ['imap-mail.outlook.com', 'smtp-mail.outlook.com'],
#                      'gmail':['imap.gmail.com','smtp.gmail.com'], 'yahoo':['imap.mail.yahoo.com', 'smtp.mail.yahoo.com']}

def choose_mode():
    while True:
        try:
            mode = int(raw_input("Choose mode: web[1] or desktop(NO AVALIBLE NOW)[2]? Enter a number: "))
            if mode == 1:
                return 'web'
            if mode == 2:
                app = int(raw_input("Choose mail client: Lotus[1] or Outlook[2]? Enter a number: "))
                if app == 1:
                    return 'lotus'
                if app == 2:
                    return 'outlook'
        except:
            print 'Choose right mode! Enter a number of mode.'
def save_attachment(mail_, download_):
    """
    Given a message, save its attachments to the specified
    download folder (default is /tmp)

    return: file path to attachment
    """
    print "Checking attachments..."
    try:
        att_path = "No attachment found."
        for part in mail_.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get('Content-Disposition') is None:
                continue

            filename = part.get_filename()
            att_path = path.join(download_, filename)

            if not path.isfile(att_path):
                fp = open(att_path, 'wb')
                fp.write(part.get_payload(decode=True))
                fp.close()
            print "Attachments downloaded!"
    except:
        print "No attachments!"
    return att_path


def security_analysis(urls_list, mail_data):
    if urls_list:
        results = dict()
        for site in urls_list:
            isClear, siteType = VirusTotal.check_url(site)
            results[site] = (isClear, siteType)
            print site, isClear, siteType
        print "Security_analysis results. Is processedd?", results
        illness_types = []
        for key, value in results.items():
            if not value[0]:
                illness_types.append(value[1])
        print "illness_types",illness_types
        if len(illness_types) == 0:
            return u'clean site'
        else:
            return VirusTotal.most_common(illness_types)
    else:
        print "No any URLs"
        return u'clean site'

def parse_urls_from_mail(mail_):
    url_list = re.findall("(?P<url>https?://[^\s]+)", str(mail_))
    url_list = [domain.split('/')[2] for domain in url_list]
    unique_url_list = set(url_list)
    return list(unique_url_list)


def confirm_analysis_results(security_analysis_results, sender, subject):
    config_file = open('config.ini', 'r+')
    config = ConfigParser.SafeConfigParser()
    config.readfp(config_file)
    mail_types = config.get('classification', 'classification_list').split(',')
    mail_types = 'legit', 'phishing', 'spam'

    if security_analysis_results.strip() ==('clean site'):
        security_analysis_results = mail_types[0]
    if security_analysis_results.strip() == 'phishing site':
        security_analysis_results = mail_types[1]
    if security_analysis_results.strip() == 'malware site' or security_analysis_results.strip() == 'malicious site' \
            or security_analysis_results.strip() == 'suspicious site':
        security_analysis_results = mail_types[2]

    while True:
        answer = raw_input('The email from %s with subject %s marked as %s.\n Do you agree?[Y]/[n]\n'
                           % (sender, subject, security_analysis_results))
        if answer.lower() == 'y':
            return security_analysis_results
        if answer.lower() == 'n':
            count = 1
            for item in mail_types:
                print item, ' [', count, ']   '
                count += 1
            selected_type = raw_input('Please, choose the right type. Enter number or right item: ')
            if selected_type:
                print 'mail_types[int(selected_type)-1] ', mail_types[int(selected_type)-1]
                try:
                    return mail_types[int(selected_type)-1]
                except:
                    print "Error. Please, input integer corresponding to mail type!"

def parse_uid(data):
    pattern_uid = re.compile('\d+ \(UID (?P<uid>\d+)\)')
    match = pattern_uid.match(data)
    return match.group('uid')

def move_to_email_folder(mail_, label, num, imap):
    print 'Moving_an_email_to the newfolder...'
    resp, data = imap.fetch(num, "(UID)")
    #print data, resp
    msg_uid = parse_uid(data[0])
    #print "msg_uid", msg_uid
    result = imap.uid('MOVE', msg_uid, label)
    #print result

    if result[0] == 'OK':
        imap.expunge()


def save_results(sender, subject, security_analysis_results):
    print "Results saved to the database!"
    with open('email_history.txt','a') as file:
        file.write("Email from %s with subject '%s' is _ %s \n" % (sender, subject, security_analysis_results))


def check_in_spamlist(sender, subject):
    print 'check_in_spamlist', sender, subject
    if not os.path.exists('email_history.txt'):
        with open('email_history.txt', 'w'):
            print "Creating email_history.txt..."
    with open('email_history.txt', 'r') as file:
        for line in file.readlines():
            if sender in line:
                print "This SENDER is already in database! Skipping it"
                if subject in line:
                    print "This SUBJECT is already in database! Skipping it"
                    email_type = line.split('is _ ')[1]
                    return email_type
        return False


def autoreply(sender, subject, reply_address, type):
    try:
        config_file = open('config.ini', 'r+')
        config = ConfigParser.SafeConfigParser()
        config.readfp(config_file)
        username = config.get('imap', 'username')
        password = config.get('imap', 'password')
        smtp_server = config.get('imap', 'smtp_server')

        template = open("templates/%s.txt" % type.strip(), 'r').read()
        greeting = "Hello, %s\n" % reply_address

        msg = MIMEMultipart()
        msg['From'] = str(username)
        msg['To'] = str(reply_address)
        msg['Subject'] = "ANALYSIS " + subject
        message = greeting + template
        msg.attach(MIMEText(message))

        mailserver = smtplib.SMTP(smtp_server, 587)
        # identify ourselves to smtp gmail client
        mailserver.ehlo()
        # secure our email with tls encryption
        mailserver.starttls()
        # re-identify ourselves as an encrypted connection
        mailserver.ehlo()

        mailserver.login(username, password)
        mailserver.sendmail(username, reply_address, msg.as_string())

        mailserver.quit()
        print "Autoreplied succesfully!"
    except Exception, e:
        print 'Cant send reply'
        print e

def process_email(mail_, download_, num, imap, reply_address):
    """Email processing to be done here. mail_ is the Mail object passed to this
    function. download_ is the path where attachments may be downloaded to.
    log_ is the logger object.
    """
    sender, subject = email.utils.parseaddr(mail_['From'])[1], mail_['Subject']
    print "sender %s, subject %s"% (sender, subject)
    type = check_in_spamlist(sender, subject)
    if type:
        autoreply(sender, subject, reply_address, type)
        return

    mail_data = save_attachment(mail_, download_)
    urls_list = parse_urls_from_mail(mail_)
    security_analysis_results = security_analysis(urls_list, mail_data)
    confirm = confirm_analysis_results(security_analysis_results, sender, subject)

    if confirm:
        #move_to_email_folder(mail_,confirm, num, imap)
        save_results(sender, subject, confirm)

    return 'Done'

def main():
    #TODO interactive mail server set up
    log.info('Script started!')
    while True:
        # <--- Start of configuration section

        mode = choose_mode()
        # Read config file - halt script on failure
        try:
            config_file = open('config.ini', 'r+')
        except IOError:
            log.critical('configuration file is missing')
            break
        config = ConfigParser.SafeConfigParser()
        config.readfp(config_file)

        # Retrieve IMAP username - halt script if missing
        try:
            username = config.get('imap', 'username')
        except ConfigParser.NoOptionError:
            log.critical('no IMAP username specified in configuration file')
            break

        # Retrieve IMAP password - halt script if missing
        try:
            password = config.get('imap', 'password')
        except ConfigParser.NoOptionError:
            log.critical('no IMAP password specified in configuration file')
            break

        # Retrieve IMAP host - halt script if section 'imap' or value
        # missing
        try:
            host = config.get('imap', 'host')
        except ConfigParser.NoSectionError:
            log.critical('no "imap" section in configuration file')
            break
        except ConfigParser.NoOptionError:
            log.critical('no IMAP host specified in configuration file')
            break

        # Retrieve IMAP SSL setting - warn if missing, halt if not boolean
        try:
            ssl = config.getboolean('imap', 'ssl')
        except ConfigParser.NoOptionError:
            # Default SSL setting to False if missing
            log.warning('no IMAP SSL setting specified in configuration file')
            ssl = False
        except ValueError:
            log.critical('IMAP SSL setting invalid - not boolean')
            break

        # Retrieve IMAP folder to monitor - warn if missing
        try:
            folder = config.get('imap', 'folder')
        except ConfigParser.NoOptionError:
            # Default folder to monitor to 'INBOX' if missing
            log.warning('no IMAP folder specified in configuration file')
            folder = 'INBOX'

        # Retrieve address for auto-replying
        try:
            reply_address = config.get('autoreply', 'reply_address')
        except ConfigParser.NoSectionError:
            log.critical('no "autoreply" section in configuration file')
            break
        except ConfigParser.NoOptionError:
            log.critical('noreply_address specified in configuration file')
            break

        # Retrieve path for downloads - halt if section of value missing
        try:
            download = config.get('path', 'download')
        except ConfigParser.NoSectionError:
            log.critical('no "path" section in configuration')
            break
        except ConfigParser.NoOptionError:
            # If value is None or specified path not existing, warn and default
            # to script path
            log.warn('no download path specified in configuration')
            download = None
        finally:
            download = download if (
                download and path.exists(download)
            ) else path.abspath(__file__)
        log.info('setting path for email downloads - {0}'.format(download))

        while True:
            # <--- Start of IMAP server connection loop
            if mode == 'web':
                # Attempt connection to IMAP server
                log.info('connecting to IMAP server - {0}'.format(host))
                try:
                    imap = imaplib.IMAP4_SSL(host)
                except Exception:
                    # If connection attempt to IMAP server fails, retry
                    etype, evalue = sys.exc_info()[:2]
                    estr = traceback.format_exception_only(etype, evalue)
                    logstr = 'failed to connect to IMAP server - '
                    for each in estr:
                        logstr += '{0}; '.format(each.strip('\n'))
                    log.error(logstr)
                    time.sleep(10)
                    continue
                log.info('server connection established')

                # Attempt login to IMAP server
                log.info('logging in to IMAP server - {0}'.format(username))
                try:
                    result = imap.login(user=username, password=password)
                    log.info('login successful - {0}'.format(result))
                except Exception:
                    # Halt script when login fails
                    etype, evalue = sys.exc_info()[:2]
                    estr = traceback.format_exception_only(etype, evalue)
                    logstr = 'failed to login to IMAP server - '
                    for each in estr:
                        logstr += '{0}; '.format(each.strip('\n'))
                    log.critical(logstr)
                    break

                # Select IMAP folder to monitor
                log.info('selecting IMAP folder - {0}'.format(folder))
                try:
                    result = imap.select(folder)
                    log.info('folder selected')
                except Exception:
                    # Halt script when folder selection fails
                    etype, evalue = sys.exc_info()[:2]
                    estr = traceback.format_exception_only(etype, evalue)
                    logstr = 'failed to select IMAP folder - '
                    for each in estr:
                        logstr += '{0}; '.format(each.strip('\n'))
                    log.critical(logstr)
                    break

            # Retrieve and process all unread messages. Should errors occur due
            # to loss of connection, attempt restablishing connection
            while True:
                try:
                    (retcode, messages) = imap.search(None, '(UNSEEN)')
                    if retcode == 'OK' and messages[0]:
                        for num in messages[0].split(' '):
                            print 'Processing %d emails...' % len(messages[0].split(' '))
                            try:
                                typ, data = imap.fetch(num, '(RFC822)')
                                mail = email.message_from_string(data[0][1])

                                process_email(mail, download, num, imap, reply_address)
                                log.info('Email processed!')
                                # if host == 'imap.mail.yahoo.com':
                                #     print "Exit_loop"
                                #     exit_loop = True
                            except Exception, e:
                                print e
                                log.error('failed to fetch email - {0}')
                                continue
                    else:
                        log.info("No new emails!")
                    time.sleep(4)
                except Exception,e:
                    print e
                    log.error('failed to search an email - {0}')
                    #TODO move delay to ettings
                    time.sleep(4)
                    continue
            if mode == 'lotus':
                print 'Lotus integration under developing!'

            if mode == 'outlook':
                print 'Outlook integration under developing!'
                    # End of configuration section --->
        break
    log.info('script stopped ...')

if __name__ == '__main__':
    main()