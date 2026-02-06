# -------------------------------------------------------------
# File Name: crl_verifier
#
# Name: Itai Shamay
# Date: 2/6/2026
# 
# -------------------------------------------------------------

from cryptography import x509
from cryptography.x509 import ObjectIdentifier
from colorama import Fore, Back, init
import requests
import json
from datetime import datetime, timedelta, timezone

init(autoreset=True)

def generate_windows_events(log_content, status_code):
    """
        Generate windows event logs based on CRL status.
        
        Keyword arguments:
        log_content -- Description of CRL status
        status_code -- Status of the CRL File
    """

    import win32evtlogutil
    import win32evtlog

    # Tries creating Event Source if doesn't exist
    try:
        win32evtlogutil.AddSourceToRegistry(
            appName="CRL Monitoring Script",
            eventLogType="Application"
        )
    
    # Incase source already exists
    except:
        print(f"Event Source {YELLOW}EXISTS.")

    # Checks whether status code means that the CRL (or LB is 5) is valid
    if status_code in [1, 5]:
        event_type = win32evtlog.EVENTLOG_INFORMATION_TYPE

    # Checks whether status code means CRL is due to expire
    elif status_code == 2:
        event_type = win32evtlog.EVENTLOG_WARNING_TYPE

    # Checks whether status code means CRL is expired (or LB is unaccessible)
    elif status_code in [3, 4, 6, 10]:
        event_type = win32evtlog.EVENTLOG_ERROR_TYPE
    else:
        event_type = win32evtlog.EVENTLOG_ERROR_TYPE

    # Create the event and add it to the event source
    win32evtlogutil.ReportEvent(
        appName="CRL Monitoring Script",
        eventID=status_code,
        eventType=event_type,
        strings=[log_content],
        data=None
    )


def datetime_to_unix(date):
    """
        Converts Date to Unix timestamp.

        Keyword arguments:
        date -- Date object

        Returns:
        timestamp
    """

    return int(date.timestamp())

def clear_PROM_log():
    """ Fetches the Prometheus text file, and clears it. """

    try:
        with open("C:/Program Files/windows_exporter/textfile_input/crl_status.txt", 'w+') as prom_file:
            prom_file.write("")
    except FileNotFoundError:
        import os
        os.makedirs(os.path.dirname("C:/Program Files/windows_exporter/textfile_input/crl_status.txt"))

def write_PROM_log(crl_file:str, creation_date_timestamp:int, overlapping_delta_timestamp:int, expiration_date_timestamp:int, status_code: int):
    """
        Writes current event into Prometheus textfile, for it to be picked up by the exporter

        Keyword arguments:
        crl_file -- CRL file name
        creation_date_timestamp -- The Unix timestamp of the Creation Day of the file
        overlapping_delta_timestamp -- The Unix timestamp of the day of replacement of the CRL
        expiration_date_timestamp -- The Unix timestamp of the Expiration Day of the file
        status_code -- Represents the status of the CRL
    """

    crl_file = crl_file.replace(".crl", "")
    prom_log_format = f"""
# HELP crl_status Provides a viewpoint about the CRL
# TYPE crl_status gauge
crl_status{{crl_name="{crl_file}"}} {status_code}
crl_creation_date{{crl_name="{crl_file}"}} {creation_date_timestamp}
crl_overlapping_date{{crl_name="{crl_file}"}} {overlapping_delta_timestamp}
crl_expiration_date{{crl_name="{crl_file}"}} {expiration_date_timestamp}
"""

    try:
        with open("C:/Program Files/windows_exporter/textfile_input/crl_status.txt", 'a+') as prom_file:
            prom_file.write(prom_log_format)

    except FileNotFoundError:
        import os
        os.makedirs(os.path.dirname("C:/Program Files/windows_exporter/textfile_input/crl_status.txt"))

        with open("C:/Program Files/windows_exporter/textfile_input/crl_status.txt", 'a+') as log_file:
            log_file.write(prom_log_format)

def write_log(http_path, log_content, status_code):
    """
        Writes a custom log into path (default='C:/PKI/crl_monitoring.txt').

        Keyword arguments:
        http_path -- Full CRL file path (CRL URL)
        log_content -- CRL Status description
        status_code -- Status of the CRL file
    """

    log_format = f"""
{http_path}:
---- {log_content}
---- status code: {status_code}
---- time {datetime.now()}
"""

    try:
        with open("C:/PKI/crl_monitoring.txt", 'a') as log_file:
            log_file.write(log_format)
    except FileNotFoundError:
        import os
        os.makedirs(os.path.dirname("C:/PKI/crl_monitoring.txt"))

        with open("C:/PKI/crl_monitoring.txt", 'a') as log_file:
            log_file.write(log_format)

def validate_crl(cdp_server, path_type, crl_name):
    """
        Builds the full CRL URL, downloads the CRL and examines it.

        Keyword arguments:
        cdp_server -- Name of the CDP server storing the CRL
        path_type -- Path type to navigate to (CertEnroll / CertData)
        crl_name -- Name of the CRL file
    """

    full_path = f"https://{cdp_server}/{path_type}/{crl_name}"
    crl_request = requests.get(full_path)
    
    # Checks whether web request status code is anything but 200 (OK)
    if (int(crl_request.status_code) != 200):
        crl_status = 4
        log_message = "CRL is UNREACHABLE."

        print(f"CRL is {Back.RED}UNREACHABLE{Back.RESET}.")
        print(f"{Fore.YELLOW}CDP Server: {cdp_server}, CRL: {crl_name}")
        write_log(full_path, "CRL is unreachable", crl_request.status_code)

    else:

        # Parses the CRL file
        crl_data = x509.load_der_x509_crl(crl_request.content)

        creation_date = crl_data.last_update_utc
        expiration_date = crl_data.next_update_utc
        
        # Tries fetching CRL's Next Publish extension
        try:
            overlapping_delta = crl_data.extensions.get_extension_for_oid(ObjectIdentifier("1.3.6.1.4.1.311.21.4")).value.value

        except x509.ExtensionNotFound:
            overlapping_delta = expiration_date - timedelta(days=3)

        current_date = datetime.now(timezone.utc)

        # Checks whether CRL has reached Overlapping state by passing the date
        if (current_date <= overlapping_delta):
            crl_status = 1
            log_message = f"CRL '{crl_name}' is VALID, and is fresh until {overlapping_delta}."

            replacement_delta = abs(overlapping_delta - current_date).days
            print(f"CRL is {Back.GREEN}VALID{Back.RESET} and should be replaced in {Back.GREEN}{replacement_delta} days{Back.RESET}.")
            print(f"{Fore.YELLOW}CDP Server: {cdp_server}, CRL: {crl_name}")

        # Checks whether CRL has reached overlapping state, while staying smaller than Expiration
        elif (current_date > overlapping_delta and current_date <= expiration_date):
            crl_status = 2
            log_message = f"CRL '{crl_name}' entered OVERLAPPING STATE, and will expire at {expiration_date}"

            expiration_delta = abs(expiration_date - current_date).days
            print(f"CRL is {Back.YELLOW}LAPSING{Back.RESET} and will expire in {Back.YELLOW}{expiration_delta} days{Back.RESET}.")
            print(f"{Fore.YELLOW}CDP Server: {cdp_server}, CRL: {crl_name}")

        # Checks whether the CRL file is expired
        elif (current_date > expiration_date):
            crl_status = 3
            log_message = f"CRL '{crl_name}' is EXPIRED since {expiration_date}"

            past_expiration_delta = abs(current_date - expiration_date).days
            print(f"CRL is {Back.RED}EXPIRED{Back.RESET}, and has been expired for {Back.RED}{past_expiration_delta} days{Back.RESET}.")
            print(f"{Fore.YELLOW}CDP Server: {cdp_server}, CRL: {crl_name}")

        else:
            crl_status = 10
            print(f"Script is {Back.RED}BROKEN </3")

    write_log(http_path=full_path, log_content=log_message, status_code=crl_status)
    clear_PROM_log()
    write_PROM_log(
        crl_file=crl_name, 
        creation_date_timestamp=datetime_to_unix(creation_date),
        overlapping_delta_timestamp=datetime_to_unix(overlapping_delta),
        expiration_date_timestamp=datetime_to_unix(expiration_date),
        status_code=crl_status
    )

    generate_windows_events(log_content=log_message, status_code=crl_status)

validate_crl("c.pki.goog", "we2", "yK5nPhtHKQs.crl")
