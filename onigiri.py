# onigiri.py - remote malware triage script using F-Response and openioc_scan
# Copyright (c) 2015 Takahiro Haruyama (@cci_forensics)
# http://takahiroharuyama.github.io/

g_x86_python_path = r"C:\Python27x86\python.exe"
g_ftk_path = r"C:\tmp\ftkimager\ftkimager.exe"
g_vol_path = r"C:\volatility\vol.py"
g_vol_plugins_path = r"" # set empty if not needed

from datetime import datetime
from glob import glob
from time import sleep
import argparse, os, sys, re, subprocess, logging, hashlib

import win32com.client, requests
from Registry import Registry
import colorama
colorama.init()

g_color_term = colorama.Fore.MAGENTA
g_color_detail = colorama.Fore.CYAN

requests.packages.urllib3.disable_warnings() # for FlexDisk self-signed certificates
IO_BLOCKSIZE = 1024 * 1024 * 100
g_profiles = {
                6000:{'Windows Vista':'VistaSP0'},
                6001:{'Windows Vista':'VistaSP1', 'Windows Server 2008':'Win2008SP1'},
                6002:{'Windows Vista':'VistaSP2', 'Windows Server 2008':'Win2008SP2'},
                7600:{'Client':'Win7SP0', 'Server':'Win2008R2SP0'},
                7601:{'Client':'Win7SP1', 'Server':'Win2008R2SP1'},
                9200:{'Client':'Win8SP0', 'Server':'Win2012'},
                9600:{'Client':'Win8SP1', 'Server':'Win2012R2'}
            }
g_all_cats = ['sysreg', 'userreg', 'mft', 'prefetch', 'evtx', 'amcache', 'journal']

class FRESbase(object):
    def __init__ (self, f, verbose, out_path, skip, ftk_path):
        self.logger = logging.getLogger(type(self).__name__)
        set_logger(self.logger, verbose, out_path, '%(name)s:%(levelname)s: %(message)s')
        self.f = f
        self.out_path = out_path
        self.skip = skip
        self.ftk_path = ftk_path

    def acquire_ram(self, victim):
        targets = victim.Targets
        pm = re.compile(r'.*:pmem$')
        self.logger.debug('Issue Discovery Request...')
    	for target in targets:
            if pm.search(target.TargetName):
                self.logger.info('Physical Memory found: {0} (DiskType={1})'.format(target.TargetName, target.DiskType))

                dest_path = self.out_path + "\\" + victim.MachineNameOrIP
                img_path = dest_path + "\\pmem.dd4.001"
                if self.skip and os.path.exists(img_path):
                    self.logger.info('the RAM image already exists, so skip the acquisition ({0})'.format(img_path))
                    continue
                if not os.path.exists(dest_path):
                    os.mkdir(dest_path)

                try:
                    self.logger.debug('Login to F-Response Disk...')
                    target.Login()
                except win32com.client.pywintypes.com_error:
                    self.logger.critical('Login to F-Response Disk failed. Aborted in the previous acquisition? Please check the status on GUI console and logout the pmem manually.')
                    sys.exit(1)
                #login_check = target.PhysicalDiskMapping
                #device = target.PhysicalDiskName
                if target.PhysicalDiskMapping == -1:
                    self.logger.critical('PhysicalDiskMapping failed due to timing issue. Simply try again.')
                    sys.exit(1)
                device = r'\\.\PhysicalDrive' + str(target.PhysicalDiskMapping)
                self.logger.info('acquiring mapped physical memory ({0})...'.format(device))
                cmd = [self.ftk_path, device, dest_path + "\\pmem"]
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout_data, stderr_data = proc.communicate()
                '''
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                for line in iter(proc.stdout.readline, ''):
                    self.logger.info(line.rstrip())
                proc.stdout.close()
                proc.wait()
                '''
                self.logger.debug('Remove F-Response Disk...')
                target.Logout()

                self.logger.debug('returncode={0}'.format(proc.returncode))
                if proc.returncode == 1:
                    self.logger.error("check with the cmdline: {0}".format(cmd))
                    self.logger.error(stderr_data)
                    sys.exit()
                self.logger.info('RAM image saved: {0}'.format(img_path))

    def get_file_uri(self, uri, path, expanded_path):
        entry = path.split('\\')[0].lower()
        leftover = '\\'.join(path.split('\\')[1:])
        node = entry if entry != '*' else ''

        self.logger.debug('traversing URI: {0}'.format(uri))
        response = requests.get(uri, auth=(self.user, self.pwd), verify=False)
        results = response.json()['response']['contents']

        for res in results:
            if (res['name'].lower() == entry or entry == '*') and res['type'] == 'file' and res['state'] != 'realloc' and leftover == '':
                #self.logger.debug('file URI found: {0}'.format(res['uri']))
                yield res['uri'], expanded_path + res['name']
            elif (res['name'].lower() == entry or (entry == '*' and (res['name'] not in ('..', '..-$TXF_DATA')))) and \
                res['type'] == 'dir' and res['state'] != 'realloc' and leftover != '' and res['uri'].find('enc=json') != -1:
                for child_uri, child_expanded_path in self.get_file_uri(res['uri'], leftover, expanded_path + res['name'] + '\\'):
                    #self.logger.debug('walking dir URI: {0}'.format(child_uri))
                    yield child_uri, child_expanded_path

    def acquire_file(self, ip, vol_name, vol_uri, path):
        for uri, expanded_path in self.get_file_uri(vol_uri, path, ''):
            self.logger.debug('acquiring file... (uri="{0}", expanded_path="{1}")'.format(uri, expanded_path))
            response = requests.get(uri, auth=(self.user, self.pwd), verify=False)
            data = response.content # safe even if the file size is too big? not sure..

            dest_path = self.out_path + "\\" + ip + "\\" + vol_name + "\\" + expanded_path
            if self.skip and os.path.exists(dest_path):
                self.logger.info('the file already exists, so skip the acquisition ({0})'.format(dest_path))
                continue
            dest_folder = os.path.dirname(dest_path)
            if not os.path.exists(dest_folder):
                os.makedirs(dest_folder)
            with open(dest_path, 'wb') as f:
                f.write(data)
            self.logger.info('file saved: {0}'.format(dest_path))

    def get_tgt(self, uri):
        response = requests.get(uri, auth=(self.user, self.pwd), verify=False)
        tgts = response.json()['response']['contents']
        for tgt in tgts:
            yield tgt['name'], tgt['uri']

    def acquire_category_files(self, victim, file_cats, scan):
        ip = victim.MachineNameOrIP
        for tgt_name, tgt_uri in self.get_tgt('https://{0}:3261/flexd?enc=json'.format(ip)):
            self.logger.debug('volume target={0}'.format(tgt_name))
            for cat in file_cats:
                if cat == 'sysreg':
                    self.acquire_file(ip, tgt_name, tgt_uri, r"Windows\System32\config\SOFTWARE")
                    self.acquire_file(ip, tgt_name, tgt_uri, r"Windows\System32\config\SYSTEM")
                    self.acquire_file(ip, tgt_name, tgt_uri, r"Windows\System32\config\SAM")
                    self.acquire_file(ip, tgt_name, tgt_uri, r"Windows\System32\config\SECURITY")
                elif cat == 'userreg':
                    self.acquire_file(ip, tgt_name, tgt_uri, r"Users\*\NTUSER.DAT")
                    self.acquire_file(ip, tgt_name, tgt_uri, r"Users\*\AppData\Local\Microsoft\Windows\UsrClass.dat")
                elif cat == 'mft':
                    self.acquire_file(ip, tgt_name, tgt_uri, r"$MFT")
                elif cat == 'prefetch':
                    self.acquire_file(ip, tgt_name, tgt_uri, r"Windows\Prefetch\*")
                    self.acquire_file(ip, tgt_name, tgt_uri, r"Windows\Prefetch\ReadyBoot\*")
                elif cat == 'evtx':
                    self.acquire_file(ip, tgt_name, tgt_uri, r"Windows\System32\winevt\Logs\Security.evtx")
                    self.acquire_file(ip, tgt_name, tgt_uri, r"Windows\System32\winevt\Logs\System.evtx")
                    self.acquire_file(ip, tgt_name, tgt_uri, r"Windows\System32\winevt\Logs\Application.evtx")
                    # RDP logs
                    self.acquire_file(ip, tgt_name, tgt_uri, r"Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx")
                    self.acquire_file(ip, tgt_name, tgt_uri, r"Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx")
                    # scheduled tasks
                    self.acquire_file(ip, tgt_name, tgt_uri, r"Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx")
                    self.acquire_file(ip, tgt_name, tgt_uri, r"Windows\Tasks\SCHEDLGU.TXT")
                elif cat == 'amcache':
                    self.acquire_file(ip, tgt_name, tgt_uri, r"Windows\AppCompat\Programs\Amcache.hve")
                elif cat == 'journal':
                    self.acquire_file(ip, tgt_name, tgt_uri, r"$LogFile")
                    self.acquire_file(ip, tgt_name, tgt_uri, r"$Extend\$UsnJrnl") # $J
            if 'sysreg' not in file_cats and scan:
                # volatility needs the profile from sysreg
                self.acquire_file(ip, tgt_name, tgt_uri, r"Windows\System32\config\SOFTWARE")

class FREScc(FRESbase):
    def __init__ (self, f, verbose, out_path, skip, ftk_path, conf_path):
        super(FREScc, self).__init__(f, verbose, out_path, skip, ftk_path)
        self.f.FCCConfigureFileLocation = conf_path
        self.f.LoadConfig()
        self.user = self.f.FRESUsername
        self.pwd = self.f.FRESPassword

    def acquire(self, ram, file_cats, scan):
        activeclients = self.f.ActiveClients
        self.logger.debug('Discover F-Response Disks...')
        for ac in activeclients:
            self.logger.info('ActiveClient found: {0} (Platform={1})'.format(ac.MachineNameOrIP, ac.Platform))
            if ram or scan:
                self.logger.info('Starting RAM Acquisition')
                self.acquire_ram(ac)
            if len(file_cats) != 0 or scan:
                self.logger.info('Starting File Acquisition')
                self.acquire_category_files(ac, file_cats, scan)

class FRESemc(FRESbase):
    def __init__ (self, f, verbose, out_path, skip, ftk_path, machine_list, user, domain, password):
        super(FRESemc, self).__init__(f, verbose, out_path, skip, ftk_path)
        self.creds = self.f.Credentials
        self.creds.add(user, domain, password)
        self.logger.debug('credential added: user={0}, domain={1}, password={2}'.format(user, domain, password))
        self.computers = self.f.Machines
        for machine in machine_list:
            self.computers.add(machine)
        self.logger.debug('machine(s) added: {0}'.format(machine_list))
        self.user = self.f.FRESUsername
        self.pwd = self.f.FRESPassword

    def acquire(self, ram, file_cats, scan):
        for computer in self.computers:
            if computer.Status != 3:
                self.logger.info('Directly-deploying agent into the victim machine: {0} (Status={1})...'.format(computer.MachineNameOrIP, computer.Status))
                if computer.Status == 0:
                    self.logger.critical('Windows admin auth failed. Please check the account username/password.')
                    sys.exit(1)
                if computer.Status == 1:
                    self.logger.debug('installing F-Response...')
                    computer.InstallFResponse()
                    #self.logger.debug('waiting for the installation (sleep 10sec)...')
                    #sleep(10)
                if computer.Status == 2:
                    self.logger.debug('starting F-Response...')
                    computer.StartFResponse()
                    #self.logger.debug('waiting for the start (sleep 5sec)...')
                    sleep(5)

            self.logger.info('Agent ready: {0} (Platform={1}, Status={2})'.format(computer.MachineNameOrIP, computer.Platform, computer.Status))
            if ram or scan:
                self.logger.info('Starting RAM Acquisition')
                self.acquire_ram(computer)
            if len(file_cats) != 0 or scan:
                self.logger.info('Starting File Acquisition')
                self.acquire_category_files(computer, file_cats, scan)

            self.logger.info('stopping/uninstalling agent...')
            computer.StopFResponse()
            computer.UnInstallFResponse()

def set_logger(logger, verbose, out_path, fmt):
    handler = logging.StreamHandler()
    file_handler = logging.FileHandler(out_path + '\\output.log', 'a+')
    logger.addHandler(handler)
    logger.addHandler(file_handler)

    formatter = logging.Formatter(fmt)
    #formatter = logging.Formatter('%(name)s:%(levelname)s: %(message)s')
    handler.formatter = formatter
    file_handler.formatter = formatter

    logger.setLevel(logging.INFO)
    handler.setLevel(logging.INFO)
    file_handler.setLevel(logging.INFO)
    if verbose:
        logger.setLevel(logging.DEBUG)
        handler.setLevel(logging.DEBUG)
        file_handler.setLevel(logging.DEBUG)

def calculate_hashes(out_path):
    with open(out_path + '\\sha1_hashes.txt', 'w') as lf:
        t = datetime.now().strftime('%Y/%m/%d %H:%M:%S')
        lf.write('Acquisition Time: {0}\n\n'.format(t))
        lf.write('SHA1{0}Size{1}Path\n'.format('\t'*6, '\t'*2))
        for root, dirs, files in os.walk(out_path):
            for file_ in files:
                if file_ == 'sha1_hashes.txt' or file_.find('pmem.') != -1:
                    continue
                full_path = os.path.join(root, file_)
                size = os.path.getsize(full_path)
                with open(full_path, 'rb') as f:
                    data = f.read()
                hash_ = hashlib.sha1(data).hexdigest()
                lf.write('{0}\t{1:11d}\t{2}\n'.format(hash_, size, full_path))

def get_profile(build_number, client_server_ident, arch):
    os_version = ''
    if build_number == 6000:
        os_version = g_profiles[6000]['Windows Vista']
    elif build_number == 6001 or build_number == 6002:
        if client_server_ident.find('Vista') != -1:
            os_version = g_profiles[build_number]['Windows Vista']
        else:
            os_version = g_profiles[build_number]['Windows Server 2008']
    else:
        os_version = g_profiles[build_number][client_server_ident]

    if arch.find('x86') != -1:
        return os_version + 'x86'
    else: #amd64
        return os_version + 'x64'

def openioc_scan(out_path, ioc_dir, verbose, python_path, vol_path, plugins_path):
    logger = logging.getLogger('openioc_scan')
    set_logger(logger, verbose, out_path, '%(message)s')

    for hostname in os.listdir(out_path):
        if os.path.isdir(out_path + '\\' + hostname):
            img_path = out_path + '\\' + hostname + '\\pmem.dd4.001'
            if not os.path.exists(img_path):
                logger.critical('Memory image not found in {0}'.format(img_path))
                return
            logger.info('IOC scan target: {0}'.format(hostname))
            for software_path in glob(out_path + '\\' + hostname + '\\*\\Windows\\System32\\config\\SOFTWARE'):
                if os.path.isfile(software_path):
                    reg = Registry.Registry(software_path)

                    try:
                        BuildLabEx = reg.open("Microsoft\\Windows NT\\CurrentVersion").value('BuildLabEx').value()
                        build_number, arch = BuildLabEx.split('.')[0], BuildLabEx.split('.')[2]
                        if int(build_number) < 6000:
                            logger.critical("The OS is not supported")
                            return
                        elif int(build_number) < 7600:
                            product_name = reg.open("Microsoft\\Windows NT\\CurrentVersion").value('ProductName').value()
                            logger.debug('identifying profile... (build_number={0}, product_name={1}, arch={2})'.format(build_number, product_name, arch))
                            profile = get_profile(int(build_number), product_name, arch)
                        else:
                            installation_type = reg.open("Microsoft\\Windows NT\\CurrentVersion").value('InstallationType').value()
                            logger.debug('identifying profile... (build_number={0}, installation_type={1}, arch={2})'.format(build_number, installation_type, arch))
                            profile = get_profile(int(build_number), installation_type, arch)
                    except Registry.RegistryValueNotFoundException:
                        logger.critical("Couldn't get registry values from {0}".format(software_path))
                        return
                    logger.info('Profile identified from SOFTWARE registry: {0}'.format(profile))

                    arg_profile = '--profile={0}'.format(profile)
                    arg_ioc_dir = '--ioc_dir={0}'.format(ioc_dir)
                    if plugins_path == '':
                        cmd = [python_path, vol_path, 'openioc_scan', arg_profile, arg_ioc_dir, '-f', img_path, '-e']
                    else:
                        cmd = [python_path, vol_path, 'openioc_scan', '--plugins={0}'.format(plugins_path), arg_profile, arg_ioc_dir, '-f', img_path, '-e']
                    logger.info('running openioc_scan...')
                    logger.info(' '.join(cmd))
                    #proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    #stdout_data, stderr_data = proc.communicate()
                    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    for line in iter(proc.stdout.readline, ''):
                        if line.find('>>> ') != -1:
                            line = colorama.Style.BRIGHT + g_color_term + line.rstrip() + colorama.Fore.RESET + colorama.Style.RESET_ALL
                        elif line.find('matched IOC term detail: ') != -1:
                            path = ':'.join(line.split(':')[1:])
                            line = 'matched IOC term detail:' + g_color_detail + path.rstrip() + colorama.Fore.RESET
                        logger.info(line.rstrip())
                    proc.stdout.close()
                    proc.wait()
                    logger.debug('returncode={0}'.format(proc.returncode))
                    if proc.returncode == 1:
                        logger.error("check with the cmdline: {0}".format(cmd))

def main():
    parser = argparse.ArgumentParser(description='onigiri.py - remote malware triage')
    parser.add_argument('output', help="folder path saving acquired memory image / files")
    parser.add_argument('-r', '--ram', action='store_true', help="acquire RAM")
    parser.add_argument('-f', '--files', help="acquire targeted file categories in disk (comma-delimited): {0} or all".format(','.join(g_all_cats)))
    parser.add_argument('-s', '--scan', action='store_true', help="acquire RAM then scan volatile IOCs")
    parser.add_argument('-i', '--ioc_dir', help="folder path including IOC files for openioc_scan")
    parser.add_argument('-p', '--python', help="path to x86 python (python.exe) used by volatility", default=g_x86_python_path)
    parser.add_argument('-t', '--ftk', help="path to ftkimager.exe", default=g_ftk_path)
    parser.add_argument('-o', '--vol', help="path to vol.py (volatility)", default=g_vol_path)
    parser.add_argument('-l', '--plugins', help="path to additional volatility plugins folder", default=g_vol_plugins_path)
    parser.add_argument('-v', '--verbose', action='store_true', help="print verbose messages")
    parser.add_argument('--skip', action='store_true', help="skip acquisition if RAM image or files exist")
    parser.add_argument('--version', action='version', version='%(prog)s 0.5')
    subparsers = parser.add_subparsers(dest='edition', help='F-Response editions')
    parser_cc = subparsers.add_parser('cc', help='Consultant or Consultant+Covert')
    parser_cc.add_argument('config', help="config folder path including fresponse.ini")
    parser_emc = subparsers.add_parser('emc', help='Enterprise')
    parser_emc.add_argument('machine', help="the victim machine IP address list (comma-delimited)")
    parser_emc.add_argument('user', help="admin user name at the victim machine")
    parser_emc.add_argument('password', help="the user password at the victim machine")
    parser_emc.add_argument('-d', '--domain', default="WORKGROUP", help="domain name the victim machine belongs to")

    args = parser.parse_args()
    logger = logging.getLogger('main')
    set_logger(logger, args.verbose, args.output, '%(name)s:%(levelname)s: %(message)s')
    logger.info('onigiri.py - remote malware triage')
    logger.debug('args: {0}'.format(args))

    if args.ram is False and args.files is None and args.scan is False:
        logger.error('Please specify your action: -r or -f [FILES] or -s')
        parser.print_help()
        return

    if args.edition == 'cc': # consultant or consultant+covert
        try:
            fcc = win32com.client.Dispatch("FCCCTRL.FCC")
        except win32com.client.pywintypes.com_error:
            logger.critical('Cannot access to F-Response Consultant Connector COM API')
            return
        else:
            logger.debug('F-Response Consultant or Consultant+Covert Edition COM API loaded')
            if args.config[-1] == '\\':
                fres = FREScc(fcc, args.verbose, args.output, args.skip, args.ftk, args.config)
            else:
                fres = FREScc(fcc, args.verbose, args.output, args.skip, args.ftk, args.config + '\\') # if not, conf loading will fail
    elif args.edition == 'emc': # enterprise
        try:
            femc = win32com.client.Dispatch("FEMCCTRL.FEMC")
        except win32com.client.pywintypes.com_error:
            logger.critical('Cannot access to F-Response Enterprise Management Console COM API')
            return
        else:
            logger.debug('F-Response Enterprise Edition COM API loaded')
            machine_list = [machine for machine in args.machine.split(',')]
            fres = FRESemc(femc, args.verbose, args.output, args.skip, args.ftk, machine_list, args.user, args.domain, args.password)
    logger.debug('Configuration for read only iSCSI: user={0}, pass={1}'.format(fres.user, fres.pwd))

    file_cats = []
    if args.files is not None:
        try:
            file_cats = [cat.lower() for cat in args.files.split(',')]
        except ValueError:
            logger.error("Invalid disk option {0}".format(args.files))
        else:
            if 'all' in file_cats:
                file_cats = g_all_cats
        logger.info('targeted file categories in disk: {0}'.format(file_cats))

    logger.info('########### STEP1: RAM/files Acquisition ############')
    fres.acquire(args.ram, file_cats, args.scan)

    logger.info('calculating SHA1 hashes of the acquired files...')
    calculate_hashes(args.output)

    if args.scan:
        logger.info('########### STEP2: Scanning IOCs in RAM ############')
        if args.ioc_dir is None:
            logger.critical('You should specify the folder including IOCs')
            return
        openioc_scan(args.output, args.ioc_dir, args.verbose, args.python, args.vol, args.plugins)

if __name__ == '__main__':
    main()
