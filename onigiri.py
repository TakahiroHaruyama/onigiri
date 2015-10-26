# onigiri.py - remote malware triage script using F-Response and openioc_scan
# Copyright (c) 2015 Takahiro Haruyama (@cci_forensics)
# http://takahiroharuyama.github.io/

g_x86_python_path = r"C:\Python27x86\python.exe"
g_ftk_path = r"C:\tmp\ftkimager\ftkimager.exe"
g_vol_path = r"C:\volatility\vol.py"
g_vol_plugins_path = r"" # set empty if not needed
g_dumpit_path = r"C:\tmp\MWMT-v2.1-RTM\DumpIt.exe"
g_psexec_path = r"C:\tmp\SysinternalsSuite\PsExec.exe"

from datetime import datetime
from glob import glob
from time import sleep
from datetime import datetime
import argparse, os, sys, re, subprocess, logging, hashlib, socket, io, mmap

import win32com.client, requests
from Registry import Registry
import colorama
colorama.init()
from ctypes import *
nt = windll.ntdll

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
    def __init__ (self, f, verbose, out_path, skip, ftk_path, psexec_path, dumpit_path, domain, user, password):
        self.logger = logging.getLogger(type(self).__name__)
        set_logger(self.logger, verbose, out_path, '%(name)s:%(levelname)s: %(message)s')
        self.f = f
        self.out_path = out_path
        self.skip = skip
        self.ftk_path = ftk_path
        self.psexec_path = psexec_path
        self.dumpit_path = dumpit_path
        self.domain = domain
        self.user = user
        self.password = password

    def acquire_ram(self, victim, alternative):
        targets = victim.Targets
        pm = re.compile(r'.*:pmem$')
        self.logger.debug('Issue Discovery Request...')
    	for target in targets:
            if pm.search(target.TargetName):
                self.logger.info('Physical Memory found: {0} (DiskType={1})'.format(target.TargetName, target.DiskType))

                dest_path = self.out_path + "\\" + victim.MachineNameOrIP
                img_path = dest_path + "\\pmem"
                if self.skip and (os.path.exists(img_path + '.dd4.001') or os.path.exists(img_path + '.dmp')):
                    self.logger.info('the RAM image already exists, so skip the acquisition ({0})'.format(img_path))
                    continue
                if not os.path.exists(dest_path):
                    os.mkdir(dest_path)

                if alternative:
                    self.logger.info('acquiring mapped physical memory using PsExec&DumpIt...')
                    cmd_listen = [self.dumpit_path, '/l', '/f', img_path + '.dmp']
                    self.logger.debug('DumpIt Listener cmdline: {}'.format(' '.join(cmd_listen)))
                    proc_listen = subprocess.Popen(cmd_listen, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    for i in range(3):
                        self.logger.info('trying... {0}'.format(i+1))
                        dest_host = socket.gethostbyname(socket.gethostname())
                        cmd_psexec = [self.psexec_path, r'\\' + victim.MachineNameOrIP, '-accepteula', '-c', '-f', '-u', self.domain + '\\' + self.user,
                                #'-p', self.password, '-r', 'onigiri', self.dumpit_path, '/t', dest_host, '/a', '/d', '/lznt1'] DumpIt lznt1 cannot be decompressed
                                '-p', self.password, '-r', 'onigiri', self.dumpit_path, '/t', dest_host, '/a', '/d']
                        self.logger.debug('PsExec cmdline: {}'.format(' '.join(cmd_psexec)))
                        proc_psexec = subprocess.Popen(cmd_psexec, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                        #stdout_data, stderr_data = proc_psexec.communicate()
                        '''  # for Python 3.3
                        while 1:
                            try:
                                outs, errs = proc_psexec.communicate(timeout=5)
                                break
                            except subprocess.TimeoutExpired:
                                size = os.path.getsize(img_path + '.dmp')
                                sys.stdout.write('\r...{:8d}MB'.format(long(size / (1024 * 1024))))
                                continue
                        '''
                        sleep(2)
                        while proc_psexec.poll() is None:
                            sleep(0.1)
                            size = os.path.getsize(img_path + '.dmp')
                            sys.stdout.write('\r...{:8d}MB'.format(long(size / (1024 * 1024))))
                        print '\r\t\t ...Done.'

                        if proc_psexec.returncode == 0:
                            break
                        else:
                            self.logger.error(stderr_data)
                            self.logger.error('PsExec&DumpIt failed.')
                    self.logger.debug('PsExec returncode={0}'.format(proc_psexec.returncode))
                    if proc_psexec.returncode != 0:
                        proc_listen.terminate()
                        self.logger.critical('RAM acquisition failed (PsExec&DumpIt).')
                        self.logger.error("check with the cmdline: {0}".format(' '.join(cmd_psexec)))
                        sys.exit(1)
                    else:
                        stdout_data, stderr_data = proc_listen.communicate()
                    self.logger.debug('DumpIt Listener returncode={0}'.format(proc_listen.returncode))
                    if proc_listen.returncode != 0:
                        self.logger.error(stderr_data)
                        self.logger.critical('RAM acquisition failed (DumpIt Listener).')
                        self.logger.error("check with the cmdline: {0}".format(' '.join(cmd_listen)))
                        sys.exit(1)
                    self.logger.info('RAM image saved: {0}'.format(img_path + '.dmp'))

                else:
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
                    self.logger.info('acquiring mapped physical memory using F-Response&FTKImager ({0})...'.format(device))
                    cmd = [self.ftk_path, device, dest_path + "\\pmem"]

                    self.logger.debug('FTKImager cmdline: {}'.format(' '.join(cmd)))
                    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=-1)
                    with io.open(proc.stderr.fileno(), closefd=False) as stream: # iter(proc.stdout.readline) doesn't work for '\r'?
                        for line in stream:
                            if line.find('MB') != -1 or line.find('complete') != -1:
                                sys.stdout.write('\r' + line.rstrip('\n'))
                    print ''
                    proc.wait()
                    self.logger.debug('Remove F-Response Disk...')
                    target.Logout()
                    self.logger.debug('returncode={0}'.format(proc.returncode))
                    if proc.returncode != 0:
                        self.logger.critical('RAM acquisition failed (F-Response&FTKImager).')
                        self.logger.error("check with the cmdline: {0}".format(' '.join(cmd)))
                        sys.exit(1)
                    self.logger.info('RAM image saved: {0}'.format(img_path + '.dd4.001'))

    def get_file_uri(self, uri, path, expanded_path):
        entry = path.split('\\')[0].lower()
        leftover = '\\'.join(path.split('\\')[1:])
        node = entry if entry != '*' else ''

        self.logger.debug('traversing URI: {0}'.format(uri))
        response = requests.get(uri, auth=(self.iscsi_user, self.iscsi_pwd), verify=False)
        results = response.json()['response']['contents']

        for res in results:
            if (res['name'].lower() == entry or entry == '*') and res['type'] == 'file' and res['state'] != 'realloc' and leftover == '':
                #self.logger.debug('file URI found: {0}'.format(res['uri']))
                yield res['uri'], expanded_path + res['name'], long(res['size'])
            elif (res['name'].lower() == entry or (entry == '*' and (res['name'] not in ('..', '..-$TXF_DATA')))) and \
                res['type'] == 'dir' and res['state'] != 'realloc' and leftover != '' and res['uri'].find('enc=json') != -1:
                for child_uri, child_expanded_path, child_size in self.get_file_uri(res['uri'], leftover, expanded_path + res['name'] + '\\'):
                    #self.logger.debug('walking dir URI: {0}'.format(child_uri))
                    yield child_uri, child_expanded_path, child_size

    def acquire_file(self, ip, vol_name, vol_uri, path):
        for uri, expanded_path, size in self.get_file_uri(vol_uri, path, ''):
            self.logger.info('acquiring file: {}'.format(expanded_path))
            self.logger.debug('uri="{0}", size={1}'.format(uri, size))

            dest_path = self.out_path + "\\" + ip + "\\" + vol_name + "\\" + expanded_path
            if self.skip and os.path.exists(dest_path):
                self.logger.info('the file already exists, so skip the acquisition ({0})'.format(dest_path))
                continue
            dest_folder = os.path.dirname(dest_path)
            if not os.path.exists(dest_folder):
                os.makedirs(dest_folder)

            response = requests.get(uri, auth=(self.iscsi_user, self.iscsi_pwd), verify=False, stream=True)
            with open(dest_path, 'wb') as f:
                progress_size = 0
                for chunk in response.iter_content(chunk_size=IO_BLOCKSIZE):
                    if chunk:  # filter out keep-alive new chunks
                        f.write(chunk)
                        progress_size += len(chunk)
                        if size == 0: # e.g., $J
                            sys.stdout.write("\r...{} bytes (cannot get size info, chunk size = {})".format(progress_size, len(chunk)))
                        else:
                            percent = int(progress_size * 100 / size)
                            sys.stdout.write("\r...{}%, {} bytes (chunk size = {})".format(percent, progress_size, len(chunk)))
                f.flush()

            print ''
            self.logger.info('file saved: {0}'.format(dest_path))


    def get_tgt(self, uri):
        response = requests.get(uri, auth=(self.iscsi_user, self.iscsi_pwd), verify=False)
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
    def __init__ (self, f, verbose, out_path, skip, ftk_path, psexec_path, dumpit_path, domain, user, password, conf_path):
        super(FREScc, self).__init__(f, verbose, out_path, skip, ftk_path, psexec_path, dumpit_path, domain, user, password)
        self.f.FCCConfigureFileLocation = conf_path
        self.f.LoadConfig()
        self.iscsi_user = self.f.FRESUsername
        self.iscsi_pwd = self.f.FRESPassword

    def acquire(self, ram, file_cats, scan, alternative):
        activeclients = self.f.ActiveClients
        self.logger.debug('Discover F-Response Disks...')
        done = []
        for ac in activeclients:
            if ac.MachineNameOrIP not in done:
                self.logger.info('ActiveClient found: {0} (Platform={1})'.format(ac.MachineNameOrIP, ac.Platform))
                if ram or scan:
                    self.logger.info('Starting RAM Acquisition')
                    self.acquire_ram(ac, alternative)
                if len(file_cats) != 0 or scan:
                    self.logger.info('Starting File Acquisition')
                    self.acquire_category_files(ac, file_cats, scan)
                done.append(ac.MachineNameOrIP)
                self.logger.debug('done: {0}'.format(done))

class FRESemc(FRESbase):
    def __init__ (self, f, verbose, out_path, skip, ftk_path, psexec_path, dumpit_path, domain, user, password, machine_list):
        super(FRESemc, self).__init__(f, verbose, out_path, skip, ftk_path, psexec_path, dumpit_path, domain, user, password)
        self.creds = self.f.Credentials
        self.creds.add(user, domain, password)
        self.logger.debug('credential added: user={0}, domain={1}, password={2}'.format(user, domain, password))
        self.computers = self.f.Machines
        for machine in machine_list:
            self.computers.add(machine)
        self.logger.debug('machine(s) added: {0}'.format(machine_list))
        self.iscsi_user = self.f.FRESUsername
        self.iscsi_pwd = self.f.FRESPassword

    def acquire(self, ram, file_cats, scan, alternative):
        done = []
        for computer in self.computers:
            if computer.MachineNameOrIP not in done:
                if computer.Status != 3:
                    self.logger.info('Directly-deploying agent into the victim machine: {0} (Status={1})...'.format(computer.MachineNameOrIP, computer.Status))
                    if computer.Status == 0:
                        self.logger.critical('Invalid IP or Windows admin auth failed. Please check the account username/password.')
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
                    self.acquire_ram(computer, alternative)
                if len(file_cats) != 0 or scan:
                    self.logger.info('Starting File Acquisition')
                    self.acquire_category_files(computer, file_cats, scan)

                self.logger.info('stopping/uninstalling agent...')
                computer.StopFResponse()
                computer.UnInstallFResponse()

                done.append(computer.MachineNameOrIP)
                self.logger.debug('done: {0}'.format(done))

    def uninstall(self):
        done = []
        for computer in self.computers:
            if computer.MachineNameOrIP not in done:
                if computer.Status == 0:
                    self.logger.critical('Invalid IP or Windows admin auth failed. Please check the account username/password.')
                    sys.exit(1)
                if computer.Status == 1:
                    self.logger.critical('agent not installed')
                    sys.exit(1)
                if computer.Status == 3:
                    self.logger.debug('stopping F-Response...')
                    computer.StopFResponse()
                if computer.Status == 2:
                    self.logger.debug('uninstalling F-Response...')
                    computer.UnInstallFResponse()
                self.logger.info('agent uninstalled successfully')
                done.append(computer.MachineNameOrIP)
                self.logger.debug('done: {0}'.format(done))

def set_logger(logger, verbose, out_path, fmt):
    handler = logging.StreamHandler()
    file_handler = logging.FileHandler(out_path + '\\output.log', 'a+')
    logger.addHandler(handler)
    logger.addHandler(file_handler)

    fmt = "%(asctime)s " + fmt
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

def calculate_hashes(out_path, verbose):
    logger = logging.getLogger('calculate_hashes')
    set_logger(logger, verbose, out_path, '%(message)s')

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
                h = hashlib.sha1()
                logger.debug('calculating hash: {}'.format(full_path))
                progress = ''
                with open(full_path, 'rb') as f:
                    map = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                    while True:
                        data = map.read(IO_BLOCKSIZE)
                        if data is '':
                            break
                        h.update(data)
                        progress += data
                        if verbose:
                            sys.stdout.write('\r...{}%'.format(int(len(progress) * 100 / size)))
                if verbose:
                    print '\r Done\t'
                hash_ = h.hexdigest()
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

def openioc_scan(out_path, ioc_dir, verbose, python_path, vol_path, plugins_path, pslist):
    logger = logging.getLogger('openioc_scan')
    set_logger(logger, verbose, out_path, '%(message)s')

    for hostname in os.listdir(out_path):
        if os.path.isdir(out_path + '\\' + hostname):
            img_path = out_path + '\\' + hostname + '\\pmem'
            if os.path.exists(img_path + '.dmp'):
                img_path = img_path + '.dmp'
            elif os.path.exists(img_path + '.dd4.001'):
                img_path = img_path + '.dd4.001'
            else:
                #logger.critical('Memory image not found in {0}'.format(img_path))
                continue

            logger.info('IOC scan target: {0}'.format(hostname))
            logger.debug('memory image path: {0}'.format(img_path))
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
                    if pslist:
                        cmd = [python_path, vol_path, 'pslist', arg_profile, '-f', img_path]
                    elif plugins_path == '':
                        cmd = [python_path, vol_path, 'openioc_scan', arg_profile, arg_ioc_dir, '-f', img_path, '-e']
                    else:
                        cmd = [python_path, vol_path, 'openioc_scan', '--plugins={0}'.format(plugins_path), arg_profile, arg_ioc_dir, '-f', img_path, '-e']
                    logger.info('running volatility...')
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
    parser.add_argument('-a', '--alternative', action='store_true', help="acquire RAM using PsExec&DumpIt instead of F-Response&FTKImager")
    parser.add_argument('-e', '--psexec', help="path to PsExec.exe", default=g_psexec_path)
    parser.add_argument('-m', '--dumpit', help="path to DumpIt.exe", default=g_dumpit_path)
    parser.add_argument('-d', '--domain', default="WORKGROUP", help="domain name the victim machine belongs to")
    parser.add_argument('-u', '--user', default="administrator", help="admin user name at the victim machine")
    parser.add_argument('-c', '--password', default="forensics", help="the user password at the victim machine")
    parser.add_argument('-j', '--pslist', action='store_true', help="run pslist instead of openioc_scan (just check Volatility works)")

    parser.add_argument('-v', '--verbose', action='store_true', help="print verbose messages")
    parser.add_argument('--skip', action='store_true', help="skip acquisition if RAM image or files exist")
    parser.add_argument('--skiphash', action='store_true', help="skip hash calculation")
    parser.add_argument('--version', action='version', version='%(prog)s 0.5')

    subparsers = parser.add_subparsers(dest='edition', help='F-Response editions')
    parser_cc = subparsers.add_parser('cc', help='Consultant or Consultant+Covert')
    parser_cc.add_argument('config', help="config folder path including fresponse.ini")
    parser_emc = subparsers.add_parser('emc', help='Enterprise')
    parser_emc.add_argument('machine', help="the victim machine IP address list (comma-delimited)")
    parser_emc.add_argument('--uninstall', action='store_true', help="just uninstall the emc agent")

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
                fres = FREScc(fcc, args.verbose, args.output, args.skip, args.ftk, args.psexec, args.dumpit, args.domain, args.user, args.password, args.config)
            else:
                fres = FREScc(fcc, args.verbose, args.output, args.skip, args.ftk, args.psexec, args.dumpit, args.domain, args.user, args.password, args.config + '\\') # if not, conf loading will fail
    elif args.edition == 'emc': # enterprise
        try:
            femc = win32com.client.Dispatch("FEMCCTRL.FEMC")
        except win32com.client.pywintypes.com_error:
            logger.critical('Cannot access to F-Response Enterprise Management Console COM API')
            return
        else:
            logger.debug('F-Response Enterprise Edition COM API loaded')
            machine_list = [machine for machine in args.machine.split(',')]
            fres = FRESemc(femc, args.verbose, args.output, args.skip, args.ftk, args.psexec, args.dumpit, args.domain, args.user, args.password, machine_list)
            logger.debug('Validation: server={0}, port={1}'.format(fres.f.ValidationServer, fres.f.ValidationPort))
            if args.uninstall:
                logger.debug('switched to emc agent uninstallation...')
                fres.uninstall()
                return
    logger.debug('Configuration for read only iSCSI: user={0}, pass={1}'.format(fres.iscsi_user, fres.iscsi_pwd))

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
    fres.acquire(args.ram, file_cats, args.scan, args.alternative)

    if args.skiphash is False:
        logger.info('calculating SHA1 hashes of the acquired files...')
        calculate_hashes(args.output, args.verbose)

    if args.scan:
        logger.info('########### STEP2: Scanning IOCs in RAM ############')
        if args.ioc_dir is None:
            logger.critical('You should specify the folder including IOCs')
            return
        openioc_scan(args.output, args.ioc_dir, args.verbose, args.python, args.vol, args.plugins, args.pslist)

    logger.info('onigiri finished\n')

if __name__ == '__main__':
    main()
