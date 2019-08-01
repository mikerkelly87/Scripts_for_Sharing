#!/bin/bash
# Written by: Nathan Pawelek (nathan.pawelek@rackspace.com)
# RPC_ADC.sh
#
# Designed to perform automated device configuration for RPC server deployments

################################################################################
# Usage options
################################################################################

usage() {
cat << EOF

Usage: $0 [OPTIONS] [ARGS]

This script is intended provide QC for Ubuntu Openstack installations

OPTIONS:
 -a     Override RS_SERVER_NAME variable to properly build hostname and /etc/hosts
 -b     Use BBCode tagging instead of terminal colorization (used by ADC)
 -c     Mark device QC complete
 -f     First pass QC
 -h     Display this message
 -k     Add SSH key(s) to /root/.ssh/authorized_keys

        ---
        Accepts an unlimited number of keys. Input must be a
        single semi-colon (;) delimited "argument".

        Example:
        $0 -k "ssh-rsa KEY1 <identity>;ssh-rsa KEY2 <identity>;ssh-rsa KEY3 <identity>"
        ---

 -n     Two bond configuration - generate and replace /etc/network/interfaces

        ---
        Requires four network interfaces as a single "argument" to configure bonding

        Example:
        $0 -n "p6p1 p7p1 p6p2 p7p2"

        Argument order matters!! This will assume that 'bond0' is comprised of the
        first two interfaces and 'bond1' the remaining two. Attempts to anticipate if
        changes will cause connectivity issues upon reboot.

        i.e. Based on the above input:

        bond0 = p6p1 p7p1
        bond1 = p6p2 p7p2
        ---

 -o     Single bond configuration - generate and replace /etc/network/interfaces

        ---
        Requires two network interfaces as a single "argument" to configure bonding

        Example:
        $0 -o "p6p1 p7p1"

        bond0 = "p6p1 p7p1"
        ---

 -q     Prevent output to screen for second pass without BBCode
 -s     Second pass QC
 -t     Network connectivity testing for Management and ServiceNet interfaces
 -v     Test VLAN assignments

        ---
        Requires that CDP be enabled from the switches. Use switch_tool.py to enable
        and disable CDP. Can accept any number of interfaces. NOTE: this can take
        some time.

        Example:
        $0 -v p1p1 p1p2 p2p1 p2p2
        ---

 -u     Upgrade kernel
 -w     Run upgrade_firmware.py
 -z     Install HP/Dell tools
EOF
}

################################################################################
# Determine Ubuntu OS version
################################################################################

get_version() {
    # Determine Ubuntu version

    VERSION=$(lsb_release -r | awk '{print $NF}')

    if [[ $(which dmidecode) ]]; then
        VENDOR=$(dmidecode --type 3 | awk '/Manufacturer/ {print $2}')
    else
        apt-get -qq update && apt-get -qq install dmidecode &> /dev/null
        VENDOR=$(dmidecode --type 3 | awk '/Manufacturer/ {print $2}')
    fi

    if [[ ${VERSION} != 18.04 ]]; then
        # Exit on anything other than Ubuntu 18.04
        echo -e "${FAIL}\tUbuntu version (${VERSION})"
        adc_status FAIL ${ADC_FP_STATUS} "Ubuntu version incorrect"
        exit 1
    else
        echo -e "${PASS}\tUbuntu version (${VERSION})"
    fi
}

################################################################################
# Verify ability to resolve DNS
################################################################################

validate_dns() {
    if [[ $(which dig) ]]; then
        dig +short rackspace.com &> /dev/null
    else
        apt-get -qq update && apt-get -qq install dnsutils &> /dev/null
        dig +short rackspace.com &> /dev/null
    fi

    if [[ $? -ne 0 ]]; then
        echo -e "${FAIL}\tUnable to resolve DNS"
        adc_status FAIL ${ADC_FP_STATUS} "Unable to resolve DNS"
        exit 1
    else
        echo -e "${PASS}\tResolve DNS"
    fi
}

################################################################################
# Set MaxSessions to 100 in sshd_config
################################################################################

set_maxsessions() {
    if [[ $(grep "MaxSessions" /etc/ssh/sshd_config) ]]; then
        sed -i '/MaxSessions/d' /etc/ssh/sshd_config
        echo -e "\nMaxSessions 100" >> /etc/ssh/sshd_config
        service ssh restart &> /dev/null
    else
        echo -e "\nMaxSessions 100" >> /etc/ssh/sshd_config
        service ssh restart &> /dev/null
    fi

    if [[ $? -ne 0 ]]; then
        echo -e "${FAIL}\tUnable to set MaxSessions"
        adc_status FAIL ${ADC_FP_STATUS} "Unable to set MaxSessions"
        exit 1
    else
        echo -e "${PASS}\tSet MaxSessions"
    fi
}

################################################################################
# Verify the /deleteme logical volume has been removed [first pass]
################################################################################

remove_deleteme() {
    # Eventually, may want to make this actually remove deleteme
    COUNTS=$(lvs | grep deleteme | wc -l)
    if [[ $COUNTS -gt 1 ]]; then
        echo -e "${FAIL}\tDetected multiple deleteme logical volumes. Please Remove Manually."
        adc_status FAIL ${ADC_FP_STATUS} "Detected multiple deleteme logical volumes. Please Remove Manually."
        exit 1
    else
        lvs | grep deleteme &> /dev/null
        if [[ $? -eq 0 ]]; then
            (umount /deleteme &>/dev/null \
                && rmdir /deleteme &>/dev/null \
                && lvchange -an /dev/mapper/$(lvs | grep deleteme | awk ' { print $2 }')-deleteme00 &>/dev/null \
                && lvremove -f /dev/mapper/$(lvs | grep deleteme | awk ' { print $2 }')-deleteme00 &>/dev/null \
                && cp /etc/fstab /root/fstab.bak &>/dev/null \
                && sed -i '/\/deleteme/d' /etc/fstab &>/dev/null \
                && echo -e "${PASS}\tSuccessfully Removed deleteme logical volume" ) \
            || (echo -e "${FAIL}\tThe 'deleteme' logical volume was not removed successfully."
            adc_status FAIL ${ADC_FP_STATUS} "The Deleteme logical volume was not removed successfully"
            exit 1)
        else
            echo -e "${PASS}\tThe Deleteme logical volume was not detected"
        fi
    fi
}

################################################################################
# Verify the /deleteme logical volume has been removed [first pass]
################################################################################

expand_nova() {
    COUNTS=$(vgs | wc -l)
    if [[ $COUNTS -gt 2 ]]; then
        echo -e "${FAIL}\tDetected multiple volume groups. Please expand nova Manually."
        adc_status FAIL ${ADC_FP_STATUS} "Detected multiple volume groups. Please expand nova Manually."
    else
        ZEROSPACE=$(vgs | awk '{print $7}' | grep -v 'VFree' | sed "s/\..*//")
        lvs | grep nova &> /dev/null
        if [[ $? -eq 0 ]] && [[ $ZEROSPACE -ne 0 ]]; then
            (umount /var/lib/nova &>/dev/null \
                && lvresize -f -l+100%FREE /dev/$(lvs | grep nova | awk ' { print $2 }')/$(lvs | grep nova | awk '{print $1}') &>/dev/null \
                && resize2fs -f /dev/mapper/$(lvs | grep nova | awk ' { print $2 }')-$(lvs | grep nova | awk '{print $1}') &>/dev/null \
                && mount -a \
                && echo -e "${PASS}\tSuccessfully expanded nova logical volume" ) \
            || (echo -e "${FAIL}\tThe 'nova' logical volume was not expanded successfully."
            adc_status FAIL ${ADC_FP_STATUS} "The nova logical volume was not expanded successfully"
            exit 1)
        else
            echo -e "${PASS}\tThe nova logical volume was not detected or no free space"
        fi
    fi
}

################################################################################
# Standardize /etc/hosts and /etc/hostname [first pass]
################################################################################

validate_hosts() {
    # Standardize /etc/hosts and /etc/hostname

    INTERFACE="$(route -n | awk '/^0.0.0.0/ {print $NF}')"
    ADDRESS=$(ip a sh ${INTERFACE} | awk '/inet / {sub(/\/[0-9]+$/, "", $2); \
                print $2; exit}')
    FQDN="${RS_SERVER_NAME}"
    HOSTNAME=$(echo ${FQDN} | awk -F. '{print $1}')

    if [[ ${ADDRESS} && ${FQDN} && ${HOSTNAME} ]]; then
        cp -f /etc/hosts ${BACKUP_DIR}/hosts.bak &> /dev/null
        echo -e "127.0.0.1\tlocalhost.localdomain localhost" > /etc/hosts
        echo -e "${ADDRESS}\t${HOSTNAME} ${FQDN}" >> /etc/hosts
        echo "${HOSTNAME}" > /etc/hostname
        service hostname restart &>/dev/null
        echo -e "${FIXED}\tReconfigured /etc/hosts and /etc/hostname"
    else
        echo -e "${FAIL}\tMissing variable(s), unable to modify /etc/hosts and \
/etc/hostname"
    fi
}

################################################################################
# Un-blacklist and add modules [first pass]
################################################################################

validate_modules() {
    # Ensure no necessary modules are blacklisted and enable modules
    BLACKLIST_CONF="/etc/modprobe.d/blacklist.local.conf"
    MODULES="/etc/modules"

    # Un-blacklist Modules - Line will only modify file if file exists and
    # blacklist e1000e or blacklist ixgbe exists at the beginning of a line
    if [[ -a ${BLACKLIST_CONF} ]]; then
        if [[ ${VENDOR} == HP ]]; then
            sed -i 's/^blacklist tg3/#blacklist tg3/g' "${BLACKLIST_CONF}"
        else
            sed -i 's/^blacklist e1000e/#blacklist e1000e/g' "${BLACKLIST_CONF}"
        fi
        sed -i 's/^blacklist ixgbe/#blacklist ixgbe/g' "${BLACKLIST_CONF}"
    fi

    # Add bonding and NIC modules to /etc/modules file. We only need to add
    # these lines if they don't exist. The base driver is different for Dell and HP
    (grep -q '^bonding' "${MODULES}" && echo -e "${PASS}\t'bonding' found in ${MODULES}") \
        || (echo -e "${FIXED}\tInserting 'bonding' module into ${MODULES}" \
        && echo 'bonding' >> "${MODULES}")

    if [[ ${VENDOR} == HP ]]; then
        (grep -q '^tg3' "${MODULES}" && echo -e "${PASS}\t'tg3' found in ${MODULES}") \
            || (echo -e "${FIXED}\tInserting 'tg3' module into ${MODULES}" \
            && echo 'tg3' >> "${MODULES}")
    else
        (grep -q '^e1000e' "${MODULES}" && echo -e "${PASS}\t'e1000e' found in ${MODULES}") \
            || (echo -e "${FIXED}\tInserting 'e1000e' module into ${MODULES}" \
            && echo 'e1000e' >> "${MODULES}")
    fi

    (grep -q '^ixgbe' "${MODULES}" && echo -e "${PASS}\t'ixgbe' found in ${MODULES}") \
        || (echo -e "${FIXED}\tInserting 'ixgbe' module into ${MODULES}" \
        && echo 'ixgbe' >> "${MODULES}")

    (grep -q '^8021q' "${MODULES}" && echo -e "${PASS}\t'8021q' found in ${MODULES}") \
        || (echo -e "${FIXED}\tInserting '8021q' module into ${MODULES}" \
        && echo '8021q' >> "${MODULES}")


    (modprobe bonding && echo -e "${PASS}\tbonding module loaded") \
        || echo -e "${FAIL}\tbonding module failed to load"

    if [[ ${VENDOR} == HP ]]; then
        (modprobe tg3 && echo -e "${PASS}\ttg3 module loaded") \
            || echo -e "${FAIL}\ttg3 module failed to load"
    else
        (modprobe e1000e && echo -e "${PASS}\te1000e module loaded") \
            || echo -e "${FAIL}\te1000e module failed to load"
    fi

    (modprobe ixgbe && echo -e "${PASS}\tixgbe module loaded") \
        || echo -e "${FAIL}\tixgbe module failed to load"
    (modprobe 8021q && echo -e "${PASS}\t8021q module loaded") \
        || echo -e "${FAIL}\t8021q module failed to load"
}

################################################################################
# Enable DRAC console serial redirection [[12.04 SPECIFIC]] [first pass]
################################################################################

drac_serial_console() {
    # Create file to configure console serial redirection over DRAC
    # (this will allow you to access DRAC from your terminal session window)

    cat << EOF > /etc/init/ttyS0.conf && echo -e "${FIXED}\tConfigured serial \
console redirection (ttyS0)"
# ttyS0 - getty
#
# This service maintains a getty on ttyS0 from the point the system is
# started until it is shut down again.

start on runlevel [2345] and (
            not-container or
            container CONTAINER=lxc or
            container CONTAINER=lxc-libvirt)

stop on runlevel [!2345]

respawn
exec /sbin/getty -8 -L 115200 ttyS0 ansi
EOF

    (start ttyS0 &>/dev/null \
        && echo -e "${PASS}\tttyS0 started") \
        || echo -e "${INFORM}\tttyS0 already started"
}

################################################################################
# Apply kernel and package updates [first pass]
################################################################################

resolve_dpkg_transactions() {
    # Ensure that apt-get install will run, just in-case a previous apt-get failed

    dpkg --configure -a &> /dev/null
}

upgrade_kernel_1204() {
    # Update kernel from 3.2

    resolve_dpkg_transactions
    apt-get -qq update
    (apt-get -qq install --install-recommends linux-generic-lts-raring \
        &>/dev/null && echo -e "${PASS}\tUpdate kernel to 3.8") \
        || echo -e "${FAIL}\tUpdate kernel to 3.8"
}

upgrade_kernel_1404() {
    # Does nothing at this time
    resolve_dpkg_transactions
    echo -e "${INFORM}\tUpdate 14.04 kernel (currently does nothing)"
}

update_packages() {
    # Maintain existing major kernel version and update existing packages

    apt-get -qq update
#    (apt-get -qq dist-upgrade &>/dev/null \
#        && echo -e "${PASS}\tUpdate system packages") \
#        || echo -e "${FAIL}\tUpdate system packages"

    # Remove all unattended-upgrades Origins to no packages update
    sed -i 's@\(.*${distro_codename}-security\)@//\1@g' \
        /etc/apt/apt.conf.d/50unattended-upgrades &> /dev/null
    apt-get -qq autoremove &> /dev/null
}

install_tools() {
    # Install necessary Linux packages, enable sar, and install recap
    # If version 14.04 and infra01 install deployment/target host packages
    # If just version 14.04 install target host packages
    # If 12.04 install default packages

    DEFAULTPKGS="dsh curl ethtool ifenslave vim sysstat linux-crashdump xterm bridge-utils iperf traceroute nmap screen irqbalance git bc make"
    DEPLOYPKGS="aptitude build-essential git openssh-server python-dev"
    TARGETPKGS="debootstrap ifenslave ifenslave-2.6 lsof lvm2 openssh-server sudo tcpdump vlan"
    apt-get -qq update

    if [[ ${VERSION} == 16.04 && ${RS_SERVER_NAME} =~ 'infra01' ]]; then
        (DEBIAN_FRONTEND=noninteractive apt-get -qq install ${DEFAULTPKGS} ${DEPLOYPKGS} ${TARGETPKGS} &>/dev/null \
            && echo -e "${PASS}\tInstall additional Linux tools") \
            || echo -e "${FAIL}\tInstall additional Linux tools"
    elif [[ ${VERSION} == 16.04 ]]; then
        (DEBIAN_FRONTEND=noninteractive apt-get -qq install ${DEFAULTPKGS} ${TARGETPKGS} &>/dev/null \
            && echo -e "${PASS}\tInstall additional Linux tools") \
            || echo -e "${FAIL}\tInstall additional Linux tools"
    else
        (DEBIAN_FRONTEND=noninteractive apt-get -qq install ${DEFAULTPKGS} &>/dev/null \
            && echo -e "${PASS}\tInstall additional Linux tools") \
            || echo -e "${FAIL}\tInstall additional Linux tools"
    fi

    unset DEBIAN_FRONTEND
    sed -i 's@ENABLED="false"@ENABLED="true"@' /etc/default/sysstat

    CHECK_RECAP=$(which recap &> /dev/null ; echo $?)
    if [[ $CHECK_RECAP -eq 0 ]]; then
        echo -e "${PASS}\tRecap already installed"
    else
        # Install recap
        (cd ${ADC_DIR} && git clone https://github.com/rackerlabs/recap.git \
            || cd ${ADC_DIR}/recap && git pull) &>/dev/null
        (cd ${ADC_DIR}/recap/ && make install &>/dev/null && sleep 5 \
            && sed -i "s@^LOG_EXPIRY=.*@LOG_EXPIRY=30@" /etc/recap.conf \
            && sed -i "s@^EMAIL_ON_ERROR=.*@EMAIL_ON_ERROR=0@g" /etc/recap.conf \
            && for i in USESAR USESARR USESARQ USENETSTAT USENETSTATSUM; \
                do sed -i "s@^${i}=.*@${i}=yes@" /etc/recap.conf; done \
            && echo -e "${PASS}\tInstall and configure Recap") \
            || echo -e "${FAIL}\tInstall and configure Recap"
    fi
    
    # Point UEFI grub to regular grub
    HAZ_UEFI_GRUB=$(ls /boot/efi/EFI/ubuntu/grub.cfg >/dev/null 2>&1 && echo '0' || echo '1')
    FIX_UEFI_GRUB=$(wc -l /boot/efi/EFI/ubuntu/grub.cfg | awk '{ print $1 }')
    ACT_UEFI_GRUB=$(grep crash /proc/cmdline >/dev/null 2>&1 && echo '0' || echo '1')
    if [[ ${HAZ_UEFI_GRUB} -eq 0 ]]; then
        if [[ ${FIX_UEFI_GRUB} -eq 3 ]]; then
            if [[ ${ACT_UEFI_GRUB} -eq 0 ]]; then
            echo -e "${FIXED}\tUEFI grub update active"
            else
            echo -e "${MANUAL}\tUEFI grub already updated. Still needs reboot."
            fi
        else
            gdrive="$(df -h /boot/grub/ | grep -v Filesystem | awk '{ print $1 }')" \
            && grubuuid="$(blkid $gdrive | sed 's/ /\\\n/g' | egrep '^UUID' | awk -F\" '{ print $2 }')" \
            && (cd /boot/efi/EFI/ubuntu/; cp grub.cfg grubcfg.bak) \
            && echo "search.fs_uuid $grubuuid root hd0,gpt2" > /boot/efi/EFI/ubuntu/grub.cfg \
            && echo "set prefix=(\$root)'/grub'" >> /boot/efi/EFI/ubuntu/grub.cfg \
            && echo "configfile \$prefix/grub.cfg" >> /boot/efi/EFI/ubuntu/grub.cfg \
            && echo -e "${MANUAL}\tUEFI grub updated. Please reboot. Backup saved to /boot/efi/EFI/ubuntu/grubcfg.bak"
        fi
    else
        echo -e "${PASS}\tNo UEFI";
    fi

    # Configure kdump as active
    ENABLE_KDUMP=$(sed -i 's@^USE_KDUMP=0@USE_KDUMP=1@g' /etc/default/kdump-tools &> /dev/null ; echo $?)
    if [[ ${ENABLE_KDUMP} -eq 0 ]]; then
        VERIFY_CMDLINE=$(grep -o crashkernel=1024M /proc/cmdline &>/dev/null ; echo $?)
        if [[ ${VERIFY_CMDLINE} -eq 0 ]]; then
            echo -e "${FIXED}\tEnable kdump"
        else
            echo -e "${MANUAL}\tEnable kdump, must reboot and rerun first pass prior to running second pass"
            ADC_FAIL=2
        fi
    else
        echo -e "${FAIL}\tEnable kdump"
    fi

    # crashkernel memory allocation defaults to 384M.
    # This default changed to 512M in 18.04
    # Modify value to 1G for any servers with at least 128M of RAM
    (cp /etc/default/grub.d/kdump-tools.cfg ${BACKUP_DIR}/kdump-tools.cfg.bak \
            && sed -i 's@512@1024@g' /etc/default/grub.d/kdump-tools.cfg \
            && update-grub &> /dev/null \
            && echo -e "${FIXED}\tConfigure crash kernel memory allocation to 1024M") \
            || echo -e "${FAIL}\tConfigure crash kernel memory allocation to 1024M"
}

install_openmanage() {
    # Install OMSA repo, packages, and start services

    SOURCES_FILE="/etc/apt/sources.list.d/linux.dell.com.sources.list"
    CODENAME=$(lsb_release -c | awk '{print $NF}')

    if [[ -f ${SOURCES_FILE} ]] &&
        [[ $(grep "linux.dell.com" ${SOURCES_FILE}) ]]; then
        echo -e "${INFORM}\tDell OMSA repository already installed"
    else
        echo "deb http://linux.dell.com/repo/community/openmanage/930/${CODENAME} ${CODENAME} main" \
            >> "${SOURCES_FILE}" && echo -e "${PASS}\tInstalled Dell OMSA repository"
    fi

    # Verify the OMSA repository keys
    (gpg --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-key 1285491434D8786F \
        &>/dev/null && echo -e "${PASS}\tDownloading GPG key") \
        || echo -e "${FAIL}\tDownloading GPG key"

    (gpg -a --export 1285491434D8786F | apt-key add - &>/dev/null \
        && echo -e "${PASS}\tInstalling GPG key") \
        || echo -e "${FAIL}\tInstalling GPG key"

    apt-get -qq update
    (apt-get -qq install srvadmin-all &>/dev/null \
        && echo -e "${PASS}\tInstalling OMSA packages") \
        || echo -e "${FAIL}\tInstalling OMSA packages"

    (${OMSA_SBIN}/srvadmin-services.sh restart &>/dev/null \
        && sleep 30 && echo -e "${PASS}\tStarting OMSA services") \
        || echo -e "${FAIL}\tStarting OMSA services"

    if [[ ${VERSION} == 16.04 ]]; then
        # Enable persistence
        for OMSA_SERVICE in dataeng instsvcdrv dsm_om_connsvc racsvc.sh
        do
            (update-rc.d ${OMSA_SERVICE} defaults &>/dev/null \
                && echo -e "${PASS}\tEnable ${OMSA_SERVICE} persistence") \
                || echo -e "${FAIL}\tEnable ${OMSA_SERVICE} persistence"
        done
    fi
}

install_hp_mcp() {
    # Remove old path so this function is compatible with openstack-ops
    rm -f /etc/apt/sources.list.d/linux.hp.com.sources.list /etc/apt/sources.list.d/hp-mcp.list /etc/apt/sources.list.d/hp-stk.list 2>/dev/null

    # Install HP MCP repo, packages, and start Proliant services
    SOURCES_FILE="/etc/apt/sources.list.d/downloads_linux_hpe_com_SDR_repo_mcp.list"
    CODENAME=$(lsb_release -c | awk '{print $NF}')

    if [[ ${CODENAME} == trusty ]] || [[ ${CODENAME} == xenial ]]; then
        echo "deb http://downloads.linux.hpe.com/SDR/repo/mcp/ubuntu ${CODENAME}/10.60 non-free" \
            > "${SOURCES_FILE}" && echo -e "${PASS}\tInstalled HP MCP repository"
    elif [[ ${CODENAME} == precise ]]; then
        echo "deb http://downloads.linux.hpe.com/SDR/repo/mcp/ubuntu ${CODENAME}/9.50 non-free" \
            > "${SOURCES_FILE}" && echo -e "${PASS}\tInstalled HP MCP repository"
    fi

    # Download and verify the HP MCP repository keys
    for FINGERPRINT in 5CE2D476 B1275EA3 26C2B797
    do
      (gpg --keyserver pool.sks-keyservers.net --recv-key ${FINGERPRINT} \
          &>/dev/null && echo -e "${PASS}\tDownloading GPG key [${FINGERPRINT}]") \
          || echo -e "${FAIL}\tDownloading GPG key [${FINGERPRINT}]"

      (gpg -a --export ${FINGERPRINT} | apt-key add - &>/dev/null \
          && echo -e "${PASS}\tInstalling GPG key [${FINGERPRINT}]") \
          || echo -e "${FAIL}\tInstalling GPG key [${FINGERPRINT}]"
    done

    # Install packages
    MCPPKGS="hp-health hponcfg ssacli hp-snmp-agents"
    apt-get -qq remove hpssacli 2>/dev/null
    apt-get clean
    apt-get -qq update
    (apt-get -qq install ${MCPPKGS} &>/dev/null \
        && echo -e "${PASS}\tInstalling HP MCP packages") \
        || echo -e "${FAIL}\tInstalling HP MCP packages"

    (/etc/init.d/hp-health restart &>/dev/null \
        && sleep 30 && echo -e "${PASS}\tStarting hp-health services") \
        || echo -e "${FAIL}\tStarting hp-health services"
}

install_dellhp_tools() {
    #Functio to check vendor and install our old way installing HP/Dell tools
    #These tools should now be part of our kick process

    if [[ ${VENDOR} == Dell ]]; then
        install_openmanage      &>> ${FIRSTPASS_LOG}
    elif [[ ${VENDOR} == HP ]]; then
        install_hp_mcp          &>> ${FIRSTPASS_LOG}
    fi
}

################################################################################
# Apply BIOS updates [first pass]
################################################################################

710_bios_performance() {
    # Disable cstates for R710 Performance

    (${OMCONFIG} chassis biossetup attribute=cstates setting=disabled \
        &>/dev/null && echo -e "${FIXED}\tEnable BIOS performance profile") \
        || echo -e "${FAIL}\tEnable BIOS performance profile"
    sleep 2
}

dell_bios_performance() {
    # Enable the performance profile in the BIOS

    (${OMCONFIG} chassis biossetup attribute=SysProfile setting=PerfOptimized \
        &>/dev/null && echo -e "${FIXED}\tEnable BIOS performance profile") \
        || echo -e "${FAIL}\tEnable BIOS performance profile"
    sleep 2
}

update_dell_bios() {
    # Configure serial and performance options via omconfig/racadm

    CHASSIS=$(${OMREPORT} system summary | awk '/^Chassis Model/ {print $NF}')
    DRAC_VERSION=$(${OMREPORT} system summary \
        | grep "^Remote Access Controller Information" -A7 \
        | awk '/^Product/ {print $3}')

    # Verify OMSA is running
    ${OMSA_SBIN}/srvadmin-services.sh status &>/dev/null

    if [[ $? -eq 0 ]]; then
        if [[ ${DRAC_VERSION} == iDRAC7 ]]; then
            # Verify status of Lifecycle Controller
            LIFECYCLE_CONTROLLER_STATUS=$(${RACADM} get \
                LifecycleController.LCAttributes.LifecycleControllerState 2>&1 \
                | head -1 | awk '{print $1}')

            # Attempt to enable if it's not already
            if [[ ${LIFECYCLE_CONTROLLER_STATUS} != Enabled ]]; then
                LC_FAILURE=0
                TIMER=120
                ${RACADM} set \
                    LifecycleController.LCAttributes.LifecycleControllerState 1 \
                    &>/dev/null

                # Determine if racadm is functioning
                if [[ $? -eq 0 ]]; then
                    echo -e "${FIXED}\tEnable Lifecycle Controller"
                else
                    # Attempt a racreset
                    echo -e "${INFORM}\tExecuting 'racadm racreset'"
                    ${RACADM} racreset &> /dev/null
                    sleep 30

                    # Wait for racadm to become responsive (up to 2 minutes)
                    while [[ ${TIMER} -ne 0 ]]
                    do
                        LIFECYCLE_CONTROLLER_STATUS=$(${RACADM} get \
                            LifecycleController.LCAttributes.LifecycleControllerState \
                            2>&1 | head -1 | awk '{print $1}')
                        if [[ ${LIFECYCLE_CONTROLLER_STATUS%:} == ERROR ]]; then
                            (( TIMER -= 10 ))
                            sleep 10
                        else
                            # Enable the Lifecycle controller
                            (${RACADM} set \
                                LifecycleController.LCAttributes.LifecycleControllerState 1 \
                                &>/dev/null && echo -e "${FIXED}\tEnable Lifecycle Controller") \
                                || LC_FAILURE=1
                            break
                        fi
                    done
                fi

                if [[ ${LC_FAILURE} -eq 0 && ${TIMER} -ne 0 ]]; then
                    # Indicate to ADC that the Lifecycle Controller was successfully
                    # enabled and requires a reboot
                    echo -e "${MANUAL}\tLifecycle Controller enabled, must reboot prior to running secondpass"
                    ADC_FAIL=1
                else
                    # Lifecycle Controller will require manual intervention
                    echo -e "${MANUAL}\tAttempts to enable Lifecycle Controller failed. Additional troubleshooting necessary"
                fi
            fi
        fi

        # Apply BIOS changes to allow console serial redirection over DRAC
        (${OMCONFIG} chassis biossetup attribute=extserial setting=rad \
            &>/dev/null && echo -e "${FIXED}\tEnable BIOS ExtSerialConnector") \
            || echo -e "${FAIL}\tEnable BIOS ExtSerialConnector"
        (${OMCONFIG} chassis biossetup attribute=fbr setting=115200 \
            &>/dev/null && echo -e "${FIXED}\tEnable BIOS FailSafeBaud") \
            || echo -e "${FAIL}\tEnable BIOS FailSafeBaud"
        (${OMCONFIG} chassis biossetup attribute=serialcom setting=com2 \
            &>/dev/null && echo -e "${FIXED}\tEnable BIOS SerialComm") \
            || echo -e "${FAIL}\tEnable BIOS SerialComm"
        (${OMCONFIG} chassis biossetup attribute=crab setting=enabled \
            &>/dev/null && echo -e "${FIXED}\tEnable BIOS RedirAfterBoot") \
            || echo -e "${FAIL}\tEnable BIOS RedirAfterBoot"

        if [[ ${CHASSIS} == R710 ]]; then
            # If chassis is R710 then use alternate method
            710_bios_performance
        else
            # All other chassis models
            dell_bios_performance
        fi

        # Apply DRAC settings to allow console serial redirection over DRAC
        (${RACADM} config -g cfgSerial -o cfgSerialBaudRate 115200 \
            &>/dev/null && echo -e "${FIXED}\tEnable racadm cfgSerialBaudRate") \
            || echo -e "${FAIL}\tEnable racadm cfgSerialBaudRate"
        (${RACADM} config -g cfgSerial -o cfgSerialConsoleEnable 1 \
            &>/dev/null && echo -e "${FIXED}\tEnable racadm cfgSerialConsoleEnable") \
            || echo -e "${FAIL}\tEnable racadm cfgSerialConsoleEnable"
        (${RACADM} config -g cfgSerial -o cfgSerialSshEnable 1 \
            &>/dev/null && echo -e "${FIXED}\tEnable racadm cfgSerialSshEnable") \
            || echo -e "${FAIL}\tEnable racadm cfgSerialSshEnable"
        (${RACADM} config -g cfgSerial -o cfgSerialHistorySize 2000 \
            &>/dev/null && echo -e "${FIXED}\tEnable racadm cfgSerialHistorySize") \
            || echo -e "${FAIL}\tEnable racadm cfgSerialHistorySize"
    else
        if [[ ${OMSA_COUNT} -eq 0 ]]; then
            ((OMSA_COUNT++))
            ${OMSA_SBIN}/srvadmin-services.sh restart &>/dev/null && sleep 30
            update_dell_bios
        else
            echo -e "${MANUAL}\tUnable to successfully start OMSA services"
        fi
    fi
}

update_hp_bios() {
    # Ensure that the OS control profile is set

    # Verify iLO 4
    ILO_VERSION=$(${HPONCFG} -g | awk '/^Version/ {print $2}')
    if [[ ${ILO_VERSION} == 4.* ]]; then

        # Dump current settings
        ILO_XML="/home/rack/.adc/ilo_settings.xml"
        ${HPONCFG} -a -w ${ILO_XML} &>/dev/null

        # 1 = OS Control Mode (Disabled Mode for iLO)
        # 2 = HP Static Low Power Mode
        # 3 = HP Dynamic Power Savings Mode
        # 4 = HP Static High Performance Mode

        # Check if "OS Control Mode" is set
        HOST_POWER_SAVER_STATUS=$(grep 'HOST_POWER_SAVER="1"' ${ILO_XML})

        if [[ -z ${HOST_POWER_SAVER_STATUS} ]]; then
            HOST_POWER_SAVER_XML="/home/rack/.adc/host_power_saver.xml"
            ILO_LOG="/home/rack/rs-automations/ilo_log.txt"

            cat > ${HOST_POWER_SAVER_XML} << EOF
<RIBCL VERSION="2.0">
<LOGIN USER_LOGIN="root" PASSWORD="calvincalvin">
<SERVER_INFO MODE="write">
<SET_HOST_POWER_SAVER HOST_POWER_SAVER="1"/>
</SERVER_INFO>
</LOGIN>
</RIBCL>
EOF

            # Set "OS Control Mode"
            SET_HOST_POWER=$(${HPONCFG} -f ${HOST_POWER_SAVER_XML} | tail -1)
            if [[ ${SET_HOST_POWER} =~ succeeded ]]; then
                echo -e "${FIXED}\tOS control profile"
                rm -rf ${ILO_XML} ${ILO_LOG} ${HOST_POWER_SAVER_XML}
            else
                echo -e "${FAIL}\tOS control profile"
                rm -rf ${ILO_XML} ${HOST_POWER_SAVER_XML}
            fi
        else
            echo -e "${PASS}\tOS control profile"
        fi
    else
        echo -e "${FAIL}\tHP iLO 4 not found"
    fi
}

ilo_textcons_grub() {
    # Ensure that Ubuntu is configured to properly allow TEXTCONS console

    GRUB_CONF="/etc/default/grub"
    LINUX_DEFAULT=$(awk -F\" '/^GRUB_CMDLINE_LINUX_DEFAULT/ {print $2}' ${GRUB_CONF})
    LINUX_DEFAULT_NEW="${LINUX_DEFAULT}"

    for i in vga=normal nomodeset
    do
        if [[ -z $(echo "${LINUX_DEFAULT}" | grep "$i") ]]; then
            LINUX_DEFAULT_NEW="$LINUX_DEFAULT_NEW $i"
        fi
    done

    if [[ -a ${GRUB_CONF} ]]; then
        if [[ ${LINUX_DEFAULT_NEW} ]]; then
            (sed -i "s@^GRUB_CMDLINE_LINUX_DEFAULT.*@GRUB_CMDLINE_LINUX_DEFAULT=\"${LINUX_DEFAULT_NEW}\"@g" ${GRUB_CONF} \
                && update-grub &> /dev/null \
                && echo -e "${PASS}\tHP iLO textcons mode set in grub") \
                || echo -e "${FAIL}\tHP iLO textcons mode set in grub"
        else
            echo -e "${FAIL}\tHP iLO textcons mode set in grub"
        fi
    fi
}

################################################################################
# Properly align UDEV rules for Ubuntu 12.04 [first pass]
################################################################################

regen_udev() {
    # Remove existing rule and regenerate 70-persistent-net.rules with PCI names
    # in comments

    UDEV_NET=/etc/udev/rules.d/70-persistent-net.rules
    BAK_UDEV_NET=${BACKUP_DIR}/70-persistent-net.rules.bak

    if [[ -e ${UDEV_NET} ]]; then
        rm "${UDEV_NET}"
        udevadm trigger --action=add
        udevadm settle
        sleep 2
        udevadm settle

        # We create our backup file, though it isn't strictly necessary since we
        # can regenerate the file with udev. We do use it as a tmp file when doing
        # our parsing and sorting
        cp "${UDEV_NET}" "${BAK_UDEV_NET}" &> /dev/null
    fi
}

bdf_mac_sort () {
    # Sort by PCI BDF notation, use Bus Device then MAC address
    # (instead of Function) for sorting

    if [[ -e ${UDEV_NET} ]]; then
        for MAC_VEN in $(sed -r ':r;/(^|\n)$/!{$!{N;br}};s/\n/\v/g' "${BAK_UDEV_NET}" |
                sort | sed 's/\v/\n/g' | awk '/SUBSYSTEM/ {print $0}' |
                awk -F\" '{print $8}' | awk -F: '{print $1":"$2":"$3}' |
                uniq); do grep "${MAC_VEN}" "${BAK_UDEV_NET}" | sort; done | \
                            awk 'BEGIN {i=0} {sub(/eth[0-9].*$/,"eth"i"\"") ; i++} \
                            {print $0}' > "${UDEV_NET}" \
                            && echo -e "${FIXED}\tAlign udev by vendor hardware address" \
                            || echo -e "${FAIL}\tAlign udev by vendor hardware address"
    else
        echo -e "${INFORM}\tUnable to find and align UDEV"
    fi
}

validate_udev_changes() {
    # Fix /etc/network/interfaces to ensure connectivity after reboot

    if [[ -e ${UDEV_NET} ]]; then
        MAC_ADDRESS=$(ip a sh ${INTERFACE} | awk '/link\/ether/ {print $2}')
        NEW_INTERFACE=$(grep ${MAC_ADDRESS} ${UDEV_NET} | awk '{print $NF}' |
                            cut -c6- | sed 's@"@@g')

        cp -fn /etc/network/interfaces ${BACKUP_DIR}/interfaces &> /dev/null
        sed -i "s@${INTERFACE}@${NEW_INTERFACE}@g" /etc/network/interfaces
    fi
}

################################################################################
# Verify Ubuntu version and architecture [second pass]
################################################################################

verify_ubuntu_version() {
    ARCHITECTURE=$(uname -p)
    CODENAME=$(lsb_release -c | awk '{print $NF}')

    if [[ ( ${VERSION} == 14.04 || ${VERSION} == 12.04 || ${VERSION} == 16.04 || ${VERSION} == 18.04  ) && \
        ${ARCHITECTURE} == x86_64 ]]; then
        echo -e "${PASS}\tUbuntu Version (${VERSION}; $(uname -r))"
    else
        echo -e "${FAIL}\tUbuntu Version (${VERSION}; $(uname -r))"
    fi
}

################################################################################
# Standardize /etc/hosts and /etc/hostname [second pass]
################################################################################

verify_hosts() {
    INTERFACE="$(route -n | awk '/^0.0.0.0/ {print $NF}')"
    ADDRESS=$(ip a sh ${INTERFACE} | awk '/inet / {sub(/\/[0-9]+$/, "", $2); \
                print $2; exit}')
    FQDN="${RS_SERVER_NAME}"
    HOSTNAME=$(echo ${FQDN} | awk -F. '{print $1}')

    if [[ ${ADDRESS} && ${HOSTNAME} && ${FQDN} ]]; then
        if [[ $(grep "^${ADDRESS}.*${HOSTNAME}.*${FQDN}$" /etc/hosts) ]]; then
            echo -e "${PASS}\tVerify /etc/hosts"
        else
            echo -e "${FAIL}\tVerify /etc/hosts"
        fi

        if [[ $(grep "^${HOSTNAME}$" /etc/hostname) ]]; then
            echo -e "${PASS}\tVerify /etc/hostname"
        else
            echo -e "${FAIL}\tVerify /etc/hostname"
        fi
    else
        echo -e "${FAIL}\tMissing variable(s), unable to verify /etc/hosts \
and /etc/hostname"
    fi
}

################################################################################
# Verify timezone is UTC [second pass]
################################################################################

verify_timezone() {
    if [[ $(date +%Z) != UTC ]]; then
        echo -e "${FAIL}\tVerify timezone is UTC [or matches infra01]"
    else
        echo -e "${PASS}\tVerify timezone is UTC"
    fi
}

################################################################################
# Verify DNS resolution is functioning [second pass]
################################################################################

verify_dns() {
    PING=$(ping -c1 google.com)

    if [[ $? -eq 0 ]]; then
            echo -e "${PASS}\tVerify DNS resolution"
        else
            echo -e "${FAIL}\tVerify DNS resolution"
    fi
}

################################################################################
# Verify modules are enabled [second pass]
################################################################################

verify_drivers() {
    BLACKLIST_CONF="/etc/modprobe.d/blacklist.local.conf"
    MODULES="/etc/modules"

    if [[ ${VENDOR} == DELL ]]; then
        if [[ -a ${BLACKLIST_CONF} ]]; then
            BLACKLISTED=$(egrep "^blacklist.*(igb|ixgbe|e1000e)" ${BLACKLIST_CONF})
            if [[ -z ${BLACKLISTED} ]]; then
                echo -e "${PASS}\tVerify ${BLACKLIST_CONF}"
            else
                echo -e "${FAIL}\tVerify ${BLACKLIST_CONF}"
            fi
        fi

        bonding_PERSISTENCE=$(grep ^bonding ${MODULES})
        e1000e_PERSISTENCE=$(grep ^e1000e ${MODULES})
        ixgbe_PERSISTENCE=$(grep ^ixgbe ${MODULES})
        m8021q_PERSISTENCE=$(grep ^8021q ${MODULES})
        bonding_STATUS=$(lsmod | grep ^bonding)
        e1000e_STATUS=$(lsmod | grep ^e1000e)
        ixgbe_STATUS=$(lsmod | grep ^ixgbe)
        m8021q_STATUS=$(lsmod | grep ^8021q)

        if [[ ${bonding_PERSISTENCE} && ${bonding_STATUS} &&
              ${e1000e_PERSISTENCE} && ${e1000e_STATUS} &&
              ${ixgbe_PERSISTENCE} && ${ixgbe_STATUS} &&
              ${m8021q_PERSISTENCE} && ${m8021q_STATUS} ]]; then
            echo -e "${PASS}\tVerify ${MODULES}"
        else
            echo -e "${FAIL}\tVerify ${MODULES}"
        fi
    elif [[ ${VENDOR} == HP ]]; then
        if [[ -a ${BLACKLIST_CONF} ]]; then
            BLACKLISTED=$(egrep "^blacklist.*(igb|ixgbe|tg3)" ${BLACKLIST_CONF})
            if [[ -z ${BLACKLISTED} ]]; then
                echo -e "${PASS}\tVerify ${BLACKLIST_CONF}"
            else
                echo -e "${FAIL}\tVerify ${BLACKLIST_CONF}"
            fi
        fi

        # HP side (swapped e1000e (intel) and tg3 (broadcom) drivers)
        bonding_PERSISTENCE=$(grep ^bonding ${MODULES})
        tg3_PERSISTENCE=$(grep ^tg3 ${MODULES})
        ixgbe_PERSISTENCE=$(grep ^ixgbe ${MODULES})
        m8021q_PERSISTENCE=$(grep ^8021q ${MODULES})
        bonding_STATUS=$(lsmod | grep ^bonding)
        tg3_STATUS=$(lsmod | grep ^tg3)
        ixgbe_STATUS=$(lsmod | grep ^ixgbe)
        m8021q_STATUS=$(lsmod | grep ^8021q)

        if [[ ${bonding_PERSISTENCE} && ${bonding_STATUS} &&
              ${tg3_PERSISTENCE} && ${tg3_STATUS} &&
              ${ixgbe_PERSISTENCE} && ${ixgbe_STATUS} &&
              ${m8021q_PERSISTENCE} && ${m8021q_STATUS} ]]; then
            echo -e "${PASS}\tVerify ${MODULES}"
        else
            echo -e "${FAIL}\tVerify ${MODULES}"
        fi
    fi
}

################################################################################
# Verify kdump enabled [second pass]
################################################################################
verify_kdump_enabled() {
    (grep -o 'USE_KDUMP=1' /etc/default/kdump-tools &> /dev/null \
            && echo -e "${PASS}\tVerify kdump is enabled") \
            || echo -e "${FAIL}\tVerify kdump is enabled"
}

################################################################################
# Verify crashdump memory allocation == 1024M [second pass]
################################################################################
verify_crashdump_memory_alloc() {
    (grep -o 1024M /proc/cmdline &> /dev/null \
            && grep -o 1024M /etc/default/grub.d/kdump-tools.cfg  &> /dev/null \
            && echo -e "${PASS}\tVerify crashdump memory allocation set to 1024M") \
            || echo -e "${FAIL}\tVerify crashdump memory allocation set to 1024M (this requires a reboot to take effect)"
}

################################################################################
# Verify file system layout [second pass]
################################################################################

verify_filesystem() {
    # Resize any swap disks larger than 8GB. Run only if 8G > swap00 > 7G

    SWAP_PARTITION=$(blkid | awk '/TYPE=\"swap\"/ {print $1}')
    SWAP_PARTITION=$(echo "${SWAP_PARTITION}" | sed 's@mapper/@@;s@-swap@/swap@')
    SWAP_PARTITION=${SWAP_PARTITION%:}

    ROOT_PARTITION=$(blkid | awk '/ROOT|root/ {print $1}')
    ROOT_PARTITION=$(echo "${ROOT_PARTITION}" | sed 's@mapper/@@;s@-root@/root@')
    ROOT_PARTITION=${ROOT_PARTITION%:}

    if [[ ! $(which lvs) ]]; then
        apt-get -qq update
        apt-get -qq install lvm2 &> /dev/null
    fi

    ROOTVG_NAME=$(lvs --noheadings ${ROOT_PARTITION} | awk '{print $2}')

    if [[ $(free -g | awk '/^Swap:/ {print $2}') -gt 8 ]]; then

        if [[ -b ${SWAP_PARTITION} &&
           $(lvs --noheadings ${SWAP_PARTITION} 2>/dev/null) ]]; then

            swapoff -a &>/dev/null
            lvresize -f -L 8G ${SWAP_PARTITION} &>/dev/null
            mkswap ${SWAP_PARTITION} &>/dev/null
            swapon -a &>/dev/null
            echo -e "${FIXED}\tSWAP resized to 8GB ('${SWAP_PARTITION}')"

        else
            echo -e "${INFORM}\t'${SWAP_PARTITION}' is a stand-alone partition \
which does not use LVM"
        fi
    elif [[ $(free -g | awk '/^Swap:/ {print $2}') -eq 0 ]]; then
            echo -e "${FAIL}\tNo active swap partition currently enabled"
    else
        echo -e "${PASS}\tVerify SWAP ('${SWAP_PARTITION}')"
    fi

    VGFREE=$(vgs ${ROOTVG_NAME} --noheadings -o vg_free --units M | cut -c3-)
    VGFREE=${VGFREE%M}
    VGFREE=${VGFREE%.*}

    if [[ ${VGFREE} -gt 102400 ]]; then
        echo -e "${FAIL}\tVolume group '${ROOTVG_NAME}' has ${VGFREE}M of \
space available - Allocation of additional space in the volume group required."
    elif [[ ${VGFREE} -gt 0 ]]; then
        echo -e "${MANUAL}\tVolume group '${ROOTVG_NAME}' has ${VGFREE}M of \
space available"
    fi

    echo -e "${INFORM}\t'lsblk' output ----------------------------------------"
    lsblk -i
    echo "---------------------------------------------------------------"
}

################################################################################
# Verify OMSA/MCP is installed and running [second pass]
################################################################################

verify_omsa() {
    OMSA_INSTALL_STATUS=$(dpkg -s srvadmin-all | awk '/^Status:/ {print $NF}')

    if [[ ${OMSA_INSTALL_STATUS} == installed ]] &&
        [[ -a ${OMCONFIG} ]] && [[ -a ${OMREPORT} ]] && [[ -a ${RACADM} ]]; then
        echo -e "${PASS}\tVerify Dell OMSA Install"
    else
        echo -e "${FAIL}\tVerify Dell OMSA Install"
    fi

    # Determine if OMSA is up-and-running
    OMSA_RUNNING=$(ps aux | grep -c [d]sm_sa_datamgrd)

    if [[ ${OMSA_RUNNING} -gt 0 ]]; then
        OMSA_RUNNING_STATUS=0
        echo -e "${PASS}\tVerify Dell OMSA Running"
    else
        ${OMSA_SBIN}/srvadmin-services.sh restart &> /dev/null
        if [[ $? -eq 0 ]]; then
            echo -e "${PASS}\tVerify Dell OMSA Running"
        else
            OMSA_RUNNING_STATUS=1
            echo -e "${FAIL}\tVerify Dell OMSA Running"
        fi
    fi
}

verify_mcp() {
    MCP_INSTALL_STATUS=$(dpkg -s hp-health | awk '/^Status:/ {print $NF}')

    if [[ ${MCP_INSTALL_STATUS} == installed ]] &&
        [[ -a ${HPASMCLI} ]] && [[ -a ${HPSSACLI} ]]; then
        echo -e "${PASS}\tVerify HP MCP Install"
    else
        echo -e "${FAIL}\tVerify HP MCP Install"
    fi

    # Determine if MCP is loaded
    MCP_LOADED=$(lsmod | egrep -c "^[h]p(ilo|sa)")
    MCP_RUNNING=$(ps aux | egrep -c "[h]p(sa|asm)")

    if [[ ${MCP_LOADED} -gt 0 ]] && [[ ${MCP_RUNNING} -gt 0 ]]; then
        MCP_RUNNING_STATUS=0
        echo -e "${PASS}\tVerify HP MCP loaded and running"
    else
        MCP_RUNNING_STATUS=1
        echo -e "${INFORM}\tIdentified missing HP MCP driver(s), attempting to modprobe"

        # Load the hp modules
        for driver in hpilo hpsa
        do
            lsmod | grep ^${driver} &> /dev/null
            if [[ $? -ne 0 ]]; then
                (modprobe ${driver} \
                    && echo -e "${PASS}\tSuccessfully loaded HP driver '${driver}'") \
                    || echo -e "${FAIL}\Unable to 'modprobe ${driver}'"
            fi
        done

        # Start the hp-health service
        /etc/init.d/hp-health start &>/dev/null

        if [[ $? -eq 0 ]]; then
            echo -e "${PASS}\Started hp-health service"
        else
            echo -e "${FAIL}\Started hp-health service"
        fi

        # Determine if MCP is loaded again
        sleep 10
        MCP_LOADED=$(lsmod | egrep -c "^[h]p(ilo|sa)")
        MCP_RUNNING=$(ps aux | egrep -c "[h]p(sa|asm)")

        if [[ ${MCP_LOADED} -eq 2 ]] && [[ ${MCP_RUNNING} -eq 2 ]]; then
            MCP_RUNNING_STATUS=0
            echo -e "${PASS}\tVerify HP MCP is loaded"
        else
            MCP_RUNNING_STATUS=1
            echo -e "${FAIL}\tVerify HP MCP is loaded"
        fi
    fi
}

verify_ilo_textcons() {
    # Ensure that Ubuntu is configured to properly allow TEXTCONS console

    GRUB_CONF="/etc/default/grub"
    LINUX_DEFAULT=$(awk -F\" '/^GRUB_CMDLINE_LINUX_DEFAULT/ {print $2}' ${GRUB_CONF})
    LINUX_DEFAULT_NEW="${LINUX_DEFAULT}"

    for i in vga=normal nomodeset
    do
        if [[ -z $(echo "${LINUX_DEFAULT}" | grep "$i") ]]; then
            LINUX_DEFAULT_NEW="$LINUX_DEFAULT_NEW $i"
        fi
    done

    if [[ -a ${GRUB_CONF} ]]; then
        if [[ ${LINUX_DEFAULT_NEW} ]]; then
            (sed -i "s@^GRUB_CMDLINE_LINUX_DEFAULT.*@GRUB_CMDLINE_LINUX_DEFAULT=\"${LINUX_DEFAULT_NEW}\"@g" ${GRUB_CONF} \
                && update-grub &> /dev/null \
                && echo -e "${PASS}\tVerify HP iLO textcons mode set in grub") \
                || echo -e "${FAIL}\tVerify HP iLO textcons mode set in grub"
        else
            echo -e "${FAIL}\tVerify HP iLO textcons mode set in grub"
        fi
    fi
}

################################################################################
# Verify Hyperthreading [second pass]
################################################################################

verify_hyperthreading() {
    if [[ ${VENDOR} == Dell ]]; then
        if [[ ${OMSA_RUNNING_STATUS} -eq 0 ]]; then
            HYPER_THREADING=$(${OMREPORT} chassis processors index=0 | grep Hyper -A2 \
                | awk '/^Enabled/ {print $NF}')

            if [[ ${HYPER_THREADING} == Yes ]]; then
                echo -e "${PASS}\tVerify Hyperthreading"
            else
                echo -e "${FAIL}\tVerify Hyperthreading"
            fi
        else
            echo -e "${FAIL}\tUnable to verify [Hyperthreading information] without \
    OMSA running"
        fi
    elif [[ ${VENDOR} == HP ]]; then
        if [[ ${MCP_RUNNING_STATUS} -eq 0 ]]; then
            HYPER_THREADING=$(${HPASMCLI} -s "show ht" | awk '/Processor/ {print $NF}' \
                | sed 's/.$//')

            if [[ ${HYPER_THREADING} == enabled ]]; then
                echo -e "${PASS}\tVerify Hyperthreading"
            else
                echo -e "${FAIL}\tVerify Hyperthreading"
            fi
        else
            echo -e "${FAIL}\tUnable to verify [Hyperthreading information] without \
    HP MCP driver(s) loaded"
        fi
    fi
}

################################################################################
# Verify BIOS [second pass]
################################################################################

verify_bios() {
    if [[ ${VENDOR} == Dell ]]; then
        CHASSIS=$(${OMREPORT} system summary | awk '/^Chassis Model/ {print $NF}')

        if [[ ${CHASSIS} == R710 ]]; then
            EXTSERIAL=$(${OMREPORT} chassis biossetup \
                | awk -F: '/^External Serial Connector/ {print $NF}' | cut -c2-)
            if [[ ${EXTSERIAL} == "Remote Access Device" ]]; then
                echo -e "${PASS}\tVerify BIOS ExtSerial"
            else
                echo -e "${FAIL}\tVerify BIOS ExtSerial"
            fi

            FBR=$(${OMREPORT} chassis biossetup \
                | awk -F: '/Failsafe BAUD Rate/ {print $NF}' | cut -c2-)
            if [[ ${FBR} == 115200 ]]; then
                echo -e "${PASS}\tVerify BIOS FailSafeBaud"
            else
                echo -e "${FAIL}\tVerify BIOS FailSafeBaud"
            fi

            SERIALCOM=$(${OMREPORT} chassis biossetup \
                | awk -F: '/^Serial Communications / {print $NF}' | cut -c2-)
            if [[ ${SERIALCOM} == "On with Console Redirection via COM2" ]]; then
                echo -e "${PASS}\tVerify BIOS SerialCom"
            else
                echo -e "${FAIL}\tVerify BIOS SerialCom"
            fi

            CRAB=$(${OMREPORT} chassis biossetup \
                | awk -F: '/^Console Redirection After Boot/ {print $NF}' | cut -c2-)
            if [[ ${CRAB} == Enabled ]]; then
                echo -e "${PASS}\tVerify BIOS ConsoleRedirection"
            else
                echo -e "${FAIL}\tVerify BIOS ConsoleRedirection"
            fi

            CSTATES=$(${OMREPORT} chassis biossetup \
                | awk -F: '/^Processor C State Control/ {print $NF}' | cut -c2-)
            if [[ ${CSTATES} == Disabled ]]; then
                echo -e "${PASS}\tVerify BIOS Performance profile"
            else
                echo -e "${FAIL}\tVerify BIOS Performance profile"
            fi
        else
            EXTSERIAL=$(${OMREPORT} chassis biossetup display=shortnames \
                | awk -F: '/^ExtSerialConnector/ {print $NF}' | cut -c2-)
            if [[ ${EXTSERIAL} == RemoteAccDevice ]]; then
                echo -e "${PASS}\tVerify BIOS ExtSerial"
            else
                echo -e "${FAIL}\tVerify BIOS ExtSerial"
            fi

            FBR=$(${OMREPORT} chassis biossetup display=shortnames \
                | awk -F: '/^FailSafeBaud/ {print $NF}' | cut -c2-)
            if [[ ${FBR} == 115200 ]]; then
                echo -e "${PASS}\tVerify BIOS FailSafeBaud"
            else
                echo -e "${FAIL}\tVerify BIOS FailSafeBaud"
            fi

            SERIALCOM=$(${OMREPORT} chassis biossetup display=shortnames \
                | awk -F: '/^SerialComm/ {print $NF}' | cut -c2-)
            if [[ ${SERIALCOM} == OnConRedirCom2 ]]; then
                echo -e "${PASS}\tVerify BIOS SerialCom"
            else
                echo -e "${FAIL}\tVerify BIOS SerialCom"
            fi

            CRAB=$(${OMREPORT} chassis biossetup display=shortnames \
                | awk -F: '/^RedirAfterBoot/ {print $NF}' | cut -c2-)
            if [[ ${CRAB} == Enabled ]]; then
                echo -e "${PASS}\tVerify BIOS ConsoleRedirection"
            else
                echo -e "${FAIL}\tVerify BIOS ConsoleRedirection"
            fi

            SYSPROFILE=$(${OMREPORT} chassis biossetup display=shortnames \
                | awk -F: '/^SysProfile/ {print $NF}' | cut -c2-)
            if [[ ${SYSPROFILE} == PerfOptimized ]]; then
                echo -e "${PASS}\tVerify BIOS Performance profile"
            else
                echo -e "${FAIL}\tVerify BIOS Performance profile"
            fi
        fi

        cfgSerialBaudRate=$(${RACADM} getconfig -g cfgSerial \
            | awk -F= '/^cfgSerialBaudRate/ {print $NF}')
        if [[ ${cfgSerialBaudRate} == 115200 ]]; then
            echo -e "${PASS}\tVerify racadm SerialBaudRate"
        else
            echo -e "${FAIL}\tVerify racadm SerialBaudRate"
        fi

        cfgSerialConsoleEnable=$(${RACADM} getconfig -g cfgSerial \
            | awk -F= '/^cfgSerialConsoleEnable/ {print $NF}')
        if [[ ${cfgSerialConsoleEnable} == 1 || Enabled ]]; then
            echo -e "${PASS}\tVerify racadm SerialConsoleEnable"
        else
            echo -e "${FAIL}\tVerify racadm SerialConsoleEnable"
        fi

        cfgSerialSshEnable=$(${RACADM} getconfig -g cfgSerial \
            | awk -F= '/^cfgSerialSshEnable/ {print $NF}')
        if [[ ${cfgSerialSshEnable} == 1 || Enabled ]]; then
            echo -e "${PASS}\tVerify racadm SerialSshEnable"
        else
            echo -e "${FAIL}\tVerify racadm SerialSshEnable"
        fi

        cfgSerialHistorySize=$(${RACADM} getconfig -g cfgSerial \
            | awk -F= '/^cfgSerialHistorySize/ {print $NF}')
        if [[ ${cfgSerialHistorySize} == 2000 ]]; then
            echo -e "${PASS}\tVerify racadm SerialHistorySize"
        else
            echo -e "${FAIL}\tVerify racadm SerialHistorySize"
        fi
    elif [[ ${VENDOR} == HP ]]; then
        ILO_VERSION=$(${HPONCFG} -g | awk '/^Version/ {print $2}')
        if [[ ${ILO_VERSION} == 4.* || ${ILO_VERSION} == 5.* ]]; then

            # Dump current settings
            ILO_XML="/home/rack/.adc/ilo_settings.xml"
            ${HPONCFG} -a -w ${ILO_XML} &>/dev/null

            # Check if "HP Static High Performance Mode" is set
            HOST_POWER_SAVER_STATUS=$(grep 'HOST_POWER_SAVER="4"' ${ILO_XML})
            if [[ ${HOST_POWER_SAVER_STATUS} ]]; then
                echo -e "${PASS}\tVerify HP Static High Performance Mode"
            else
                echo -e "${FAIL}\tVerify HP Static High Performance Mode"
            fi
            rm -rf ${ILO_XML}
        fi
    fi
}

################################################################################
# Verify CPU [second pass]
################################################################################

verify_cpu() {
    if [[ ${VENDOR} == Dell ]]; then
        if [[ ${OMSA_RUNNING_STATUS} -eq 0 ]]; then
            CPU_HEALTH=$(${OMREPORT} chassis processors | awk '/^Health :/ {print $NF}')

            if [[ ${CPU_HEALTH} == Ok ]]; then
                echo -e "${PASS}\tVerify CPU health \
    (`grep -m 1 "model name" /proc/cpuinfo | cut -c '14-' | tr -d '\n'; \
    echo -en " (x$(grep -c "model name" /proc/cpuinfo) total)"`)"
            else
                echo -e "${FAIL}\tVerify CPU health"
            fi
        else
            echo -e "${FAIL}\tUnable to verify [CPU information] without OMSA running"
        fi
    elif [[ ${VENDOR} == HP ]]; then
        if [[ ${MCP_RUNNING_STATUS} -eq 0 ]]; then
            CPU_HEALTH=$(${HPASMCLI} -s "show server" | awk '/Status/ {print $NF}')
            CPU_NUMBER=0

            for proc in ${CPU_HEALTH}
            do
                if [[ ${proc} == Ok ]]; then
                    echo -e "${PASS}\tVerify CPU (${CPU_NUMBER}) health"
                else
                    echo -e "${FAIL}\tVerify CPU (${CPU_NUMBER}) health"
                fi
                ((CPU_NUMBER++))
            done
        else
            echo -e "${FAIL}\tUnable to verify [CPU information] without \
    HP MCP driver(s) loaded"
        fi
    fi
}

################################################################################
# Verify overall system status: Everything should be reporting as OK [second pass]
################################################################################

verify_chassis_status() {
    if [[ ${VENDOR} == Dell ]]; then
        if [[ ${OMSA_RUNNING_STATUS} -eq 0 ]]; then
            ${OMREPORT} chassis | grep -A10 SEV | grep -v SEV | while read line
            do
                COMPONENT=$(echo $line | awk -F: '{print $NF}' | cut -c2-)
                if [[ $(echo ${line} | grep ^Ok) ]]; then
                    echo -e "${PASS}\tVerify chassis ${COMPONENT}"
                else
                    echo -e "${FAIL}\tVerify chassis ${COMPONENT}"
                fi
            done
        else
            echo -e "${FAIL}\tUnable to verify [Chassis status] without OMSA running"
        fi
    elif [[ ${VENDOR} == HP ]]; then
        if [[ ${MCP_RUNNING_STATUS} -eq 0 ]]; then
            # Fans
            FAN_STATUS=$(${HPASMCLI} -s "show fans" | awk '{print $1 " " $3}' | grep No)

            if [[ ${FAN_STATUS} ]]; then
                echo -e "${FAIL}\tVerify chassis fans"
            else
                echo -e "${PASS}\tVerify chassis fans"
            fi

            # Power Supplies
            POWERSUPPLY_STATUS=$(${HPASMCLI} -s "show powersupply" | awk '/Condition/ {print $NF}' \
                | grep -v Ok)

            if [[ ${POWERSUPPLY_STATUS} ]]; then
                echo -e "${FAIL}\tVerify chassis powersupply"
            else
                echo -e "${PASS}\tVerify chassis powersupply"
            fi
        else
            echo -e "${FAIL}\tUnable to verify [Chassis information] without \
    HP MCP driver(s) loaded"
        fi
    fi
}

################################################################################
# Verify memory health [second pass]
# Compare number of slots used with number reporting 'OK' at the bottom)
################################################################################

verify_memory_status() {
    if [[ ${VENDOR} == Dell ]]; then
        if [[ ${OMSA_RUNNING_STATUS} -eq 0 ]]; then
            MEMORY_HEALTH=$(${OMREPORT} chassis memory | awk '/^Health :/ {print $NF}')
            MEMORY_SLOTS_USED=$(${OMREPORT} chassis memory \
                | awk -F: '/^Slots Used/ {print $NF}' | cut -c2-)
            MEMORY_OK_COUNT=$(${OMREPORT} chassis memory | grep -c "Status         : Ok")

            if [[ ${MEMORY_HEALTH} == Ok && \
                ( ${MEMORY_SLOTS_USED} -eq ${MEMORY_OK_COUNT} ) ]]; then
                echo -e "${PASS}\tVerify memory status"
            else
                echo -e "${FAIL}\tVerify memory status"
            fi
        else
            echo -e "${FAIL}\tUnable to verify [Memory information] without OMSA running"
        fi
    elif [[ ${VENDOR} == HP ]]; then
        if [[ ${MCP_RUNNING_STATUS} -eq 0 ]]; then
            MEMORY_HEALTH=$(${HPASMCLI} -s "show dimm" | awk '/^Status/ {print $NF}' \
                | grep -v Ok)
            MEMORY_SLOTS_USED=$(${HPASMCLI} -s "show dimm" | grep -c Present)
            MEMORY_OK_COUNT=$(${HPASMCLI} -s "show dimm" | awk '/^Status/ {print $NF}' \
                | wc -l)

            if [[ -z ${MEMORY_HEALTH} && \
                ( ${MEMORY_SLOTS_USED} -eq ${MEMORY_OK_COUNT} ) ]]; then
                echo -e "${PASS}\tVerify memory status"
            else
                echo -e "${FAIL}\tVerify memory status"
            fi
        else
            echo -e "${FAIL}\tUnable to verify [Memory information] without \
    HP MCP driver(s) loaded"
        fi
    fi
}

################################################################################
# Verify RAID status [second pass]
################################################################################

verify_raid_status() {
    if [[ ${VENDOR} == Dell ]]; then
        if [[ ${OMSA_RUNNING_STATUS} -eq 0 ]]; then
            # Enumerate storage controllers
            STORAGE_CONTROLLERS=$(${OMREPORT} storage controller | awk '/^ID/ {print $NF}')

            # Confirm vdisk(s) across all controllers are healthy
            for CONTROLLER_ID in ${STORAGE_CONTROLLERS}
            do
                for VDISK in $(${OMREPORT} storage vdisk controller=${CONTROLLER_ID} \
                    | awk '/^ID/ {print $NF}')
                do
                    VDISK_STATE=$(${OMREPORT} storage vdisk controller=${CONTROLLER_ID} \
                        vdisk=${VDISK} | awk -F: '/^State/ {print $NF}' | cut -c2-)

                    if [[ ${VDISK_STATE} == Ready ]]; then
                        echo -e "${PASS}\tVerify vdisk=${VDISK}"
                    elif [[ ${VDISK_STATE} == Initialization || \
                            ${VDISK_STATE} == "Background Initialization" ]]; then
                        echo -e "${PASS}\tVerify vdisk=${VDISK} (\
    $(${OMREPORT} storage vdisk controller=0 | awk '/^Progress/ {print $3}') initialized)"
                    else
                        echo -e "${FAIL}\tVerify vdisk=${VDISK} (${VDISK_STATE})"
                    fi
                done
            done

            # Confirm pdisk(s) across all controllers are healthy
            for CONTROLLER_ID in ${STORAGE_CONTROLLERS}
            do
                for DISK in $(${OMREPORT} storage pdisk controller=${CONTROLLER_ID} \
                    | awk '/^Name/ {print $NF}')
                do
                    DISK_INFO=$(${OMREPORT} storage pdisk controller=${CONTROLLER_ID} \
                        pdisk=${DISK} | egrep "^(Status|State)")
                    DISK_STATUS=$(echo "${DISK_INFO}" | awk -F: '/^Status/ {print $NF}' \
                        | cut -c2-)
                    DISK_STATE=$(echo "${DISK_INFO}" | awk -F: '/^State/ {print $NF}' \
                        | cut -c2-)

                    if [[ ${DISK_STATUS} == Ok && ${DISK_STATE} == Online ]]; then
                        echo -e "${PASS}\tVerify pdisk=${DISK}"
                    else
                        echo -e "${FAIL}\tVerify pdisk=${DISK} (Status: \
    ${DISK_STATUS}; ${DISK_STATE})"
                    fi
                done
            done

            # Confirm the storage battery is functional
            for CONTROLLER_ID in ${STORAGE_CONTROLLERS}
            do
                BATTERY_INFO=$(${OMREPORT} storage battery controller=${CONTROLLER_ID} \
                    | egrep "^(Status|State|ID)")
                BATTERY_STATUS=$(echo "${BATTERY_INFO}" | awk -F: '/^Status/ {print $NF}' \
                    | cut -c2-)
                BATTERY_STATE=$(echo "${BATTERY_INFO}" | awk -F: '/^State/ {print $NF}' \
                    | cut -c2-)

                if [[ ${BATTERY_STATUS} == Ok && ${BATTERY_STATE} == Ready ]]; then
                    echo -e "${PASS}\tVerify battery on controller=${CONTROLLER_ID}"
                else
                    echo -e "${FAIL}\tVerify battery on controller=${CONTROLLER_ID} (Status: \
    ${BATTERY_STATUS}; ${BATTERY_STATE})"
                fi
            done

        else
            echo -e "${FAIL}\tUnable to verify [RAID information] without OMSA running"
        fi
    elif [[ ${VENDOR} == HP ]]; then
        # Controller by serial#
        STORAGE_CONTROLLERS=$(${HPSSACLI} controller all show | awk '/Array / {print $NF}' \
            | sed 's@)@@g')

        # Confirm logicaldrive(s) across all controllers are healthy
        for CONTROLLER in ${STORAGE_CONTROLLERS}
        do
            for LOGICALDRIVE in $(${HPSSACLI} controller serialnumber=${CONTROLLER} logicaldrive all show \
                | awk '/logicaldrive / {print $2}')
            do
                LOGICALDISK_STATE=$(${HPSSACLI} controller serialnumber=${CONTROLLER} logicaldrive ${LOGICALDRIVE} show \
                    | awk '/  Status:/ {print $NF}')

                if [[ ${LOGICALDISK_STATE} == OK ]]; then
                    echo -e "${PASS}\tVerify logicaldrive=${LOGICALDRIVE}"
                else
                    echo -e "${FAIL}\tVerify logicaldrive=${LOGICALDRIVE}"
                fi
            done
        done

        # Confirm physicaldrive(s) across all controllers are healthy
        for CONTROLLER in ${STORAGE_CONTROLLERS}
        do
            for PHYSICALDRIVE in $(${HPSSACLI} controller serialnumber=${CONTROLLER} physicaldrive all show | awk '/physicaldrive / {print $2}');
            do
                PHYSICALDRIVE_STATUS=$(${HPSSACLI} controller serialnumber=${CONTROLLER} physicaldrive ${PHYSICALDRIVE} show | awk '/  Status:/ {print $NF}')

                if [[ ${PHYSICALDRIVE_STATUS} == OK ]]; then
                    echo -e "${PASS}\tVerify physicaldrive=${PHYSICALDRIVE}"
                else
                    echo -e "${FAIL}\tVerify physicaldrive=${PHYSICALDRIVE}"
                fi
            done
        done

        # Verify storage battery capacity is healthy
        for CONTROLLER in ${STORAGE_CONTROLLERS}
        do
            BATTERY_STATUS=$(${HPSSACLI} controller serialnumber=${CONTROLLER} show status \
                | awk '/ Battery.*Status/ {print $NF}')

            if [[ ${BATTERY_STATUS} == OK ]]; then
                echo -e "${PASS}\tVerify storage battery on controller=${CONTROLLER}"
            else
                echo -e "${FAIL}\tVerify storage battery on controller=${CONTROLLER}"
            fi
        done
    fi
}

################################################################################
# Verify DRAC configuration [second pass]
################################################################################

verify_drac_configuration() {
    # Attempt to ping the DRAC gateway

    if [[ ${VENDOR} == Dell ]]; then
        DRAC_VERSION=$(${OMREPORT} system summary \
            | grep "^Remote Access Controller Information" -A7 \
            | awk '/^Product/ {print $3}')

        if [[ ${DRAC_VERSION} == iDRAC7 ]]; then
            # Only way I can think to do this without CORE data
            DRAC_INFO=$(${RACADM} getniccfg \
                | egrep -v "::|DHCP6|IPv6|^$|LOM Status|NIC Selection|Static ")
            DRAC_GATEWAY=$(${RACADM} getniccfg | awk '/^Gateway/ && ($NF !~ "::") {print $NF}')

            if [[ ${DRAC_GATEWAY} ]]; then
                (timeout 60s ${RACADM} ping ${DRAC_GATEWAY} >/dev/null \
                    && echo -e "${PASS}\tVerify DRAC connectivity") \
                    || echo -e "${FAIL}\tVerify DRAC connectivity (Unable to ping \
        ${DRAC_GATEWAY} from DRAC interface)"
            else
                echo -e "${FAIL}\tUnable to validate DRAC configuration"
            fi
        else
            echo -e "${INFORM}\tiDRAC7 not found, unable to test DRAC connectivity"
        fi
    fi
}

################################################################################
# Verify network hardware [second pass]
################################################################################

verify_network_hardware() {
    echo -e "${INFORM}\tDetected ( $(lspci | egrep -c "10-G|10G") ) 10G adapters"
}

################################################################################
# Enable network interfaces and enumerate [second pass]
################################################################################

verify_network_cabling() {
    # Bring up interfaces and pause for a moment
    for iface in $(ip -o l | awk '{print $2}' | sed 's/://' \
        | egrep -v "^(lo|bond|br)"); do ip link set dev $iface up; done
    sleep 5

    for iface in $(ip -o l | awk '{print $2}' | sed 's/://' \
        | egrep -v "^(lo|bond|br)"); do ethtool $iface \
        | egrep "Settings for|(Speed|Link detected):"; done > ${TMP_FILE}

        sed -i 's@10Mb/s@10Mb/s      (IMPROPER SPEED)@g' ${TMP_FILE}
        sed -i 's@100Mb/s@100Mb/s     (IMPROPER SPEED)@g' ${TMP_FILE}

        echo -e "${INFORM}\tVerify network cabling ----------------------------\
----"
        colorize_status \
        | sed -e 's@Speed@      Speed@g;s@Link detected@       Link@g;s@Settings for @@g'
        echo "---------------------------------------------------------------"
}

################################################################################
# Simple colorization function
################################################################################

colorize_status() {
    if [[ ${BBCODE} -eq 1 ]]; then
        while read line
        do
            if [[ $(echo "$line" | awk '/: yes/') ]]; then
                echo "$line" | awk '/yes/ {gsub(/yes/,\
                    "[b][color=green]&[/color][/b]");print}'
            elif [[ $(echo "$line" | awk '/: no/') ]]; then
                echo "$line" | awk '/no/ {gsub(/no/,\
                    "[b][color=red]&[/color][/b]");print}'
            elif [[ $(echo "$line" | awk '/: Unknown\!/') ]]; then
                echo "$line" | awk '/Unknown\!/ {gsub(/Unknown\!/,\
                    "[b][color=darkgoldenrod]&[/color][/b]");print}'
            else
                echo "$line"
            fi
        done < ${TMP_FILE}
    else
        while read line
        do
            if [[ $(echo "$line" | awk '/: yes/') ]]; then
                echo "$line" | awk '/yes/ {gsub(/yes/,\
                    "\033[1;32m&\033[1;000m");print}'
            elif [[ $(echo "$line" | awk '/: no|IMPROPER SPEED/') ]]; then
                echo "$line" | awk '/no|IMPROPER SPEED/ {gsub(/no|IMPROPER SPEED/,\
                    "\033[1;31m&\033[1;000m");print}'
            elif [[ $(echo "$line" | awk '/: Unknown\!/') ]]; then
                echo "$line" | awk '/Unknown\!/ {gsub(/Unknown\!/,\
                    "\033[1;33m&\033[1;000m");print}'
            else
                echo "$line"
            fi
        done < ${TMP_FILE}
    fi

    rm -f ${TMP_FILE}
}

################################################################################
# Privilege Check
################################################################################

verify_privileges() {
    # Verify root access

    if [[ $EUID -ne 0 ]]; then
        echo -e "\n${FAIL}\tRequires root access to perform changes\n"
        exit 1
    fi
}

################################################################################
# Generate ADC Template
################################################################################

generate_adc_template() {
    SERVER_NUMBER=$(cat /root/.rackspace/server_number 2>/dev/null)
    DATACENTER=$(cat /root/.rackspace/datacenter 2>/dev/null)

    echo -e "\t${BLUE}   RPC Linux ADC${NORMAL}"
    echo -e "\t${BOLD}QC Report for server ${SERVER_NUMBER} (${DATACENTER}: \
${RS_SERVER_NAME})${NOBOLD}"

    # Determine counts before file is manipulated
    FAILED_COUNT=$(grep -c "FAILED" ${SECONDPASS_LOG})
    MANUAL_COUNT=$(expr $(grep -c "MANUAL" ${SECONDPASS_LOG}) + \
        $(grep -c "MANUAL" ${FIRSTPASS_LOG}))
    FIXED_COUNT=$(grep -c "FIXED" ${FIRSTPASS_LOG})
    PASSED_COUNT=$(grep -c "PASSED" ${SECONDPASS_LOG})
    INFORM_COUNT=$(grep -c "INFORM" ${SECONDPASS_LOG})

    # Sanitize output for informative messages to print properly below
    if [[ BBCODE -eq 1 ]]; then
        sed -i '/^\[/!s/^/'"${INFORM_ESCAPED}"'  /g' ${SECONDPASS_LOG}

        # Output information that failed or is meant to be informative
        awk '/FAILED/' ${SECONDPASS_LOG}
        awk '/MANUAL/' ${FIRSTPASS_LOG}
        awk '/MANUAL/' ${SECONDPASS_LOG}
        awk '/INFORM/' ${SECONDPASS_LOG}
    else
        # Output information that failed or is meant to be informative
        awk '/FAILED/' ${SECONDPASS_LOG}
        awk '/MANUAL/' ${FIRSTPASS_LOG}
        awk '/MANUAL/' ${SECONDPASS_LOG}
        awk '$1 !~ /PASSED|FAILED|MANUAL|FIXED/' ${SECONDPASS_LOG}
    fi

    echo -e "\n--"
    echo -e "${BOLD}SUMMARY${NOBOLD}"
    echo -e "   ${FAILED_COUNT}\t${FAIL} Check(s) failed which require intervention"
    echo -e "   ${MANUAL_COUNT}\t${MANUAL} Requires additional troubleshooting"
    echo -e "   ${FIXED_COUNT}\t${FIXED}  Configuration was changed (output in \
${ADC_DIR}/{first,second}pass.log)"
    echo -e "   ${PASSED_COUNT}\t${PASS} Check(s) passed"
    echo -e "   ${INFORM_COUNT}\t${INFORM} Informative message(s)"
    echo -e "--\n"

    # Create non-colorized version for ADC email
    cp -f ${ADC_TEMPLATE} ${ADC_TEMPLATE_COLOR}
    sed -ir "s:\x1B\[[0-9;]*[mK]::g" ${ADC_TEMPLATE}
    cat -A ${ADC_TEMPLATE} | sed -e 's/\^\[(B/ /g;s/\$//g;s/\^I/\t/g;s/\^O//g' > ${ADC_TEMPLATE}.new
    mv ${ADC_TEMPLATE}.new ${ADC_TEMPLATE}

}

################################################################################
# Indicate the status for ADC logic
################################################################################

adc_status() {
    # Output to terminal for RBA
    echo "RBA START STATUS:"
    echo "$1"
    echo "RBA END STATUS:"
    echo "RBA START DATA:"
    echo "$3"
    echo "RBA END DATA:"

    # Output to file as well
    cat << EOF > $2
RBA START STATUS:
$1
RBA END STATUS:
RBA START DATA:
$3
RBA END DATA:
EOF
}

################################################################################
# Firstpass QC process
################################################################################

firstpass_qc() {
    get_version                 &> ${FIRSTPASS_LOG}
    validate_dns                &>> ${FIRSTPASS_LOG}
    set_maxsessions             &>> ${FIRSTPASS_LOG}
    remove_deleteme             &>> ${FIRSTPASS_LOG}
    expand_nova                 &>> ${FIRSTPASS_LOG}
    validate_hosts              &>> ${FIRSTPASS_LOG}
    validate_modules            &>> ${FIRSTPASS_LOG}
    install_dellhp_tools        &>> ${FIRSTPASS_LOG}

    if [[ ${VERSION} == 12.04 ]]; then
        # Configure DRAC serial console on Dell chassis
        if [[ ${VENDOR} == Dell ]]; then
            drac_serial_console &>> ${FIRSTPASS_LOG}
        fi

        if [[ ${KERNEL_UPGRADE} -eq 1 ]]; then
            # Upgrade the kernel
            upgrade_kernel_1204 &>> ${FIRSTPASS_LOG}
        fi

    elif  [[ ${VERSION} == 14.04 && ${KERNEL_UPGRADE} -eq 1 ]]; then
        # Upgrade the kernel
        upgrade_kernel_1404     &>> ${FIRSTPASS_LOG}
    fi

    update_packages             &>> ${FIRSTPASS_LOG}
    install_tools               &>> ${FIRSTPASS_LOG}

    if [[ ${VENDOR} == Dell ]]; then
        update_dell_bios        &>> ${FIRSTPASS_LOG}
    elif [[ ${VENDOR} == HP ]]; then
        ilo_textcons_grub       &>> ${FIRSTPASS_LOG}
        update_hp_bios          &>> ${FIRSTPASS_LOG}
    fi

    if [[ ${VERSION} == 12.04 ]]; then
        # Re-align udev only on 12.04
        regen_udev
        bdf_mac_sort            &>> ${FIRSTPASS_LOG}
        validate_udev_changes
    fi

    if [[ ${ADC_FAIL} -eq 1 ]]; then
        adc_status FAIL ${ADC_FP_STATUS} "Requires reboot before completing firstpass to enable the Lifecycle controller"
    elif [[ ${ADC_FAIL} -eq 2 ]]; then
        adc_status FAIL ${ADC_FP_STATUS} "Requires reboot before completing firstpass to enable linux-crashdump"
    else
        adc_status PASS ${ADC_FP_STATUS} "RPC first pass completed successfully"
    fi
}

################################################################################
# Secondpass QC process
################################################################################

secondpass_qc() {
    get_version                 &> /dev/null
    verify_ubuntu_version       &> ${SECONDPASS_LOG}
    verify_hosts                &>> ${SECONDPASS_LOG}
    verify_timezone             &>> ${SECONDPASS_LOG}
    verify_kdump_enabled        &>> ${SECONDPASS_LOG}
    verify_crashdump_memory_alloc \
                                &>> ${SECONDPASS_LOG}
    verify_dns                  &>> ${SECONDPASS_LOG}
    verify_drivers              &>> ${SECONDPASS_LOG}
    verify_filesystem           &>> ${SECONDPASS_LOG}

    if [[ ${VENDOR} == Dell ]]; then
        verify_omsa             &>> ${SECONDPASS_LOG}
    elif [[ ${VENDOR} == HP ]]; then
        verify_mcp              &>> ${SECONDPASS_LOG}
        verify_ilo_textcons     &>> ${SECONDPASS_LOG}
    fi

    verify_hyperthreading       &>> ${SECONDPASS_LOG}
    verify_bios                 &>> ${SECONDPASS_LOG}
    verify_cpu                  &>> ${SECONDPASS_LOG}
    verify_chassis_status       &>> ${SECONDPASS_LOG}
    verify_memory_status        &>> ${SECONDPASS_LOG}
    verify_raid_status          &>> ${SECONDPASS_LOG}
    verify_drac_configuration   &>> ${SECONDPASS_LOG}
    verify_network_hardware     &>> ${SECONDPASS_LOG}
    verify_network_cabling      &>> ${SECONDPASS_LOG}
    generate_adc_template       &> ${ADC_TEMPLATE}

    # Output to the console if BBCode isn't enabled
    if [[ ${BBCODE} -eq 0 && QUIET -eq 0 ]]; then
        cat ${ADC_TEMPLATE_COLOR}
    fi

    # Indicate to ADC how secondpass completed
    if [[ $(egrep "FAILED|MANUAL" ${ADC_DIR}/secondpass.log) ]]; then
        adc_status FAIL ${ADC_SP_STATUS} "$(egrep "^(FAILED|MANUAL)" ${ADC_TEMPLATE})"
    else
        adc_status PASS ${ADC_SP_STATUS} "RPC second pass completed successfully"
    fi
}

################################################################################
# Clear OMSA logs and history; Mark the server as QC'd
################################################################################

complete_qc() {
    echo -e "`date`\n\rSERVER QC-INTENSIFICATION COMPLETE" > /root/qc-status

    if [[ ${VENDOR} == Dell ]]; then
        ${OMCONFIG} system alertlog action=clear
        ${OMCONFIG} system esmlog action=clear
    elif [[ ${VENDOR} == HP ]]; then
        ${HPASMCLI} -s "clear iml"
    fi

    rm -f /root/.rackspace/rackpass /root/.bash_history
    history -c
}

################################################################################
# Add SSH key(s) to the server
################################################################################

add_ssh_keys() {
    AUTHORIZED_KEYS="/root/.ssh/authorized_keys"

    # Ensure directory exists and has the proper permissions
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh

    # Add the key from input
    while IFS=';' read -ra KEYS
    do
        for KEY in "${KEYS[@]}"
        do
            cat << EOF >> ${AUTHORIZED_KEYS}
${KEY}
EOF
        done
    done <<< "$1"

    # Verify on HP kicks that 'PermitRootLogin without-password' is enabled
    get_version &> /dev/null

    if [[ ${VENDOR} == HP ]]; then
        SSH_CONFIG="/etc/ssh/sshd_config"
        if [[ -a ${SSH_CONFIG} ]]; then
            (sed -i 's@^PermitRootLogin no@PermitRootLogin without-password@g' ${SSH_CONFIG} \
                && echo -e "${PASS}\t'PermitRootLogin without-password' verified in ${SSH_CONFIG}") \
                || echo -e "${FAIL}\tUnable to modify 'PermitRootLogin without-password' in ${SSH_CONFIG}"
            (service ssh restart &> /dev/null \
                && echo -e "${PASS}\tSSH restart") \
                || echo -e "${FAIL}\tSSH restart"
        fi
    fi
}

################################################################################
# Test networking connectivity to Management (bond0) and ServiceNet
################################################################################

network_connectivity_testing() {
    # Determine current IP information
    MGMT_INT=$(route -n | awk '/^0.0.0.0/ {print $NF}')
    MGMT_INT_INFO=$(grep "iface ${MGMT_INT}" -A20 /etc/network/interfaces \
        | sed -e '/^$/,$d')
    MGMT_GATEWAY=$(echo "${MGMT_INT_INFO}" \
        | awk '/gateway / {sub(/\/[0-9]+$/, "", $2); print $2; exit}')
    SN_INT=$(route -n | awk '!/"${MGMT_INT}"|0.0.0.0/ {print $NF}' | tail -n +3 \
        | uniq)

    echo -e "\n${YELLOW}Verifying Management (bond0)`if [[ ${SN_INT} ]]; then
    echo " and Service (${SN_INT})"; fi` network(s):${NORMAL}"
    PRIMARY=$(awk '/Currently Active Slave/ {print $NF}' /proc/net/bonding/bond0)
    SECONDARY=$(awk '/Slave Interface/ {print $NF}' /proc/net/bonding/bond0 \
        | grep -v "${PRIMARY}")

    echo -e "\n${YELLOW}Manual failover to '${SECONDARY}' on bond0:${NORMAL}"
    ifenslave -c bond0 ${SECONDARY} && ping -c4 ${MGMT_GATEWAY}

    echo -e "\n${YELLOW}Manual failover to '${PRIMARY}' on bond0:${NORMAL}"
    ifenslave -c bond0 ${PRIMARY} && ping -c4 ${MGMT_GATEWAY}

    if [[ ${SN_INT} ]]; then
        SN_GATEWAY=$(route -n | awk "/${SN_INT}/" | awk '($2 != "0.0.0.0") {print $2}' \
            | uniq)
        echo -e "\n${YELLOW}Pinging ServiceNet gateway from ${SN_INT}:${NORMAL}"
        ping -c3 ${SN_GATEWAY}
    fi

    for BOND in $(ls -1 /proc/net/bonding)
    do
        PRIMARY=$(awk '/Currently Active Slave/ {print $NF}' /proc/net/bonding/${BOND})
        PRIMARY_SPEED=$(grep -A2 "Slave Interface: ${PRIMARY}" /proc/net/bonding/${BOND} | awk '/Speed:/ {print $2}')
        SECONDARY=$(awk '/Slave Interface/ {print $NF}' /proc/net/bonding/${BOND} \
        | grep -v "${PRIMARY}")
        SECONDARY_SPEED=$(grep -A2 "Slave Interface: ${SECONDARY}" /proc/net/bonding/${BOND} | awk '/Speed:/ {print $2}')

        if [[ ${PRIMARY_SPEED} -ne ${SECONDARY_SPEED} ]]; then
            echo -e "${RED}${BOND} sub-interface speeds do NOT match:${NORMAL}"
            echo -e "\t${BOND}-${PRIMARY}: ${PRIMARY_SPEED}"
            echo -e "\t${BOND}-${SECONDARY}: ${SECONDARY_SPEED}"
        fi
    done
}

################################################################################
# Test VLAN assignment
################################################################################

vlan_assignment_testing(){
    echo "Getting native VLANs from Switch. CDP must be enabled";
    for i in $interfaces; do
      ip link set dev ${i} up;
      CDP_INFO=$(timeout 90s tcpdump -nnvi ${i} -s 1500 -c 1 'ether[20:2] == 0x2000' 2>/dev/null | egrep "(Port|Device)-ID|VLAN");
      SWITCH=$(echo "${CDP_INFO}" | awk '/Device-ID/ {print $NF}' | sed 's@\..*@@g' | cut -c2- | tr '[:lower:]' '[:upper:]');
      PORT=$(echo "${CDP_INFO}" | awk '/Port-ID/ {print $NF}' | awk -F/ '{print $NF}' | sed "s@'@@g");
      VLAN=$((echo "${CDP_INFO}") | grep "VLAN" | awk '/bytes:/ {print $NF}');
      echo -e "${SWITCH}[${PORT}]\t($RS_SERVER-${i}) Current VLAN: ${VLAN}";
    done

}

################################################################################
# Create /etc/network/interfaces
################################################################################

generate_interfaces_file() {
    # Determine current IP information
    MGMT_INT=$(route -n | awk '/^0.0.0.0/ {print $NF}')
    MGMT_INT_INFO=$(grep "iface ${MGMT_INT}" -A20 /etc/network/interfaces \
        | sed -e '/^$/,$d')
    MGMT_IP_ADDRESS=$(echo "${MGMT_INT_INFO}" \
        | awk '/address / {sub(/\/[0-9]+$/, "", $2); print $2; exit}')
    MGMT_NETMASK=$(echo "${MGMT_INT_INFO}" \
        | awk '/netmask / {sub(/\/[0-9]+$/, "", $2); print $2; exit}')
    MGMT_GATEWAY=$(echo "${MGMT_INT_INFO}" \
        | awk '/gateway / {sub(/\/[0-9]+$/, "", $2); print $2; exit}')
    MGMT_DNS_SERVERS=$(echo "${MGMT_INT_INFO}" | grep dns-nameservers \
        | head -1 | sed 's/^ *//')
    MGMT_DNS_SEARCH=$(echo "${MGMT_INT_INFO}" | grep dns-search \
        | head -1 | sed 's/^ *//')
    SN_INT=$(route -n | awk '!/"${MGMT_INT}"|0.0.0.0/ {print $NF}' | tail -n +3)
    SN_INT_INFO=$(grep "auto ${SN_INT}" -A20 /etc/network/interfaces \
        | sed -e '/^$/,$d')
    cp -fn /etc/network/interfaces ${BACKUP_DIR}/interfaces_beforebonding.bak &> /dev/null

    # Set link up on all interfaces
    echo -e -n "Bringing up all interfaces: "
    for iface in $(ip -o l | awk '{print $2}' | sed 's/://' \
        | egrep -v "^(lo|bond)"); do ip link set dev $iface up; done

    # Pause for a few moments
    echo -e "${GREEN}Done${NORMAL}"; sleep 5

    if [[ ${NETGEN} -eq 2 ]]; then
        echo -e "\n${YELLOW}bond0${NORMAL} : ${bond0_1} ${bond0_2}\n"
    else
        echo -e "\n${YELLOW}bond0${NORMAL} : ${bond0_1} ${bond0_2}"
        echo -e "${YELLOW}bond1${NORMAL} : ${bond1_1} ${bond1_2}\n"
    fi

    bond0_1_link=$(ethtool $bond0_1 | awk '/Link detected:/ {print $NF}')
    bond0_2_link=$(ethtool $bond0_2 | awk '/Link detected:/ {print $NF}')
    if [[ ${bond0_1_link} == no || ${bond0_2_link} == no ]]; then
        echo -e "\n${RED}One of the bond0 interfaces has no 'link', this \
configuration will probably break networking. You can always revert back \
to default:\n"
        echo -e "cp ${BACKUP_DIR}/interfaces_beforebonding.bak \
/etc/network/interfaces${NORMAL}"
        sleep 5
    fi

    echo "auto lo
iface lo inet loopback

auto ${bond0_1}
iface ${bond0_1} inet manual
     bond-master bond0

auto ${bond0_2}
iface ${bond0_2} inet manual
     bond-master bond0

auto bond0
iface bond0 inet static
     bond-mode active-backup
     bond-miimon 100
     slaves ${bond0_1} ${bond0_2}
     address ${MGMT_IP_ADDRESS}
     netmask ${MGMT_NETMASK}
     gateway ${MGMT_GATEWAY}" > /etc/network/interfaces

if [[ ${NETGEN} -eq 1 ]]; then
    echo -e "\nauto ${bond1_1}
iface ${bond1_1} inet manual
     bond-master bond1

auto ${bond1_2}
iface ${bond1_2} inet manual
     bond-master bond1

auto bond1
iface bond1 inet manual
     up ip link set \$IFACE up
     down ip link set \$IFACE down
     bond-mode active-backup
     bond-miimon 100
     slaves ${bond1_1} ${bond1_2}" >> /etc/network/interfaces
fi

if [[ ${SN_INT} ]]; then
    echo -e "\n${SN_INT_INFO}" >> /etc/network/interfaces
fi

    echo -e "${YELLOW}Current /etc/network/interfaces"
    echo -e "===============================${NORMAL}"
    cat /etc/network/interfaces
    echo -e "${YELLOW}===============================${NORMAL}"

    echo -e "\n${YELLOW}After reboot verify the bonding and ServiceNet \
configuration:${NORMAL}\n"
    echo "PRIMARY=\$(awk '/Currently Active Slave/ {print \$NF}' \
/proc/net/bonding/bond0)"
    echo "SECONDARY=\$(awk '/Slave Interface/ {print \$NF}' \
/proc/net/bonding/bond0 | grep -v \${PRIMARY})"
    echo "ifenslave -c bond0 \${SECONDARY} && ping -c4 ${MGMT_GATEWAY}"
    echo "ifenslave -c bond0 \${PRIMARY} && ping -c4 ${MGMT_GATEWAY}"

    if [[ ${SN_INT} ]]; then
        echo "ping -c3 \$(route -n | awk '/"${SN_INT}"/' \
| awk '(\$2 != \"0.0.0.0\") {print \$2}')"
    fi
    echo
}

################################################################################
# Download and run upgrade_firmware.py script
################################################################################

run_upgrade_firmware() {

    wget -q https://cdaf143b77df1ef33a2c-3b91d08aee75e276209f7e1e54fcece4.ssl.cf1.rackcdn.com/upgrade_firmware-june28.py -O /root/upgrade_firmware-june28.py > /dev/null
    if [ $? != 0 ]; then
        echo "Error downloading file...investigate https://cdaf143b77df1ef33a2c-3b91d08aee75e276209f7e1e54fcece4.ssl.cf1.rackcdn.com/upgrade_firmware-june28.py"
    else
        python /root/upgrade_firmware-june28.py -f
    fi
}

# build_openstack_networking() {
#     # This function assumes that bonding has already been configured on the proper interfaces
#     # Only to be run from infra01 after keys have been configured to the nodes
#     echo -e "\nRunning this assumes that bonding has already been configured.
# This step will help guide you through configuring the Openstack portion of networking.
# \n\nEnter 'none' if a bridge/network is not needed."

#     # Provide list of IP -> IP allocations for ssh'ing in and making changes to servers
#     # i.e. host_ip (for SSH) -> new openstack IP for sub-networks to be configured

#     # For the following questions, enter 'none' if not used
#     # What is the 'interface.vlan' of the associated bridge interface
#     read -p "What is the 'interface.vlan' of br-mgmt: " BR_MGMT
#     read -p "What is the 'interface.vlan' of br-storage: " BR_STORAGE
#     read -p "What is the 'interface.vlan' of br-vxlan (tunnel/overlay): " BR_VXLAN
#     read -p "What is the 'interface' of br-vlan: " BR_VLAN
#     read -p "What are the DC nameservers: " DC_NAMESERVERS

#     if [[ ${BR_MGMT} != none ]]; then
#         BR_MGMT_INT=$(echo "${BR_MGMT}" | awk -F. '{print $1}')
#         BR_MGMT_VLAN=$(echo "${BR_MGMT}" | awk -F. '{print $2}')

#         echo -e "\n# Container management VLAN interface
# iface ${BR_MGMT_INT}.${BR_MGMT_VLAN} inet manual
#     vlan-raw-device ${BR_MGMT_INT}"
#     fi

#     if [[ ${BR_STORAGE} != none ]]; then
#         BR_STORAGE_INT=$(echo "${BR_STORAGE}" | awk -F. '{print $1}')
#         BR_STORAGE_VLAN=$(echo "${BR_STORAGE}" | awk -F. '{print $2}')

#         echo -e "\n# Storage network VLAN interface (optional)
# iface ${BR_STORAGE_INT}.${BR_STORAGE_VLAN} inet manual
#     vlan-raw-device ${BR_STORAGE_INT}"
#     fi

#     if [[ ${BR_VXLAN} != none ]]; then
#         BR_VXLAN_INT=$(echo "${BR_VXLAN}" | awk -F. '{print $1}')
#         BR_VXLAN_VLAN=$(echo "${BR_VXLAN}" | awk -F. '{print $2}')

#         echo -e "\n# OpenStack Networking VXLAN (tunnel/overlay) VLAN interface
# iface ${BR_VXLAN_INT}.${BR_VXLAN_VLAN} inet manual
#     vlan-raw-device ${BR_VXLAN_INT}"
#     fi

#     if [[ ${BR_MGMT_INT} && ${BR_MGMT_VLAN} ]]; then
#         echo -e "\n# Container management bridge
# auto br-mgmt
# iface br-mgmt inet static
#     bridge_stp off
#     bridge_waitport 0
#     bridge_fd 0
#     # Bridge port references tagged interface
#     bridge_ports ${BR_MGMT_INT}.${BR_MGMT_VLAN}
#     address ${BR_MGMT_IP}
#     netmask ${BR_MGMT_NETMASK}
#     dns-nameservers ${DC_NAMESERVERS}"
#     fi

#     if [[ ${BR_VXLAN_INT} && ${BR_VXLAN_VLAN} ]]; then
#         echo -e "\n# OpenStack Networking VXLAN (tunnel/overlay) bridge
# auto br-vxlan
# iface br-vxlan inet static
#     bridge_stp off
#     bridge_waitport 0
#     bridge_fd 0
#     # Bridge port references tagged interface
#     bridge_ports ${BR_VXLAN_INT}.${BR_VXLAN_VLAN}
#     address ${BR_VXLAN_IP}
#     netmask ${BR_VXLAN_NETMASK}"
#     fi

#     if [[ ${BR_VLAN} != none ]]; then
#         BR_VLAN_INT=$(echo "${BR_VLAN}")

#         echo -e "\n# OpenStack Networking VLAN bridge
# auto br-vlan
# iface br-vlan inet manual
#     bridge_stp off
#     bridge_waitport 0
#     bridge_fd 0
#     # Bridge port references untagged interface
#     bridge_ports ${BR_VLAN_INT}"
#     fi

#     if [[ ${BR_STORAGE_INT} && ${BR_STORAGE_VLAN} ]]; then
#         echo -e "\n# Storage bridge (optional)
# auto br-storage
# iface br-storage inet static
#     bridge_stp off
#     bridge_waitport 0
#     bridge_fd 0
#     # Bridge port reference tagged interface
#     bridge_ports ${BR_STORAGE_INT}.${BR_STORAGE_VLAN}
#     address ${BR_STORAGE_IP}
#     netmask ${BR_STORAGE_NETMASK}"
#     fi
# }

################################################################################
# Script body
################################################################################

# Terminal colorization by default
# Only altered if overridden by '-b' option
BOLD=$(tput bold)
NOBOLD=$(tput sgr0)
NORMAL=$(tput sgr0)
GREEN="\\033[1;32m"
RED="\\033[1;31m"
YELLOW="\\033[1;33m"
BLUE="\\033[1;34m"
PASS="\\033[1;32mPASSED${NORMAL}"
FAIL="\\033[1;31mFAILED${NORMAL}"
INFORM="\\033[1;33mINFORM${NORMAL}"
FIXED="\\033[1;34mFIXED${NORMAL}"
MANUAL="\\033[1;35mMANUAL${NORMAL}"

# Setting up the directory used for logging
ADC_DIR="/home/rack/rs-automations"
BACKUP_DIR="/home/rack/.adc/backup"
TMP_FILE="${ADC_DIR}/tmp"
FIRSTPASS_LOG="${ADC_DIR}/firstpass.log"
SECONDPASS_LOG="${ADC_DIR}/secondpass.log"
ADC_TEMPLATE="${ADC_DIR}/adc_template"
ADC_TEMPLATE_COLOR="${ADC_DIR}/adc_template_color"
ADC_FP_STATUS="${ADC_DIR}/adc_firstpass"
ADC_SP_STATUS="${ADC_DIR}/adc_secondpass"
mkdir -p ${ADC_DIR} ${BACKUP_DIR}

# OMSA variables
OMSA_SBIN="/opt/dell/srvadmin/sbin"
OMSA_BIN="/opt/dell/srvadmin/bin"
OMCONFIG="${OMSA_BIN}/omconfig"
OMREPORT="${OMSA_BIN}/omreport"
RACADM="${OMSA_SBIN}/racadm"

# MCP variables
OPENSTACK_OPS_VERSION="1.0.1"
HPASMCLI="/sbin/hpasmcli"
HPSSACLI="/usr/sbin/ssacli"
HPONCFG="/usr/sbin/hponcfg"

QUIET=0
ADC_FAIL=0
BBCODE=0
OMSA_COUNT=0
KERNEL_UPGRADE=0
FIRSTPASS=0
SECONDPASS=0
NETGEN=0
while getopts ":a:bcfhk:n:o:qstuvwz" OPTIONS
do
    case $OPTIONS in
         h) usage
            exit 0
            ;;
         a) # Set RS_SERVER_NAME variable
            RS_SERVER_NAME="${OPTARG}"
            ;;
         b) # BBCode tagging for ADC
            # Overrides default terminal colorization
            BOLD="[b]"
            NOBOLD="[/b]"
            NORMAL="[/color][/b]"
            GREEN="[b][color=green]"
            RED="[b][color=red]"
            YELLOW="[b][color=darkgoldenrod]"
            BLUE="[b][color=blue]"
            PASS="[b][color=green]PASSED[/color][/b]"
            FAIL="[b][color=red]FAILED[/color][/b]"
            INFORM="[b][color=darkgoldenrod]INFORM[/color][/b]"
            INFORM_ESCAPED="\[b\]\[color=darkgoldenrod\]INFORM\[\/color\]\[\/b\]"
            FIXED="[b][color=blue]FIXED[/color][/b]"
            MANUAL="[b][color=purple]MANUAL[/color][/b]"
            BBCODE=1
            ;;
         c) verify_privileges
            complete_qc
            exit 0
            ;;
         f) FIRSTPASS=1
            ;;
         k) verify_privileges
            add_ssh_keys "${OPTARG}"
            exit 0
            ;;
         n) # two bond (bond0/bond1) option
            NETGEN=1
            bond0_1=$(echo "$OPTARG" | awk '{print $1}')
            bond0_2=$(echo "$OPTARG" | awk '{print $2}')
            bond1_1=$(echo "$OPTARG" | awk '{print $3}')
            bond1_2=$(echo "$OPTARG" | awk '{print $4}')
            ;;
         o) # single bond (bond0) option
            NETGEN=2
            bond0_1=$(echo "$OPTARG" | awk '{print $1}')
            bond0_2=$(echo "$OPTARG" | awk '{print $2}')
            ;;
         q) QUIET=1
            ;;
         s) SECONDPASS=1
            ;;
         t) verify_privileges
            network_connectivity_testing
            exit 0
            ;;
         u) KERNEL_UPGRADE=1
            ;;
         v) #Use CDP to test VLAN assignment
            shift
            interfaces=$@
            vlan_assignment_testing
            exit 0
            ;;
         w) run_upgrade_firmware
            exit 0
            ;;
         z) get_version
            install_dellhp_tools
            exit 0
            ;;
         :) echo -e "ERROR: Option -$OPTARG requires a value"
            exit 255
            ;;
         *) echo -e "ERROR: Invalid option -$OPTARG"
            exit 255
            ;;
    esac
done

if [[ ${NETGEN} -eq 1 ]]; then
    verify_privileges

    # Generate network configuration
    if [[ ${bond0_1} && ${bond0_2} && ${bond1_1} && ${bond1_2} ]]; then
        generate_interfaces_file
    else
        echo -e "\n${RED}Missing bonding variable(s)...${NORMAL}\n"
        exit 1
    fi
elif [[ ${NETGEN} -eq 2 ]]; then
    verify_privileges

    # Generate network configuration
    if [[ ${bond0_1} && ${bond0_2} ]]; then
        generate_interfaces_file
    else
        echo -e "\n${RED}Missing bonding variable(s)...${NORMAL}\n"
        exit 1
    fi
elif [[ ${FIRSTPASS} -eq 1 ]]; then
    verify_privileges > ${FIRSTPASS_LOG} \
        || (echo -e "\n${FAIL}\tRequires root access to perform changes\n" \
        && adc_status FAIL ${ADC_FP_STATUS} "Unable to elevate to root") \
        || exit 1
    firstpass_qc
elif [[ ${SECONDPASS} -eq 1 ]]; then
    verify_privileges > ${SECONDPASS_LOG} \
        || (echo -e "\n${FAIL}\tRequires root access to perform changes\n" \
        && adc_status FAIL ${ADC_SP_STATUS} "Unable to elevate to root") \
        || exit 1
    secondpass_qc
else
    echo -e "\n${RED}No actionable option selected...${NORMAL}"
    usage
    exit 1
fi

