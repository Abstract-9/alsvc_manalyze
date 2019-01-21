#!/usr/bin/env python

import os



def install(alsi):

    prereqs = ['libboost-regex-dev',
               'libboost-program-options-dev',
               'libboost-system-dev',
               'libboost-filesystem-dev',
               'libssl-dev build-essential',
               'cmake',
               'git']

    alsi.sudo_apt_install(prereqs)

    alsi.runcmd('cd /opt/al/pkg/al_services/alsvc_manalyze/Manalyze && '
                'cmake . &&'
                'make')



if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())