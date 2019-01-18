from assemblyline.al.service.base import ServiceBase
from assemblyline.al.common.result import Result, ResultSection, SCORE
from assemblyline.common.reaper import set_death_signal

import os
import subprocess
import json

class Manalyze(ServiceBase):
    SERVICE_CATEGORY = 'Static Analysis'
    SERVICE_ACCEPTS = 'executable/windows'
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_ENABLED = True
    SERVICE_STAGE = 'CORE'
    SERVICE_CPU_CORES = 1
    SERVICE_RAM_MB = 256

    #Set config defaults for plugins
    SERVICE_DEFAULT_CONFIG = {
        'ClamAV': False,
        'Compilers': True,
        'Strings': True,
        'FindCrypt': True,
        'CrypoAddress': True,
        'Packer': True,
        'Imports': True,
        'Resources': True,
        'Mitigation': True,
        'Overlay': True,
        "Authenticode": False,
        "Virustotal": False
    }

    def __init__(self, cfg=None):
        super(Manalyze, self).__init__(cfg)

    def start(self):
        self.log.debug("Manalyze service started")



    def execute(self, request):
        local = request.download()

        #Start construction of CLI string
        local_dir = os.path.dirname(os.path.realpath(__file__)) + '/Manalyze/bin'

        os.chdir(local_dir)

        cmdLine = ['./manalyze', local, '-o', 'json',]

        #self.construct_plugins(cmdLine)

        try:
            result_section = self.parse(subprocess.check_output(cmdLine))
        except:
            result_section = ResultSection(SCORE.NULL, "Summary")
            result_section.add_line(subprocess.check_output(cmdLine))
            result_section.add_line("JSON Decoding Failed!")

        # result_section = ResultSection(SCORE.NULL, 'Output Section')
        # result_section.add_line(subprocess.check_output(cmdLine))

        # test_section = ResultSection(SCORE.NULL, 'Test Section')
        # test_section.add_line(cmdLine)
        # test_section.add_line(os.getcwd())

        result = Result()
        result.add_section(result_section)
        # result.add_section(test_section)
        request.result = result

    def parse(self, output):
        data = json.loads(output)
        parent_section = ResultSection(SCORE.NULL, "Manalyze Results:")
        for name, level2 in data.iteritems():
            #Skip the first level (Its the filename)
            for key, value in level2.iteritems():
                section = ResultSection(SCORE.NULL, key)
                self.recurse_dict(value, section)
                parent_section.add_section(section)

        return parent_section

    def recurse_dict(self, item, parent_section):
        for key, value in item.iteritems():
            if(value is dict):
                section = ResultSection(SCORE.NULL, key)
                self.recurse_dict(value, section)
                parent_section.add_section(section)
            else:
                parent_section.add_line(key + ": " + value)

    def construct_plugins(self, cmd_line):
        cmd_line.append('-p')

        for key, value in self.cfg.iteritems():
            if value:
                cmd_line.append(key.lower())

        if cmd_line[len(cmd_line) - 1]== '-p': cmd_line.pop()

        return cmd_line
