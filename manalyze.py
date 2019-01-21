from assemblyline.al.service.base import ServiceBase
from assemblyline.al.common.result import Result, ResultSection, SCORE, TEXT_FORMAT
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
        'CryptoAddress': True,
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

        cmdLine = ['./manalyze', local, '-o', 'json', '-d', 'all', '--hashes']

        self.construct_plugins(cmdLine)

        try:
            result_section = self.parse(output=subprocess.check_output(cmdLine, preexec_fn=set_death_signal()))
        except:
            result_section = ResultSection(SCORE.NULL, "Summary")
            result_section.add_line(subprocess.check_output(cmdLine))
            result_section.add_line("JSON Decoding Failed!")
            raise

        # result_section = ResultSection(SCORE.NULL, 'Output Section')
        # result_section.add_line(subprocess.check_output(cmdLine))

        # test_section = ResultSection(SCORE.NULL, 'Test Section')
        # test_section.add_line(cmdLine)
        # test_section.add_line(os.getcwd())

        result = Result()
        result.add_section(result_section)
        # result.add_section(test_section)
        request.result = result

    def parse(self, output=None):
        data = json.loads(str(output))
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
            if isinstance(value, dict):
                section = ResultSection(SCORE.NULL, key, body_format=TEXT_FORMAT.MEMORY_DUMP)
                self.recurse_dict(value, section)
                parent_section.add_section(section)


            elif isinstance(value, list):
                parent_section.add_line(key + ":")
                parent_section.add_lines(value)

            else:

                if key=='level':
                    if(value==1): parent_section.change_score(SCORE.INFO)
                    elif(value==2): parent_section.change_score(SCORE.MED)
                    elif(value==3): parent_section.change_score(SCORE.HIGH)

                else:

                    if(isinstance(value, int)):
                        parent_section.add_line(key + ": " + str(value) + " (0x" + str(hex(value)) + ")")

                    else:
                        parent_section.add_line(key + ": " + str(value))

    def construct_plugins(self, cmd_line):
        cmd_line.append('-p')

        plugin_line = ''
        for key, value in self.cfg.iteritems():
            if value:
                plugin_line += key.lower() + ","

        if plugin_line.endswith(","): plugin_line = plugin_line[:-1]

        if plugin_line != '': cmd_line.append(plugin_line)
        else: cmd_line.pop()

        return cmd_line
