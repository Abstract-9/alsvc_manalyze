from assemblyline.al.service.base import ServiceBase
from assemblyline.al.common.result import Result, ResultSection, SCORE, TEXT_FORMAT, TAG_WEIGHT, TAG_TYPE
from assemblyline.common.reaper import set_death_signal
from assemblyline.common.net import is_valid_domain, is_valid_email, is_valid_ip


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

    #Heuristics


    def __init__(self, cfg=None):
        super(Manalyze, self).__init__(cfg)
        self.result = None

    def start(self):
        self.log.debug("Manalyze service started")



    def execute(self, request):
        local = request.download()
        self.result = request.result

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

        result = Result()
        result.add_section(result_section)
        # result.add_section(test_section)
        request.result = result

    def parse(self, output=None):
        data = json.loads(str(output))
        parent_section = ResultSection(SCORE.NULL, "Manalyze Results:")
        for name, level2 in data.iteritems():
            # Skip the first level (Its the filename)
            for key, value in level2.iteritems():
                section = ResultSection(SCORE.NULL, key)
                self.recurse_dict(value, section)

                if section.body.count("\n") > 25: section.body_format = TEXT_FORMAT.MEMORY_DUMP
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

                while True:
                    retry = False
                    try:
                        if key in self.indicator_keys:
                            func = self.indicator_keys.get(key)
                            func(self, value, parent_section)

                        elif isinstance(value, int):
                            parent_section.add_line(key + ": " + str(value) + " (" + str(hex(value)) + ")")

                        else:
                            if isinstance(value, str): self.tag_analyze(value, parent_section)
                            parent_section.add_line(key + ": " + str(value))
                    except (UnicodeDecodeError, UnicodeEncodeError) as e:
                        if retry: break
                        value = value.encode("ascii", "ignore")
                        retry = True
                        self.log.debug(str(e) + "\n----Retrying...----")
                        continue
                    break


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

    def tag_analyze(self, value, section):
        if is_valid_ip(value):
            section.add_tag(TAG_TYPE["NET_IP"], value, TAG_WEIGHT.LOW)

        if is_valid_email(value):
            section.add_tag(TAG_TYPE["NET_EMAIL"], value, TAG_WEIGHT.LOW)

        if is_valid_domain(value):
            section.add_tag(TAG_TYPE["NET_DOMAIN"], value, TAG_WEIGHT.LOW)

    def level_score(self, value, parent_section):

        if value == 1:
            parent_section.change_score(SCORE.INFO)
        elif value == 2:
            parent_section.change_score(SCORE.LOW)
        elif value == 3:
            parent_section.change_score(SCORE.HIGH)

    def entropy_score(self, value, parent_section):
        if value > 7.5:
            parent_section.add_section(ResultSection(SCORE.HIGH, "Section has high entropy!"))

    indicator_keys = {
        'level': level_score,
        'entropy': entropy_score
    }
