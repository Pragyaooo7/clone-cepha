import os
import logging
import yaml
from collections import defaultdict
from lxml import etree

log = logging.getLogger(__name__)


class XMLScanner():
    def __init__(self, remote=None, yaml_path=None) -> None:
        self.yaml_data = []
        self.yaml_path = yaml_path
        self.remote = remote

    def scan_all_files(self, path_regex: str):
        """
        :param path_regex: Regex string to find all the files which have to be scanned. 
                           Example: /path/to/dir/*.xml
        """
        (_, stdout, stderr) = self.remote.ssh.exec_command(f'ls -d {path_regex}', timeout=200)
        if stderr:
            log.info("XML_DEBUG: stderr " + stderr.read().decode())    
            return []
        files = stdout.read().decode().split('\n')
        log.info("XML_DEBUG: all file paths are " + " ".join(files))
        
        errors = []
        for fpath in files:
            error_txt = self.scan_file(fpath)
            if error_txt:
                errors += [error_txt]
            
        self.write_logs()
        return errors

    def scan_file(self, path): 
        """ 
        Scans a xml file and 
        collect data in self.yaml_data.

        :path: exact path to single xml file.
        """
        if not path:
            return None
        (_, stdout, _) = self.remote.ssh.exec_command(f'cat {path}', timeout=200)
        if stdout:
            xml_tree = etree.parse(stdout)
            txt, data = self._parse(xml_tree)
            if data:
                data["xml_file"] = path
                self.yaml_data += [data]
            return txt
        log.debug(f'XML output not found at `{str(path)}`!')

    def _parse(self, xml_tree):
        """
        This parses xml_tree and returns:
        :returns: a message string 
        :returns: data (to add in summary yaml file)

        Just an abstract class in XMLScanner, 
        to be defined in inherited classes. 
        """
        return None, None
    
    def write_logs(self):
        yamlfile = self.yaml_path
        if self.yaml_data:
            try:
                remote_yaml_file = self.remote._sftp_open_file(yamlfile, "a")
                yaml.safe_dump(self.yaml_data, remote_yaml_file, default_flow_style=False)
                remote_yaml_file.close()
            except Exception as exc: 
                log.exception(exc)
                log.info("XML_DEBUG: write logs error: " + repr(exc))
        else:
            log.info("XML_DEBUG: yaml_data is empty!")


class UnitTestScanner(XMLScanner):
    def __init__(self, remote=None, yaml_path=None) -> None:
        yaml_path = yaml_path or "/home/ubuntu/cephtest/archive/unittest_failures.yaml"
        super().__init__(remote, yaml_path)

    def get_exception_msg(self, xml_path: str):
        """
        :param xml_path: Path to unit-test xml files. 
                         If xml_path ends with "/" then, 
                         all files (of .xml extension) under that dir would be scanned. 
                         Otherwise, xml_path would be absolute path to a single xml file.
        """
        try:
            if xml_path[-1] == "/":
                errors = self.scan_all_files(f'{xml_path}*.xml')
                if errors:
                    return errors[0]
                log.debug("UnitTestScanner: No error found in XML output")
                return None
            else:
                error = self.scan_file(xml_path)
                self.write_logs()
                return error
        except Exception as exc:
            log.exception(exc)
            log.info("XML_DEBUG: get_exception_msg: " + repr(exc))

    def _parse(self, xml_tree):
        root = xml_tree.getroot()
        if int(root.get("failures", -1)) == 0 and int(root.get("errors", -1)) == 0:
            log.debug("No failures or errors in unit test.")
            return None, None

        failed_testcases = xml_tree.xpath('.//failure/.. | .//error/..')
        if len(failed_testcases) == 0:
            log.debug("No failures/errors tags found in xml file.")
            return None, None

        error_txt, error_data = "", defaultdict(list)
        for testcase in failed_testcases:
            testcase_name = testcase.get("name", "test-name")
            testcase_suitename = testcase.get("classname", "suite-name")
            for child in testcase:
                if child.tag in ['failure', 'error']:
                    fault_kind = child.tag
                    reason = child.get('message', 'No message found in xml output, check logs.')
                    short_reason = reason[:reason.find('begin captured')] # remove traceback
                    error_data[testcase_suitename] += [{
                            "kind": fault_kind, 
                            "testcase": testcase_name,
                            "message": reason,
                        }]
                    if not error_txt:
                        error_txt = f'{fault_kind.upper()}: Test `{testcase_name}` of `{testcase_suitename}`. Reason: {short_reason}.'
        
        return error_txt, { "failed_testsuites": dict(error_data), "num_of_failures": len(failed_testcases) }    


class ValgrindScanner(XMLScanner):
    def __init__(self, remote=None, yaml_path=None) -> None:
        super().__init__(remote, yaml_path)

    def get_exception_msg(self):
        try:
            errors = self.scan_all_files('/var/log/ceph/valgrind/*')
            log.info("XML_DEBUG: ")
            log.info(errors)
            if errors:
                return errors[0]
            return None
        except Exception as exc:
            log.exception(exc)
            log.info("Failed to get valgrind error: " + repr(exc))


    def _parse(self, xml_tree):
        if not xml_tree:
            return None, None
        error_tree = xml_tree.find('error')

        if not len(error_tree):
            log.info("XML_DEBUG: error_tree empty. <error> tag not found.")
            return None, None

        error_data = {}

        error_data["kind"] = error_tree.find('kind').text
        error_data["threadname"] = error_tree.find('threadname').text
        error_traceback = []
        stack = error_tree.find('stack')
        for frame in stack:
            if len(error_traceback) >= 5:
                break
            curr_frame = {
                'file': f'{frame.find("dir").text}/{frame.find("file").text}',
                'line': frame.find('line').text,
                'function': frame.find('fn').text,
            }
            error_traceback += [curr_frame]
        error_data["traceback"] = error_traceback
        
        exception_text = f"valgrind error: {error_data['kind']} in {error_data['threadname']}" 
        return exception_text, error_data
    
    def write_logs(self):
        yamlfile = self.yaml_path
        if self.yaml_data:
            with open(yamlfile, 'a') as f:
                yaml.safe_dump(self.yaml_data, f, default_flow_style=False)
        else:
            log.info("Failed to write in valgrind.yaml: yaml_data is empty!")
