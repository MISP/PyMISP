#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Jens Thom (VMRay), Koen Van Impe

VMRay automatic import
Put this script in crontab to run every /15 or /60
    */5 *    * * *   mispuser   /usr/bin/python3 /home/mispuser/PyMISP/examples/vmray_automation.py

Calls "vmray_import" for all events that have an 'incomplete' VMray analysis

Do inline config in "main".
If your MISP user is not an admin, you cannot use `get_config`,
use `overwrite_config` instead.
Example config:
    config = {
        "vmray_import_enabled": True,
        "vmray_import_apikey": vmray_api_key,
        "vmray_import_url": vmray_server,
        "vmray_import_disable_tags": False,
        "vmray_import_disable_misp_objects": False,
        "vmray_import_ignore_analysis_finished": False,
        "services_port": 6666,
        "services_url": "http://localhost",
        "Artifacts": "1",
        "VTI": "1",
        "IOCs": "1",
        "Analysis Details": "1",
    }
"""

import logging
import urllib

from typing import Any, Dict, List, Optional

import requests

from keys import misp_key, misp_url, misp_verifycert
from pymisp import PyMISP

# Suppress those "Unverified HTTPS request is being made"
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def is_url(url: str) -> bool:
    try:
        result = urllib.parse.urlparse(url)
        return result.scheme and result.netloc
    except ValueError:
        return False


class VMRayAutomationException(Exception):
    pass


class VMRayAutomation:
    def __init__(
        self,
        misp_url: str,
        misp_key: str,
        verify_cert: bool = False,
        debug: bool = False,
    ) -> None:
        # setup logging
        log_level = logging.DEBUG if debug else logging.INFO
        log_format = "%(asctime)s - %(name)s - %(levelname)8s - %(message)s"

        logging.basicConfig(level=log_level, format=log_format)
        logging.getLogger("pymisp").setLevel(log_level)
        self.logger = logging.getLogger(self.__class__.__name__)

        self.misp_url = misp_url.rstrip("/")
        self.misp_key = misp_key
        self.verifycert = verify_cert
        self.misp = PyMISP(misp_url, misp_key, ssl=verify_cert, debug=debug)
        self.config = {}
        self.tag_incomplete = 'workflow:state="incomplete"'

    @staticmethod
    def _setting_enabled(value: bool) -> bool:
        if not value:
            raise VMRayAutomationException(
                "VMRay import is disabled. "
                "Please enable `vmray_import` in the MISP settings."
            )

        return True

    @staticmethod
    def _setting_apikey(value: str) -> str:
        if not value:
            raise VMRayAutomationException(
                "VMRay API key not set. Please set the API key in the MISP settings."
            )

        return value

    @staticmethod
    def _setting_url(value: str) -> str:
        if not value:
            raise VMRayAutomationException(
                "VMRay URL not set. Please set the URL in the MISP settings."
            )

        if not is_url(value):
            raise VMRayAutomationException("Not a valid URL")

        return value

    @staticmethod
    def _setting_disabled(value: str) -> bool:
        return value.lower() in ["no", "false"]

    @staticmethod
    def _services_port(value: int) -> bool:
        if value == 0:
            return 6666
        return value

    @staticmethod
    def services_url(value: str) -> bool:
        if not is_url(value):
            raise VMRayAutomationException("Services URL is not valid.")

        return value

    @property
    def vmray_settings(self) -> Dict[str, Any]:
        return {
            "vmray_import_enabled": self._setting_enabled,
            "vmray_import_apikey": self._setting_apikey,
            "vmray_import_url": self._setting_url,
            "vmray_import_disable_tags": self._setting_disabled,
            "vmray_import_disable_misp_objects": self._setting_disabled,
            "vmray_import_ignore_analysis_finished": self._setting_disabled,
            "services_port": self._services_port,
            "services_url": self.services_url,
        }

    def _get_misp_settings(self) -> List[Dict[str, Any]]:
        misp_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": self.misp_key,
        }

        response = requests.get(
            f"{self.misp_url}/servers/serverSettings.json",
            verify=self.verifycert,
            headers=misp_headers,
        )

        if response.status_code == 200:
            settings = response.json()
            if "finalSettings" in settings:
                return settings["finalSettings"]

        raise VMRayAutomationException("Could not get settings from MISP server.")

    def get_config(self) -> None:
        self.logger.debug("Loading confing...")
        # get settings from MISP server
        settings = self._get_misp_settings()
        for setting in settings:
            config_name = setting["setting"].replace("Plugin.Import_", "")
            if config_name in self.vmray_settings:
                func = self.vmray_settings[config_name]
                value = func(setting["value"])
                self.config[config_name] = value

        # set default `vmray_import` settings
        self.config.setdefault("VTI", "1")
        self.config.setdefault("IOCs", "1")
        self.config.setdefault("Artifacts", "0")
        self.config.setdefault("Analysis Details", "1")

        self.logger.info("Loading config: Done.")

    def overwrite_config(self, config: Dict[str, Any]) -> None:
        self.config.update(config)

    def _get_sample_id(self, value: str) -> Optional[int]:
        vmray_sample_id_text = "VMRay Sample ID: "
        if not value.startswith(vmray_sample_id_text):
            self.logger.warning("Invalid Sample ID: %s.", value)
            return None

        return int(value.replace(vmray_sample_id_text, ""))

    def _call_vmray_import(self, sample_id: int, event_id: str) -> Dict[str, Any]:
        url = f"{self.config['services_url']}:{self.config['services_port']}/query"

        config = {"Sample ID": sample_id}
        for key, value in self.config.items():
            vmray_config_key = key.replace("vmray_import_", "")
            config[vmray_config_key] = str(value)

        data = {
            "module": "vmray_import",
            "event_id": event_id,
            "config": config,
            "data": "",
        }

        self.logger.debug("calling `vmray_import`: url=%s, config=%s", url, config)
        response = requests.post(url, json=data)
        if response.status_code != 200:
            raise VMRayAutomationException(
                f"MISP modules returned status code `{response.status_code}`"
            )

        json_response = response.json()
        if "error" in json_response:
            error = json_response["error"]
            raise VMRayAutomationException(f"MISP modules returned error: {error}")

        return json_response

    def _add_event_attributes(self, event_id: int, attributes: Dict[str, Any]) -> None:
        event = self.misp.get_event(event_id, pythonify=True)
        for attr in attributes["Attribute"]:
            event.add_attribute(**attr)

        self.misp.update_event(event)

    def _add_event_objects(self, event_id: int, objects: Dict[str, Any]) -> None:
        event = self.misp.get_event(event_id, pythonify=True)
        for obj in objects["Object"]:
            event.add_object(**obj)

        if "Tag" in objects:
            for tag in objects["Tag"]:
                event.add_tag(tag["name"])

        self.misp.update_event(event)

    def _add_misp_event(self, event_id: int, response: Dict[str, Any]) -> None:
        if self.config["vmray_import_disable_misp_objects"]:
            self._add_event_attributes(event_id, response["results"])
        else:
            self._add_event_objects(event_id, response["results"])

    def import_incomplete_analyses(self) -> None:
        self.logger.info("Searching for attributes with tag='%s'", self.tag_incomplete)
        result = self.misp.search("attributes", tags=self.tag_incomplete)
        attributes = result["Attribute"]

        for attr in attributes:
            event_id = int(attr["event_id"])
            self.logger.info("Processing event ID `%d`.", event_id)

            sample_id = self._get_sample_id(attr["value"])
            if not sample_id:
                continue

            response = self._call_vmray_import(sample_id, event_id)
            self._add_misp_event(event_id, response)
            self.misp.untag(attr["uuid"], self.tag_incomplete)


def main():
    debug = False
    config = {
        "Artifacts": "0",
        "VTI": "1",
        "IOCs": "1",
        "Analysis Details": "0",
        "vmray_import_disable_misp_objects": False,
    }

    automation = VMRayAutomation(misp_url, misp_key, misp_verifycert, debug)
    automation.get_config()  # only possible with admin user
    automation.overwrite_config(config)
    automation.import_incomplete_analyses()


if __name__ == "__main__":
    main()
