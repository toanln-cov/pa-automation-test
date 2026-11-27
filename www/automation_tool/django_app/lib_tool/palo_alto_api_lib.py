# PAN-OS API used by the tool. The real calls are in the version classes of lib_tool/panos/ (PanOS11_1 = default);
# the functions here keep their old names and (host, token, ...) arguments and forward to the API object of that
# firewall, chosen once per job by its PAN-OS version (keygen -> detect_rest_version).
from .panos.common import FirewallError, safe_error
from . import panos


# get token (version independent); the HTTPS session opened here is reused by the API object of the firewall
def get_token(host, user, password):
    return panos.keygen(host, user, password)


#PAN-OS version of the firewall (read only: show system info) -> API class + REST path of this firewall
def detect_rest_version(host, token):
    api = panos.connect(host, token)
    return api.sw_version, type(api).__name__


#version class object of a firewall (PanOS11_1...): PAN-OS values, answer parsing and field rules of its version
def api(host, token):
    return panos.api(host, token)


#'PAN-OS 11.1.10-h1 -> REST API v11.1, API class PanOS11_1' for the job page
def describe(host):
    return panos.describe(host)


def _forward(name):
    def call(host, token, *args, **kwargs):
        return getattr(panos.api(host, token), name)(*args, **kwargs)
    call.__name__ = name
    return call


# same names as before the version classes: palib.create_nat_rule(host, token, object, location_object) ...
FORWARDED = ('get_security_rule', 'check_security_rule_exist', 'create_security_rule', 'edit_security_rule',
             'move_security_rule',
             'get_Objects_Addresses', 'check_Objects_Addresses_exist', 'create_Objects_Addresses',
             'get_Objects_AddressGroups', 'check_Objects_AddressGroups_exist', 'create_Objects_AddressGroups_static',
             'get_Objects_Services', 'check_Objects_Services_exist', 'create_Objects_Services',
             'get_Objects_ServiceGroups', 'check_Objects_ServiceGroups_exist', 'create_Objects_ServiceGroups',
             'create_Objects_Tag', 'edit_Objects_Tag', 'edit_Objects_Addresses', 'edit_Objects_AddressGroups',
             'edit_Objects_Services', 'edit_Objects_ServiceGroups',
             'get_Zones', 'get_Objects_Tags', 'get_Objects_SecurityProfileGroups', 'get_Objects_LogForwardingProfiles',
             'get_Objects_CustomURLCategories', 'get_Objects_ExternalDynamicLists', 'get_Objects_Regions',
             'get_Objects_Applications', 'get_Objects_ApplicationGroups', 'get_Objects_ApplicationFilters',
             'predefined_names', 'predefined_application_exists', 'get_VirtualSystems',
             'name_error', 'check_row', 'job_finished', 'job_ok',
             'get_nat_rule', 'check_nat_rule_exist', 'create_nat_rule', 'edit_nat_rule',
             'move_nat_rule',
             'xml_api_op', 'backup_config', 'add_config_lock', 'remove_config_lock',
             'check_pending_changes', 'start_commit', 'get_job_status', 'start_validate')
for _name in FORWARDED:
    globals()[_name] = _forward(_name)

# public names of this module; FirewallError / safe_error re-exported from panos.common (palib.safe_error ...)
__all__ = ['FirewallError', 'safe_error', 'get_token', 'detect_rest_version', 'describe', 'api', *FORWARDED]
