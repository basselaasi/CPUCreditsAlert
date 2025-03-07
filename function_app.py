import os
import logging
import azure.functions as func
from azure.identity import ManagedIdentityCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.monitor.models import MetricAlertResource, MetricAlertSingleResourceMultipleMetricCriteria, MetricCriteria, MetricAlertAction
import threading

app = func.FunctionApp()

def create_alert(monitor_client, resource_group, alert_rule_name, resource_uri, vm_name, action_group_id):
    try:
        criteria = MetricAlertSingleResourceMultipleMetricCriteria(
            all_of=[
                MetricCriteria(
                    name="CpuCreditsRemaining",
                    metric_name="CPU Credits Remaining",
                    metric_namespace="Microsoft.Compute/virtualMachines",
                    operator="LessThan",
                    threshold=900,
                    time_aggregation="Average",
                    dimensions=[]
                )
            ]
        )
        alert_rule = MetricAlertResource(
            location="global",
            name=alert_rule_name,
            severity=3,
            enabled=True,
            scopes=[resource_uri],
            description=f"CPU Credits Remaining Alert for VM {vm_name}",
            criteria=criteria,
            evaluation_frequency="PT5M",
            window_size="PT15M",
            auto_mitigate=True,
            actions=[MetricAlertAction(action_group_id=action_group_id)]
        )
        monitor_client.metric_alerts.create_or_update(
            resource_group_name=resource_group,
            rule_name=alert_rule_name,
            parameters=alert_rule
        )
        logging.info(f"Created CPU Credits Remaining alert rule for VM '{vm_name}'")
    except Exception as e:
        logging.error(f"Async alert creation failed: {str(e)}")

def delete_alert(monitor_client, resource_group, alert_rule_name):
    try:
        monitor_client.metric_alerts.delete(resource_group, alert_rule_name)
        logging.info(f"Deleted alert rule '{alert_rule_name}' due to VM deletion")
    except Exception as e:
        if hasattr(e, 'status_code') and e.status_code == 404:
            logging.info(f"Alert rule '{alert_rule_name}' already deleted or never existed")
        else:
            logging.error(f"Failed to delete alert rule '{alert_rule_name}': {str(e)}")

@app.event_grid_trigger(arg_name="event")
def DeployCpuCreditsAlerts(event: func.EventGridEvent):
    logging.info("Function triggered")
    
    SUBSCRIPTION_ID = os.environ.get("AZURE_SUBSCRIPTION_ID")
    if not SUBSCRIPTION_ID:
        logging.error("ERROR: AZURE_SUBSCRIPTION_ID is not set!")
        return func.HttpResponse('{"error": "Subscription ID not set"}', status_code=500, mimetype="application/json")

    # Move authentication outside main logic for speed
    credential = ManagedIdentityCredential()
    resource_client = ResourceManagementClient(credential, SUBSCRIPTION_ID)
    monitor_client = MonitorManagementClient(credential, SUBSCRIPTION_ID)
    logging.info("Authenticated successfully")

    event_data = event.get_json()
    logging.info(f"Event data: {event_data}")
    resource_uri = event_data.get("resourceUri", "")
    logging.info(f"Extracted resource_uri: {resource_uri}")
    
    if not resource_uri or "virtualMachines" not in resource_uri:
        logging.info("Event not related to a virtual machine")
        return func.HttpResponse('{"status": "Not a VM event"}', status_code=200, mimetype="application/json")

    vm_name = resource_uri.split("/")[-1]
    resource_group = resource_uri.split("/")[4]
    alert_rule_name = f"CPUCreditsAlert_{vm_name}"

    try:
        vm_resource = resource_client.resources.get_by_id(resource_uri, api_version="2023-07-01")
        vm_size = vm_resource.properties["hardwareProfile"]["vmSize"]
        logging.info(f"VM '{vm_name}' ({vm_size}) exists in resource group '{resource_group}'")
        if not vm_size.startswith("Standard_B"):
            logging.warning(f"VM '{vm_name}' ({vm_size}) is not burstable, skipping alert")
            return func.HttpResponse('{"status": "Non-burstable VM"}', status_code=200, mimetype="application/json")
        
        # Check alert existence
        try:
            monitor_client.metric_alerts.get(resource_group, alert_rule_name)
            logging.info(f"Alert rule '{alert_rule_name}' already exists, skipping creation")
            return func.HttpResponse('{"status": "Alert already exists"}', status_code=200, mimetype="application/json")
        except Exception as e:
            if hasattr(e, 'status_code') and e.status_code == 404:
                logging.info(f"Alert rule '{alert_rule_name}' does not exist. Proceeding with creation.")
                action_group_id = os.environ.get("ACTION_GROUP_ID", f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{resource_group}/providers/Microsoft.Insights/actionGroups/Monitor_CPU_Alert_Rule")
                threading.Thread(target=create_alert, args=(monitor_client, resource_group, alert_rule_name, resource_uri, vm_name, action_group_id)).start()
                logging.info("Alert creation initiated in background")
                return func.HttpResponse('{"status": "Alert creation started"}', status_code=202, mimetype="application/json")
            else:
                logging.error(f"Error checking existing alert: {str(e)}")
                return func.HttpResponse(f'{{"error": "Alert check error: {str(e)}"}}', status_code=500, mimetype="application/json")

    except Exception as e:
        if hasattr(e, 'status_code') and e.status_code == 404:
            logging.info(f"VM '{vm_name}' not found, likely deleted. Checking and deleting alert rule '{alert_rule_name}'.")
            threading.Thread(target=delete_alert, args=(monitor_client, resource_group, alert_rule_name)).start()
            return func.HttpResponse('{"status": "VM deleted, alert deletion started"}', status_code=202, mimetype="application/json")
        else:
            logging.error(f"Failed to process VM details: {str(e)}")
            return func.HttpResponse(f'{{"error": "VM processing error: {str(e)}"}}', status_code=500, mimetype="application/json")