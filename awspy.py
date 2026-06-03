#!/usr/bin/python3

import argparse
import sys
import datetime
import ipaddress
import re
import os
import warnings
import shlex
import subprocess
import tempfile
import time

# Lazy loaded libraries

def _lazy_init_aws():
    global boto3, BotoCoreError, InsecureRequestWarning
    if "boto3" not in globals():
        import boto3
        from botocore.exceptions import BotoCoreError
        from urllib3.exceptions import InsecureRequestWarning

def _lazy_init_yaml():
    global yaml
    if "yaml" not in globals():
        import yaml

def _yaml_dump(*args, **kwargs):
    _lazy_init_yaml()
    return yaml.dump(*args, width=1000, **kwargs)

def _lazy_init_k8s():
    global k8s_config, k8s_client, inquirer
    if "k8s_config" not in globals():
        from kubernetes import config as k8s_config, client as k8s_client
        import inquirer

def _lazy_init_plot():
    global plt
    if "plt" not in globals():
        import plotext as plt

def _lazy_init_flask():
    global request
    if "request" not in globals():
        from flask import request

def AwsFinder(resource_id, profiles = None, regions = None, verify_ssl = True):
        _lazy_init_aws()
        resource_id = resource_id.lower()
        if profiles:
            profiles = [profiles]
        else:
            profiles = boto3.Session().available_profiles
        if regions:
            regions = [regions]
        else:
            regions = ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]
        # Regular expression for UUID pattern (for DXGW)
        uuid_pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"

        verify = None if verify_ssl else False
        for profile in profiles:
            for region in regions:
                try:
                    find_session = boto3.Session(profile_name=profile, region_name=region)
                    find_ec2 = find_session.client('ec2', verify=verify)
                    find_dx = find_session.client('directconnect', verify=verify)
                except Exception:
                    # Skip profiles/regions with access issues (SSO expired, etc.)
                    continue

                # Check if resource_id is an IP address or subnet
                try:
                    ip = ipaddress.ip_address(resource_id)
                    if isinstance(ip, ipaddress.IPv4Address):
                        response = find_ec2.describe_network_interfaces(
                            Filters=[{'Name': 'addresses.private-ip-address', 'Values': [resource_id]}]
                        )
                        if not response["NetworkInterfaces"]:
                            continue
                    elif isinstance(ip, ipaddress.IPv6Address):
                        response = find_ec2.describe_network_interfaces(
                            Filters=[{'Name': 'ipv6-addresses.ipv6-address', 'Values': [resource_id]}]
                        )
                        if not response["NetworkInterfaces"]:
                            continue
                    # Process and return the response for IP address
                    return f"Network ip {resource_id} found in profile: {profile}, region: {region}"
                except ValueError:
                    # Not a valid subnet, continue with other resource checks
                    pass
                except Exception:
                    # Error in AWS call, continue to next profile/region
                    continue


                # Check if resource_id is a subnet
                try:
                    cidr = ipaddress.ip_network(resource_id, strict=False)
                    if cidr.version == 4:
                        response = find_ec2.describe_subnets(
                            Filters=[{'Name': 'cidrBlock', 'Values': [resource_id]}]
                        )
                    else:
                        response = find_ec2.describe_subnets(
                            Filters=[{'Name': 'ipv6-cidr-block-association.ipv6-cidr-block', 'Values': [resource_id]}]
                        )
                    if not response["Subnets"]:
                        continue
                    # Process and return the response for subnet
                    return f"Subnet {resource_id} found in profile: {profile}, region: {region}"
                except ValueError:
                    # Not a valid subnet, continue with other resource checks
                    pass
                except Exception:
                    # Error in AWS call, continue to next profile/region
                    continue

                try:
                    # Check for different AWS resource types
                    if resource_id.startswith("eni-"):
                        find_ec2.describe_network_interfaces(NetworkInterfaceIds=[resource_id])
                    elif resource_id.startswith("subnet-"):
                        find_ec2.describe_subnets(SubnetIds=[resource_id])
                    elif resource_id.startswith("rtb-"):
                        find_ec2.describe_route_tables(RouteTableIds=[resource_id])
                    elif resource_id.startswith("tgw-rtb-"):
                        find_ec2.describe_transit_gateway_route_tables(TransitGatewayRouteTableIds=[resource_id])
                    elif resource_id.startswith("lgw-rtb-"):
                        result = find_ec2.describe_local_gateway_route_tables(LocalGatewayRouteTableIds=[resource_id])
                        if not result["LocalGatewayRouteTables"]:
                            continue
                    elif resource_id.startswith("pl-"):
                        find_ec2.describe_managed_prefix_lists(PrefixListIds=[resource_id])
                    elif resource_id.startswith("vpc-"):
                        find_ec2.describe_vpcs(VpcIds=[resource_id])
                    elif resource_id.startswith("sg-"):
                        find_ec2.describe_security_groups(GroupIds=[resource_id])
                    elif resource_id.startswith("i-"):
                        find_ec2.describe_instances(InstanceIds=[resource_id])
                    elif resource_id.startswith("acl-"):
                        find_ec2.describe_network_acls(NetworkAclIds=[resource_id])
                    # Check for Direct Connect Gateway (UUID format)
                    elif resource_id.startswith("dxcon-"):
                        result = find_dx.describe_connections(connectionId=resource_id)
                        if not result["connections"]:
                            continue
                    elif resource_id.startswith("dxvif-"):
                        result = find_dx.describe_virtual_interfaces(virtualInterfaceId=resource_id)
                        if not result["virtualInterfaces"]:
                            continue
                    elif re.match(uuid_pattern, resource_id):
                        result = find_dx.describe_direct_connect_gateways(directConnectGatewayId=resource_id)
                        if not result["directConnectGateways"]:
                            continue
                    else:
                        return f"Resource {resource_id} is not valid"
                    return f"Resource {resource_id} found in profile: {profile}, region: {region}"
                except Exception as e:
                    continue
        return f"Resource {resource_id} not found"

class AwsFetcher:
    def __init__(self, profile, region, verify_ssl = True):
        _lazy_init_aws()
        verify = None if verify_ssl else False
        self.session = boto3.Session(profile_name=profile, region_name=region)
        self.ec2_client = self.session.client('ec2', verify=verify)
        self.dx_client = self.session.client('directconnect', verify=verify)
        self.log_client = self.session.client('logs', verify=verify)
        self.cw_client = self.session.client('cloudwatch', verify=verify)
        self.asg_client = self.session.client('autoscaling', verify=verify)

    def get_full_inventory(self):
        """Extracts a comprehensive inventory of AWS resources for the region."""
        inventory = {
            "vpcs": [],
            "subnets": [],
            "instances": [],
            "enis": [],
            "tgws": [],
            "tgw_rtbs": [],
            "dxgws": [],
            "dx_conns": [],
            "vifs": [],
            "route_tables": []
        }
        try:
            # 1. VPCs
            vpcs_resp = self.ec2_client.describe_vpcs()
            for vpc in vpcs_resp.get('Vpcs', []):
                name = self.get_tag_value(vpc.get('Tags', []), 'Name') or 'Unnamed'
                ipv6_cidr = None
                if vpc.get('Ipv6CidrBlockAssociationSet'):
                    ipv6_cidr = vpc['Ipv6CidrBlockAssociationSet'][0].get('Ipv6CidrBlock')
                
                inventory["vpcs"].append({
                    "id": vpc['VpcId'],
                    "name": name,
                    "cidr": vpc.get('CidrBlock'),
                    "ipv6_cidr": ipv6_cidr,
                    "state": vpc.get('State')
                })

            # 2. Subnets
            subnets_resp = self.ec2_client.describe_subnets()
            for subnet in subnets_resp.get('Subnets', []):
                name = self.get_tag_value(subnet.get('Tags', []), 'Name') or 'Unnamed'
                ipv6_cidr = None
                if subnet.get('Ipv6CidrBlockAssociationSet'):
                    ipv6_cidr = subnet['Ipv6CidrBlockAssociationSet'][0].get('Ipv6CidrBlock')
                
                inventory["subnets"].append({
                    "id": subnet['SubnetId'],
                    "name": name,
                    "vpc_id": subnet['VpcId'],
                    "cidr": subnet.get('CidrBlock'),
                    "ipv6_cidr": ipv6_cidr,
                    "az": subnet.get('AvailabilityZone')
                })

            # 3. Instances
            instances_resp = self.ec2_client.describe_instances()
            for res in instances_resp.get('Reservations', []):
                for inst in res.get('Instances', []):
                    name = self.get_tag_value(inst.get('Tags', []), 'Name') or 'Unnamed'
                    ips = [inst.get('PrivateIpAddress')] if inst.get('PrivateIpAddress') else []
                    ipv6_ips = [addr.get('Ipv6Address') for addr in inst.get('Ipv6Addresses', [])]
                    ips.extend(ipv6_ips)
                    
                    inventory["instances"].append({
                        "id": inst['InstanceId'],
                        "name": name,
                        "vpc_id": inst.get('VpcId'),
                        "subnet_id": inst.get('SubnetId'),
                        "state": inst.get('State', {}).get('Name'),
                        "type": inst.get('InstanceType'),
                        "ips": ips
                    })

            # 4. ENIs
            enis_resp = self.ec2_client.describe_network_interfaces()
            # Fetch all flow logs to match with ENIs
            try:
                flow_logs_resp = self.ec2_client.describe_flow_logs()
                eni_flow_logs = {fl['ResourceId']: fl for fl in flow_logs_resp.get('FlowLogs', []) if fl['ResourceId'].startswith('eni-')}
            except:
                eni_flow_logs = {}

            for eni in enis_resp.get('NetworkInterfaces', []):
                name = self.get_tag_value(eni.get('Tags', []), 'Name') or 'Unnamed'
                ips = [ip['PrivateIpAddress'] for ip in eni.get('PrivateIpAddresses', [])]
                ipv6_ips = [addr.get('Ipv6Address') for addr in eni.get('Ipv6Addresses', [])]
                ips.extend(ipv6_ips)
                
                eni_id = eni['NetworkInterfaceId']
                flow_log = eni_flow_logs.get(eni_id)
                inventory["enis"].append({
                    "id": eni_id,
                    "name": name,
                    "vpc_id": eni.get('VpcId'),
                    "subnet_id": eni.get('SubnetId'),
                    "status": eni.get('Status'),
                    "ips": ips,
                    "description": eni.get('Description'),
                    "flow_log_status": flow_log['FlowLogStatus'] if flow_log else 'INACTIVE',
                    "flow_log_id": flow_log['FlowLogId'] if flow_log else None
                })

            # 5. TGWs
            tgws_resp = self.ec2_client.describe_transit_gateways()
            for tgw in tgws_resp.get('TransitGateways', []):
                name = self.get_tag_value(tgw.get('Tags', []), 'Name') or 'Unnamed'
                inventory["tgws"].append({
                    "id": tgw['TransitGatewayId'],
                    "name": name,
                    "state": tgw.get('State')
                })

            # 5b. TGW Route Tables
            try:
                tgw_rtbs_resp = self.ec2_client.describe_transit_gateway_route_tables()
                for rtb in tgw_rtbs_resp.get('TransitGatewayRouteTables', []):
                    name = self.get_tag_value(rtb.get('Tags', []), 'Name') or 'Unnamed'
                    inventory["tgw_rtbs"].append({
                        "id": rtb['TransitGatewayRouteTableId'],
                        "name": name,
                        "tgw_id": rtb['TransitGatewayId'],
                        "state": rtb.get('State')
                    })
            except:
                pass

            # 5c. Route Tables
            rtbs_resp = self.ec2_client.describe_route_tables()
            for rtb in rtbs_resp.get('RouteTables', []):
                name = self.get_tag_value(rtb.get('Tags', []), 'Name') or 'Unnamed'
                inventory["route_tables"].append({
                    "id": rtb['RouteTableId'],
                    "name": name,
                    "vpc_id": rtb.get('VpcId')
                })

            # 6. DXGWs
            try:
                dxgws_resp = self.dx_client.describe_direct_connect_gateways()
                for dxgw in dxgws_resp.get('directConnectGateways', []):
                    inventory["dxgws"].append({
                        "id": dxgw['directConnectGatewayId'],
                        "name": dxgw.get('directConnectGatewayName'),
                        "state": dxgw.get('directConnectGatewayState')
                    })
                
                # 6b. DX Connections
                dx_conns_resp = self.dx_client.describe_connections()
                for conn in dx_conns_resp.get('connections', []):
                    inventory["dx_conns"].append({
                        "id": conn['connectionId'],
                        "name": conn.get('connectionName'),
                        "state": conn.get('connectionState'),
                        "location": conn.get('location')
                    })

                # 6c. VIFs
                vifs_resp = self.dx_client.describe_virtual_interfaces()
                for vif in vifs_resp.get('virtualInterfaces', []):
                    inventory["vifs"].append({
                        "id": vif['virtualInterfaceId'],
                        "name": vif.get('virtualInterfaceName'),
                        "state": vif.get('virtualInterfaceState'),
                        "type": vif.get('virtualInterfaceType')
                    })
            except Exception:
                pass # May not have permissions or DX used

        except Exception as e:
            inventory["error"] = str(e)

        return inventory

    def get_instance_name(self, instance_id):
        try:
            # Fetching the instance information
            response = self.ec2_client.describe_instances(InstanceIds=[instance_id])
    
            # Extracting the first instance from the response
            reservations = response.get('Reservations', [])
            if reservations:
                instances = reservations[0].get('Instances', [])
                if instances:
                    instance = instances[0]
                    # Extracting the Name tag from the instance tags
                    for tag in instance.get('Tags', []):
                        if tag['Key'] == 'Name':
                            return tag['Value']
            return None
        except:
            return None

    def get_flow_logs_by_vpc(self, vpc_id):
        flow_logs_response = self.ec2_client.describe_flow_logs(
            Filters=[
                {'Name': 'resource-id', 'Values': [vpc_id]}
            ]
        )
        active_flow_logs = []
    
        for flow_log in flow_logs_response['FlowLogs']:
            if flow_log['LogDestinationType'] == 'cloud-watch-logs' and flow_log['FlowLogStatus'] == 'ACTIVE':
                active_flow_logs.append(f"{flow_log['FlowLogId']} - {flow_log['LogGroupName']}")
    
        return active_flow_logs

    def get_flowlog_information(self, fl_id, eni_id, hours, filter_arg, next_token=None):
        try:
            flow_logs = self.ec2_client.describe_flow_logs(FlowLogIds=[fl_id])
            log_group_name = flow_logs['FlowLogs'][0]['LogGroupName'] if flow_logs['FlowLogs'] else None
            streams = self.log_client.describe_log_streams(
                    logGroupName=log_group_name,
                    logStreamNamePrefix=eni_id
                    )
            log_stream_name = streams['logStreams'][0]['logStreamName'] if streams['logStreams'] else None
            
            params = {
                'logGroupName': log_group_name,
                'logStreamName': log_stream_name,
                'startFromHead': True
            }
            if next_token:
                params['nextToken'] = next_token
            else:
                end_time = datetime.datetime.now(datetime.timezone.utc)
                start_time = end_time - datetime.timedelta(hours=hours)
                params['startTime'] = int(start_time.timestamp() * 1000)
                params['endTime'] = int(end_time.timestamp() * 1000)

            flowlog = self.log_client.get_log_events(**params)
            
            if filter_arg:
                lower_filter = str(filter_arg).lower()
                events = [event for event in flowlog['events'] if lower_filter in str(event.get('message', '')).lower()]
            else:
                events = flowlog["events"]
                
            formatted_messages = {}
            for event in events:
                if 'message' in event and isinstance(event['message'], str):
                    message = event["message"]
                    parts = message.split()
                    event_time = datetime.datetime.fromtimestamp(event["timestamp"]/1000, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                    src_ip = parts[3]
                    dst_ip = parts[4]
                    src_port = parts[5]
                    dst_port = parts[6]
                    protocol_num = parts[7]
                    action = parts[12]
                    status = parts[13]
                    if not event_time in formatted_messages:
                        formatted_messages[event_time] = []
                    formatted_message = f"{src_ip} {src_port} -> {dst_ip} {dst_port} - Protocol: {protocol_num} - {action} - {status}"
                    formatted_messages[event_time].append(formatted_message)
                    
            # Return tuple to support pagination/streaming
            return formatted_messages, flowlog.get('nextForwardToken')

        except:
            raise ValueError('No flowlogs found for the given identifiers.')

    def get_eni_information(self, eni_identifier):
        if eni_identifier.startswith('eni-'):
            response = self.ec2_client.describe_network_interfaces(NetworkInterfaceIds=[eni_identifier])
        else:
            ip = ipaddress.ip_address(eni_identifier)
            if isinstance(ip, ipaddress.IPv4Address):
                response = self.ec2_client.describe_network_interfaces(Filters=[{'Name': 'addresses.private-ip-address', 'Values': [eni_identifier]}])
            elif isinstance(ip, ipaddress.IPv6Address):
                response = self.ec2_client.describe_network_interfaces(Filters=[{'Name': 'ipv6-addresses.ipv6-address', 'Values': [eni_identifier]}])

        try:
            eni_info = response.get('NetworkInterfaces', [None])[0]
        except:
            raise ValueError("No ENI found for the given identifier.")
        return eni_info

    def get_vpc_association_information(self, vpc_id):
        # Fetch Transit Gateway attachments for the VPC
        tgw_attachments_response = self.ec2_client.describe_transit_gateway_attachments(Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}])
        lgw_attachments_response = self.ec2_client.describe_local_gateway_route_table_vpc_associations(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        tgw_attachments = tgw_attachments_response.get('TransitGatewayAttachments', [])
        lgw_attachments = lgw_attachments_response.get('LocalGatewayRouteTableVpcAssociations', [])

        response = {}
        for attachment in tgw_attachments:
            if 'Association' in attachment and 'TransitGatewayRouteTableId' in attachment['Association']:
                response[attachment['TransitGatewayId']] = attachment['Association']['TransitGatewayRouteTableId']
        for attachment in lgw_attachments:
            response[attachment["LocalGatewayId"]] = attachment["LocalGatewayRouteTableId"]

        return response

    def get_vpc_information(self, vpc_id):
        # Fetch VPC information
        vpc_response = self.ec2_client.describe_vpcs(VpcIds=[vpc_id])
        vpc_info = vpc_response.get('Vpcs', [None])[0]
        if not vpc_info:
            raise ValueError("No VPC found for the given ID.")

        # Fetch Transit Gateway VPC attachments to get subnets
        tgw_vpc_attach_resp = self.ec2_client.describe_transit_gateway_vpc_attachments(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}, {'Name': 'state', 'Values': ['available']}]
        )
        tgw_vpc_attachments = tgw_vpc_attach_resp.get('TransitGatewayVpcAttachments', [])

        tgw_associations = []
        for vpc_attach in tgw_vpc_attachments:
            tgw_id = vpc_attach['TransitGatewayId']
            
            # Get TGW route table association for this attachment
            # We need to find the association in the TGW itself
            tgw_attach_id = vpc_attach['TransitGatewayAttachmentId']
            attach_info = self.ec2_client.describe_transit_gateway_attachments(
                TransitGatewayAttachmentIds=[tgw_attach_id]
            ).get('TransitGatewayAttachments', [{}])[0]
            
            rt_id = "unknown"
            if 'Association' in attach_info:
                rt_id = attach_info['Association'].get('TransitGatewayRouteTableId', 'unknown')

            # Get detailed info for each subnet in the attachment
            subnets_with_rt = []
            for s_id in vpc_attach.get('SubnetIds', []):
                rt_info = self.get_route_table_information(s_id)
                subnets_with_rt.append({
                    'id': s_id,
                    'route-table': rt_info or "not-found"
                })

            tgw_associations.append({
                'tgw': tgw_id,
                'tgw-route-table': rt_id,
                'attachment-id': tgw_attach_id,
                'attachment-subnets': subnets_with_rt
            })

        return {
            'vpc': {
                'id': vpc_info.get('VpcId'),
                'cidr-blocks': [assoc['CidrBlock'] for assoc in vpc_info.get('CidrBlockAssociationSet', []) if assoc.get('CidrBlock')],
                'ipv6-cidr-blocks': [assoc['Ipv6CidrBlock'] for assoc in vpc_info.get('Ipv6CidrBlockAssociationSet', []) if assoc.get('Ipv6CidrBlock')],
                'TGW-associations': tgw_associations
            },
        }

    def get_subnet_information(self, subnet_id):
        response = self.ec2_client.describe_subnets(SubnetIds=[subnet_id])
        try:
            subnet_info = response.get('Subnets', [None])[0]
        except:
            raise ValueError("No Subnet found for the given Subnet ID.")
        return subnet_info

    def get_subnet_information_by_id_or_cidr(self, identifier):
        if identifier.startswith('subnet-'):
            response = self.ec2_client.describe_subnets(SubnetIds=[identifier])
        else:
            try:
                # Check if the identifier is an IPv4 or IPv6 CIDR block
                cidr = ipaddress.ip_network(identifier, strict=False)
                if cidr.version == 4:
                    response = self.ec2_client.describe_subnets(Filters=[{'Name': 'cidr-block', 'Values': [identifier]}])
                else:
                    response = self.ec2_client.describe_subnets(Filters=[{'Name': 'ipv6-cidr-block-association.ipv6-cidr-block', 'Values': [identifier]}])
            except ValueError:
                raise ValueError("Invalid subnet identifier. It must be a subnet ID or a valid CIDR block.")

        try:
            subnet_info = response.get('Subnets', [None])[0]
        except:
            raise ValueError("No Subnet found for the given identifier.")
        return subnet_info

    def get_route_table_information(self, subnet_id):
        response = self.ec2_client.describe_route_tables(Filters=[{'Name': 'association.subnet-id', 'Values': [subnet_id]}])
        route_tables = response.get('RouteTables', [])
        # If there are multiple route tables associated, this will get the first one
        if route_tables:
            return route_tables[0].get('RouteTableId')
        else:
            return None

    def get_lgw_route_table_information_by_id(self, lgw_rt_id):
        response = self.ec2_client.search_local_gateway_routes(
            LocalGatewayRouteTableId=lgw_rt_id)
        try:
            routes = response.get('Routes', [])
        except:
            raise ValueError("No LGW Route Table found for the given ID.")
        return routes

    def get_tgw_route_table_information_by_id(self, tgw_rt_id):
        response = self.ec2_client.search_transit_gateway_routes(
            TransitGatewayRouteTableId=tgw_rt_id,
            Filters=[{'Name': 'state', 'Values': ['active', 'blackhole']}]
        )
        try:
            routes = response.get('Routes', [])
        except:
            raise ValueError("No TGW Route Table found for the given ID.")
        return routes


    def get_route_table_information_by_id(self, route_table_id):
        response = self.ec2_client.describe_route_tables(RouteTableIds=[route_table_id])
        try:
            route_table_info = response.get('RouteTables', [None])[0]
        except:
            raise ValueError("No Route Table found for the given ID.")
        return route_table_info

    def get_tag_value(self, tags, key):
        for tag in tags:
            if tag['Key'] == key:
                return tag['Value']
        return None

    def get_security_group_information(self, sg_id):
        try:
            response = self.ec2_client.describe_security_groups(GroupIds=[sg_id])
            sg_info = response.get('SecurityGroups', [None])[0]
            if not sg_info:
                raise ValueError("No Security Group found for the given ID.")
            return sg_info
        except Exception as e:
            print(f"Error retrieving security group information: {e}")
            return None


    def get_network_acl_information(self, acl_id):
        try:
            response = self.ec2_client.describe_network_acls(NetworkAclIds=[acl_id])
            acl_info = response.get('NetworkAcls', [None])[0]
            if not acl_info:
                raise ValueError("No Network ACL found for the given ID.")
            return acl_info
        except Exception as e:
            print(f"Error retrieving network ACL information: {e}")
            return None

    def get_instance_information(self, instance_identifier):
        try:
            # Check if identifier is an instance ID or name
            filters = [{'Name': 'instance-id', 'Values': [instance_identifier]}]
            if not instance_identifier.startswith('i-'):
                filters = [{'Name': 'tag:Name', 'Values': [instance_identifier]}]

            response = self.ec2_client.describe_instances(Filters=filters)
            instances = response.get('Reservations', [])[0].get('Instances', [])
            if not instances:
                return "Instance not found"

            instance_info = instances[0]
            instance_id = instance_info['InstanceId']

            status_checks = {
                    'instance_status': 'unknown',
                    'system_status': 'unknown'
                }
            try:
                status = self.ec2_client.describe_instance_status(InstanceIds=[instance_id])
                instance_status = status['InstanceStatuses'][0]
                status_checks['instance_status'] = instance_status['InstanceStatus']['Status']
                status_checks['system_status'] = instance_status['SystemStatus']['Status']
            except:
                pass

            instance_name = next((tag['Value'] for tag in instance_info['Tags'] if tag['Key'] == 'Name'), 'Unnamed')
            custodian = next((tag['Value'] for tag in instance_info['Tags'] if tag['Key'] == 'custodian-ignore'), False)
            state = instance_info['State']["Name"]
            vpc_id = instance_info['VpcId']
            try:
                iam_info = instance_info['IamInstanceProfile']
                iam_role = iam_info['Arn'].split('/')[-1]
            except:
                iam_role = None

            # Create a list of ENI dictionaries
            enis_list = [{
                'position': eni['Attachment']['DeviceIndex'],
                'id': eni['NetworkInterfaceId'],
                'subnet': eni['SubnetId'],
                "Security Groups": [group['GroupId'] for group in eni.get('Groups', [])],
                'ips': [ip['PrivateIpAddress'] for ip in eni['PrivateIpAddresses']],
            } for eni in instance_info['NetworkInterfaces']]
        
            # Sort the list based on the position
            enis_sorted_list = sorted(enis_list, key=lambda x: x['position'])
        
            # Create a dictionary from the sorted list
            enis_sorted = {eni['id']: {k: v for k, v in eni.items() if k != 'id'} for eni in enis_sorted_list}

            return {
                'id': instance_id,
                'name': instance_name,
                'vpc': vpc_id,
                'iam': iam_role,
                'state': state,
                'status': status_checks,
                'Keep after shutdown': custodian,
                'enis': enis_sorted
            }
        except:
            raise ValueError("No ec2 found for the given identifier.")

    def get_acl_by_subnet(self, subnet_id):
        try:
            # Fetching all network ACLs
            response = self.ec2_client.describe_network_acls(Filters=[
                {'Name': 'association.subnet-id', 'Values': [subnet_id]}
            ])

            acls = []
            for acl in response.get('NetworkAcls', []):
                acls.append(acl.get('NetworkAclId'))

            return acls[0]
        except:
            raise ValueError("No acl found for the given identifier.")

    def get_acl_by_id(self, subnet_id):
        try:
            # Fetching all network ACLs
            response = self.ec2_client.describe_network_acls(Filters=[
                {'Name': 'association.subnet-id', 'Values': [subnet_id]}
            ])

            acls = []
            for acl in response.get('NetworkAcls', []):
                acl_info = {
                    'id': acl.get('NetworkAclId'),
                    'is_default': acl.get('IsDefault'),
                    'entries': acl.get('Entries', []),
                    'associations': acl.get('Associations', [])
                    # Add other relevant details here
                }
                acls.append(acl_info)

            return acls
        except:
            raise ValueError("No acl found for the given identifier.")

    def format_eni_output(self, eni_info, subnet_info):

        subnet_tags = subnet_info.get('Tags', [])
        eni_tags = eni_info.get('Tags', [])
        route_table_id = self.get_route_table_information(subnet_info.get('SubnetId'))
        acl = self.get_acl_by_subnet(subnet_info.get("SubnetId"))
        flowlogs = self.get_flow_logs_by_vpc(subnet_info.get('VpcId'))
        instance = eni_info.get('Attachment', {}).get('InstanceId', 'Not attached')
        if instance.startswith("i-"):
            instance_name = self.get_instance_name(instance)
            if instance_name:
                instance = f"{instance_name} ({instance})"

        output = {
            "ENI": {
                "ID": eni_info.get('NetworkInterfaceId'),
                "description": eni_info.get('Description'),
                "instance": instance,
                "ips": [ip['PrivateIpAddress'] for ip in eni_info.get('PrivateIpAddresses', [])] + 
                       [ipv6['Ipv6Address'] for ipv6 in eni_info.get('Ipv6Addresses', [])],
                "Security Groups": [group['GroupId'] for group in eni_info.get('Groups', [])],
                "flowlogs": flowlogs
            },
            "subnet": {
                "ID": subnet_info.get('SubnetId'),
                "cidr": subnet_info.get('CidrBlock'),
                "ipv6_cidr": next((assoc['Ipv6CidrBlock'] for assoc in subnet_info.get('Ipv6CidrBlockAssociationSet', []) if assoc.get('Ipv6CidrBlock') and assoc.get('Ipv6CidrBlockState', {}).get('State') == 'associated'), None),
                "vpc": subnet_info.get('VpcId'),
                "route-table": route_table_id,
                "Vrouter": self.get_tag_value(subnet_tags, 'VrouterName'),
                "Vrouter-Position": self.get_tag_value(subnet_tags, 'VrouterInterfacePos'),
                "Vrf": self.get_tag_value(subnet_tags, 'VRFName'),
                "CTX": self.get_tag_value(subnet_tags, 'CTX'),
                "CTX-GW": self.get_tag_value(eni_tags, 'CTX-GW'),
                "CTX-PEER-GROUP": self.get_tag_value(eni_tags, 'CTX-PEER-GROUP'),
                "acl": acl
            }
        }
        return output

    def format_subnet_output(self, subnet_info):

        subnet_tags = subnet_info.get('Tags', [])
        route_table_id = self.get_route_table_information(subnet_info.get('SubnetId'))
        enis = self.get_enis_by_subnet(subnet_info.get('SubnetId'))
        acl = self.get_acl_by_subnet(subnet_info.get("SubnetId"))

        output = {
            "subnet": {
                "ID": subnet_info.get('SubnetId'),
                "cidr": subnet_info.get('CidrBlock'),
                "ipv6_cidr": next((assoc['Ipv6CidrBlock'] for assoc in subnet_info.get('Ipv6CidrBlockAssociationSet', []) if assoc.get('Ipv6CidrBlock') and assoc.get('Ipv6CidrBlockState', {}).get('State') == 'associated'), None),
                "vpc": subnet_info.get('VpcId'),
                "route-table": route_table_id,
                "Vrouter": self.get_tag_value(subnet_tags, 'VrouterName'),
                "Vrouter-Position": self.get_tag_value(subnet_tags, 'VrouterInterfacePos'),
                "Vrf": self.get_tag_value(subnet_tags, 'VRFName'),
                "CTX": self.get_tag_value(subnet_tags, 'CTX'),
                "acl": acl
            },
            "enis": enis
        }
        return output

    def format_route(self, route):
        nexthop = route.get('GatewayId') or \
                  route.get('EgressOnlyInternetGatewayId') or \
                  route.get('TransitGatewayId') or \
                  route.get('NetworkInterfaceId') or \
                  route.get('VpcPeeringConnectionId') or \
                  route.get('NatGatewayId') or \
                  route.get('LocalGatewayId') or \
                  route.get('CarrierGatewayId') or \
                  route.get('CoreNetworkArn') or \
                  route.get('VpcEndpointId') or \
                  route.get('InstanceId') or \
                  route.get('GatewayLoadBalancerEndpointId') or \
                  route.get('VirtualPrivateGatewayId') or \
                  'local'  # 'local' is used if none of the above are found
    
        destination = route.get('DestinationCidrBlock') or \
                      route.get('DestinationIpv6CidrBlock') or \
                      route.get('DestinationPrefixListId')
    
        if nexthop.startswith(("tgw-", "lgw-")):
            nexthop = f"{nexthop} to {self.vpc_info[nexthop]}"

        if destination.startswith("pl-"):
            return {f"{destination} via {nexthop}": [', '.join(map(str, self.get_managed_prefix_list_entries(destination)))]}
        else:
            return f"{destination} via {nexthop}"


    def get_eni_by_sg(self, sg_id):
        try:
            response = self.ec2_client.describe_network_interfaces(Filters=[{
                        'Name': 'group-id',
                                'Values': [sg_id]
                }])
            enis = []
            for eni in response.get('NetworkInterfaces', []):
                eni_id = eni.get('NetworkInterfaceId')
                enis.append(eni_id)
        
            return enis
        except:
            raise ValueError("Error retrieving instances by sg_id")

    def get_dxcon_information(self, dxcon_id):
        try:
            dxcon = self.dx_client.describe_connections(
                connectionId=dxcon_id
            )
            dxvifs = self.dx_client.describe_virtual_interfaces(connectionId=dxcon_id)
            response = {"dxcon": dxcon.get('connections', [None])[0], "dxvifs": dxvifs.get("virtualInterfaces", [None])}
            return response
        except:
            raise ValueError("Error retrieving DXCON information")

    def get_dxvif_information(self, dxvif_id):
        try:
            dxvif = self.dx_client.describe_virtual_interfaces(
                virtualInterfaceId=dxvif_id
            )
            dxgw_id = dxvif.get('virtualInterfaces', [None])[0]['directConnectGatewayId']
            dxgw = self.dx_client.describe_direct_connect_gateways(directConnectGatewayId=dxgw_id)
            response = {"dxvif": dxvif.get('virtualInterfaces', [None])[0], "dxgw": dxgw.get("directConnectGateways", [None])}
            return response
        except:
            raise ValueError("Error retrieving DXVIF information")

    def get_dxgw_information(self, dxgw_id):
        try:
            dxgw = self.dx_client.describe_direct_connect_gateways(
                directConnectGatewayId=dxgw_id
            )
            attachments = self.dx_client.describe_direct_connect_gateway_attachments(
                directConnectGatewayId=dxgw_id
            )
            associations = self.dx_client.describe_direct_connect_gateway_associations(
                directConnectGatewayId=dxgw_id
            )
            response = {"dxgw": dxgw.get('directConnectGateways', [None])[0], "attachments": attachments.get('directConnectGatewayAttachments', [None]), "associations": associations.get("directConnectGatewayAssociations", [None])}
            return response
        except:
            raise ValueError("Error retrieving DXGW information")

    def get_transit_gateway_information(self, tgw_id):
        try:
            # Check if identifier is an instance ID or name
            filters = [{'Name': 'transit-gateway-id', 'Values': [tgw_id]}]
            if not tgw_id.startswith('tgw-'):
                filters = [{'Name': 'tag:Name', 'Values': [tgw_id]}]

            response = self.ec2_client.describe_transit_gateways(Filters=filters)
            tgw = response.get('TransitGateways', [None])[0]

            # Format the TGW information
            formatted_tgw_info = {
                'id': tgw.get('TransitGatewayId'),
                'name': self.get_tag_value(tgw.get('Tags', []), 'Name'),
                'description': tgw.get('Description'),
                'options': tgw.get('Options', {})
            }
            return formatted_tgw_info
        except:
            raise ValueError("Error retrieving TGW")

    def get_enis_by_subnet(self, subnet_id):
        try:
            response = self.ec2_client.describe_network_interfaces(Filters=[
                {'Name': 'subnet-id', 'Values': [subnet_id]}
            ])

            enis = []
            for eni in response.get('NetworkInterfaces', []):
                eni_info = {
                    'id': eni.get('NetworkInterfaceId'),
                    'description': eni.get('Description'),
                    "ips": [ip['PrivateIpAddress'] for ip in eni.get('PrivateIpAddresses', [])] + 
                       [ipv6['Ipv6Address'] for ipv6 in eni.get('Ipv6Addresses', [])],
                    # Add other relevant details here
                }
                enis.append(eni_info)

            return enis
        except:
            raise ValueError("Error retrieving instances by subnet_id")

    def get_managed_prefix_list_entries(self, prefix_list_id):
        try:
            response = self.ec2_client.get_managed_prefix_list_entries(PrefixListId=prefix_list_id)
            return [entry['Cidr'] for entry in response.get('Entries', [])]
        except:
            raise ValueError("Error retrieving managed prefix list entries")


    def format_dxcon_output(self, response):
        # Extracting Direct Connect connection information
        dxcon_info = {
            'id': response['dxcon']['connectionId'],
            'name': response['dxcon']['connectionName'],
            'region': response['dxcon']['region'],
            'bw': response['dxcon']['bandwidth'],
            'jumbo frame': response['dxcon']['jumboFrameCapable'],
            'device': response['dxcon']['awsDevice'],
            'logical device': response['dxcon']['awsLogicalDeviceId'],
            'vifs': []
        }
        
        # Process each VIF associated with the connection
        for vif in response['dxvifs']:
            vif_info = {
                'id': vif['virtualInterfaceId'],
                'connection id': vif['connectionId'],
                'vlan': vif['vlan'],
                'Amazon AS': vif['amazonSideAsn'],
                'dxgw-id': vif.get('directConnectGatewayId', 'N/A'),  # Using 'N/A' if not present
                'peers': []
            }
            
            # Add peer information for each VIF
            for peer in vif['bgpPeers']:
                peer_info = {peer['bgpPeerId']: {
                    peer['bgpPeerId']: {
                        'asn': peer['asn'],
                        'authKey': peer['authKey'],
                        'addressFamily': peer['addressFamily'],
                        'amazonAddress': peer['amazonAddress'],
                        'customerAddress': peer['customerAddress'],
                        'bgpPeerState': peer['bgpPeerState'],
                        'bgpStatus': peer['bgpStatus'],
                        # Include additional BGP peer information if necessary
                    }
                }}
                vif_info['peers'].append(peer_info)
            
            dxcon_info['vifs'].append(vif_info)
        
        # Find the DXGW name using the DXGW ID from the DXVIF
        if 'dxgw' in response and response['dxgw']:
            dxgw_id = response['dxvifs'][0].get('directConnectGatewayId')
            dxgw_info = next((gw for gw in response['dxgw'] if gw['directConnectGatewayId'] == dxgw_id), {})
            dxcon_info['dxgw-name'] = dxgw_info.get('directConnectGatewayName', 'N/A')
    
        return dxcon_info

    def format_dxvif_output(self,vif_data):
        # Extracting Virtual Interface (VIF) information
        vif_info = {
            'id': vif_data['dxvif']['virtualInterfaceId'],
            'connection id': vif_data['dxvif']['connectionId'],
            'vlan': vif_data['dxvif']['vlan'],
            'Amazon AS': vif_data['dxvif']['amazonSideAsn'],
            'region': vif_data['dxvif']['region'],
            'dxgw-id': vif_data['dxvif']['directConnectGatewayId']
        }
        
        # Find the DXGW name using the DXGW ID
        dxgw_name = next((gw['directConnectGatewayName'] for gw in vif_data['dxgw'] if gw['directConnectGatewayId'] == vif_data['dxvif']['directConnectGatewayId']), None)
        vif_info['dxgw-name'] = dxgw_name
        
        # Processing BGP Peers
        for peer in vif_data['dxvif']['bgpPeers']:
            peer_info = {
                peer['bgpPeerId']: {
                    'asn': peer['asn'],
                    'authKey': peer['authKey'],
                    'addressFamily': peer['addressFamily'],
                    'amazonAddress': peer['amazonAddress'],
                    'customerAddress': peer['customerAddress'],
                    'bgpPeerState': peer['bgpPeerState'],
                    'bgpStatus': peer['bgpStatus'],
                    # Include additional BGP peer information if necessary
                }
            }
            vif_info['Peers'] = []
            vif_info['Peers'].append(peer_info)
        
        return vif_info

    def format_dxgw_output(self, response):
        # Extracting Direct Connect Gateway information
        dxgw_info = {
            'id': response['dxgw'].get('directConnectGatewayId'),
            'name': response['dxgw'].get('directConnectGatewayName'),
            'Amazon AS': response['dxgw'].get('amazonSideAsn'),
            'vifs': [],
            'tgw': {}
        }
    
        # Processing Virtual Interface (VIF) attachments
        for attachment in response['attachments']:
            vif_info = f"{attachment.get('virtualInterfaceId')} ({attachment.get('virtualInterfaceRegion')})"
            dxgw_info['vifs'].append(vif_info)
    
        # Processing Transit Gateway associations
        for association in response['associations']:
            tgw_id = association['associatedGateway'].get('id')
            tgw_region = association['associatedGateway'].get('region')
            allowed_prefixes = [prefix['cidr'] for prefix in association['allowedPrefixesToDirectConnectGateway']]
            
            if tgw_id not in dxgw_info['tgw']:
                dxgw_info['tgw'][tgw_id] = {
                    'region': tgw_region,
                    'cidrs': allowed_prefixes
                }
            else:
                # Append CIDRs if the TGW ID is already in the dictionary
                dxgw_info['tgw'][tgw_id]['cidrs'].extend(allowed_prefixes)
    
        return dxgw_info

    def format_rt_output(self, rt_info, filter_ip):
        if filter_ip == "all":
            filter_ip = None
        routes = rt_info.get('Routes', [])
        most_specific_route = None
        most_specific_length = -1  # Initial value for comparison
        
        vpc_id = rt_info.get('VpcId')  # Extract VPC ID from route table information
        self.vpc_info = self.get_vpc_association_information(vpc_id)
    
        for route in routes:
            # Check direct destinations first
            direct_destinations = []
            if route.get('DestinationCidrBlock'):
                direct_destinations.append(route['DestinationCidrBlock'])
            if route.get('DestinationIpv6CidrBlock'):
                direct_destinations.append(route['DestinationIpv6CidrBlock'])
    

            # Check for the most specific match among direct destinations
            for destination in direct_destinations:
                try:
                    destination_network = ipaddress.ip_network(destination, strict=False)
                    if filter_ip:
                        filter_network = ipaddress.ip_network(filter_ip, strict=False)
    
                        if filter_network.version != destination_network.version:
                            continue
    
                        if filter_network.subnet_of(destination_network):
                            if destination_network.prefixlen >= most_specific_length:
                                most_specific_length = destination_network.prefixlen
                                most_specific_route = route
                except ValueError:
                    continue
    
            # If a direct route is already the most specific, skip prefix list check
            if most_specific_route and route == most_specific_route:
                continue
    
            # Check prefix list destinations if no direct route is the most specific yet
            if route.get('DestinationPrefixListId'):
                prefix_list_id = route['DestinationPrefixListId']
                prefix_list_cidrs = self.get_managed_prefix_list_entries(prefix_list_id)
                for destination in prefix_list_cidrs:
                    try:
                        destination_network = ipaddress.ip_network(destination, strict=False)
                        if filter_ip:
                            if filter_network.version != destination_network.version:
                                continue
    
                            if filter_network.subnet_of(destination_network):
                                if destination_network.prefixlen > most_specific_length:
                                    most_specific_length = destination_network.prefixlen
                                    most_specific_route = route
                    except ValueError:
                        continue
    
        output = {"vpcid": vpc_id}
    
        # If no matching route is found, return an empty output or all routes if no filter is provided
        if not filter_ip:
            output["routes"] = [self.format_route(route) for route in routes]
        elif not most_specific_route:
            output["routes"] = []
        else:
            output["routes"] = [self.format_route(most_specific_route)]
    
        return output

    def format_tgw_route(self, route):
        # Determine if it's a propagated or static route
        route_type = 'p' if route.get('Type') == 'propagated' else 's'


        # Get destination (supporting both IPv4 and IPv6)
        destination = route.get('DestinationCidrBlock') or route.get('DestinationIpv6CidrBlock', '')

        if route.get('State') == 'blackhole':
            formatted_route = {f"({route_type}) {destination} via static": ["blackhole"]}
        else:
            # Collect and format the resource IDs
            resource_ids = [attachment.get('ResourceId') for attachment in route.get('TransitGatewayAttachments', [])]
            resource_type = next((attachment.get('ResourceType') for attachment in route.get('TransitGatewayAttachments', [])), 'unknown')
            resource_count = len(resource_ids)
            resource_ids_str = [', '.join(resource_ids)]
            formatted_route = {f"({route_type}) {destination} via {resource_count} {resource_type}": resource_ids_str}

        return formatted_route

    def format_tgw_rt_output(self, tgw_rt_info, filter_ip=None):
        if filter_ip == "all":
            filter_ip = None
        routes = tgw_rt_info
        most_specific_route = None
        most_specific_length = -1  # Initial value for comparison

        for route in routes:
            # Extract destination (IPv4 or IPv6)
            destination = route.get('DestinationCidrBlock') or route.get('DestinationIpv6CidrBlock', '')
            
            try:
                destination_network = ipaddress.ip_network(destination, strict=False)
                if filter_ip:
                    filter_network = ipaddress.ip_network(filter_ip, strict=False)

                    if filter_network.version != destination_network.version:
                        continue

                    if filter_network.subnet_of(destination_network):
                        if destination_network.prefixlen > most_specific_length:
                            most_specific_length = destination_network.prefixlen
                            most_specific_route = route
            except ValueError:
                continue

        output = {"tgw_routes": []}

        # If no matching route is found, return all routes if no filter is provided
        if not filter_ip:
            output["tgw_routes"] = [self.format_tgw_route(route) for route in routes]
        elif most_specific_route:
            output["tgw_routes"] = [self.format_tgw_route(most_specific_route)]

        return output

    def format_lgw_route(self, route):
        # Determine next hop
        nexthop = route.get('LocalGatewayVirtualInterfaceGroupId') or \
                  route.get('NetworkInterfaceId') or \
                  'local'
        
        destination = route.get('DestinationCidrBlock') or 'unknown'
        route_type = 's' # LGW routes are usually static or from VIF group
        
        formatted_route = {f"({route_type}) {destination} via {nexthop}": [route.get('State', 'active')]}
        return formatted_route

    def format_lgw_rt_output(self, lgw_rt_info, filter_ip=None):
        if filter_ip == "all":
            filter_ip = None
        routes = lgw_rt_info
        most_specific_route = None
        most_specific_length = -1

        for route in routes:
            destination = route.get('DestinationCidrBlock', '')
            try:
                destination_network = ipaddress.ip_network(destination, strict=False)
                if filter_ip:
                    filter_network = ipaddress.ip_network(filter_ip, strict=False)
                    if filter_network.version == destination_network.version:
                        if filter_network.subnet_of(destination_network):
                            if destination_network.prefixlen > most_specific_length:
                                most_specific_length = destination_network.prefixlen
                                most_specific_route = route
            except ValueError:
                continue

        output = {"lgw_routes": []}
        if not filter_ip:
            output["lgw_routes"] = [self.format_lgw_route(route) for route in routes]
        elif most_specific_route:
            output["lgw_routes"] = [self.format_lgw_route(most_specific_route)]
        return output

    def format_sg_output(self, sg_info):
        formatted_sg = {
            "Description": sg_info.get("Description"),
            "Group Name": sg_info.get("GroupName"),
            "Inbound Rules": self.format_sg_rules(sg_info.get("IpPermissions", [])),
            "Outbound Rules": self.format_sg_rules(sg_info.get("IpPermissionsEgress", []))
        }
        return formatted_sg
    
    def format_sg_rules(self, rules):
        formatted_rules = []
        for rule in rules:
            ip_protocol = rule.get("IpProtocol", "-1")
            from_port = rule.get("FromPort", "-1")
            to_port = rule.get("ToPort", "-1")
    
            # Interpret '-1' as 'all'
            ip_protocol = "all" if str(ip_protocol) == "-1" else ip_protocol
            port_range = "all" if str(from_port) == "-1" else f"{from_port}-{to_port}" if from_port != to_port else f"{from_port}"
            type = "type" if ip_protocol == "icmp" else "port"
            # Handling different types of sources (CIDR, security group, etc.)
            sources = []
            for ip_range in rule.get("IpRanges", []):
                sources.append([ip_range.get("CidrIp", ""), ip_range.get("Description", None)])
            for ipv6_range in rule.get("Ipv6Ranges", []):
                sources.append([ipv6_range.get("CidrIpv6", ""), ipv6_range.get("Description", None)])
            for user_id_group_pair in rule.get("UserIdGroupPairs", []):
                sources.append([user_id_group_pair.get("GroupId", ""), user_id_group_pair.get("Description", None)])
            for prefix_list_id in rule.get("PrefixListIds", []):
                sources.append([prefix_list_id.get("PrefixListId", ""), prefix_list_id.get("Description", None)])
    
            # Formatting each rule
            for source in sources:
                if source[0].startswith("pl-"):
                    rule_str = {f"permit {ip_protocol} from: {source[0]} {type} {port_range} - Desc: {source[1]}": [', '.join(map(str, self.get_managed_prefix_list_entries(source[0])))]}
                elif source[0].startswith("sg-"):
                    rule_str = {f"permit {ip_protocol} from: {source[0]} {type} {port_range} - Desc: {source[1]}": [', '.join(map(str, self.get_eni_by_sg(source[0])))]}
                else:
                    rule_str = f"permit {ip_protocol} from: {source[0]} {type} {port_range} - Desc: {source[1]}"
                formatted_rules.append(rule_str)
    
        return formatted_rules

    def format_acl_output(self, acl_info):
        formatted_acl = {
            "Network ACL ID": acl_info.get("NetworkAclId"),
            "VPC ID": acl_info.get("VpcId"),
            "Inbound": self.format_acl_entries(acl_info.get("Entries", []), egress=False),
            "Outbound": self.format_acl_entries(acl_info.get("Entries", []), egress=True)
        }
        return formatted_acl 
    
    def format_acl_entries(self, entries, egress):
        formatted_entries = []
        for entry in entries:
            if entry.get("Egress") == egress:
                protocol = self.get_protocol_name(entry.get('Protocol'))
                rule_action = "permit" if entry.get('RuleAction') == 'allow' else "deny"
                cidr = entry.get('CidrBlock') or entry.get('Ipv6CidrBlock', '')
                port_str = self.get_port_string(entry, protocol)
                rule_str = f"{entry.get('RuleNumber')}: {rule_action} {protocol} from {cidr} {port_str}"
                formatted_entries.append(rule_str)
    
        return formatted_entries
    
    def get_port_string(self, entry, protocol):
        """ Format the port range for the ACL entry. """
        if protocol in ['tcp', 'udp', '6', '17']:  # TCP and UDP protocols
            port_range = entry.get('PortRange')
            if port_range:
                return f"port: {port_range.get('From')}-{port_range.get('To')}"
        return ""
    
    def get_protocol_name(self, protocol_code):
        """ Convert protocol code to a more understandable text. """
        protocol_map = {
            "-1": "all",
            "1": "icmp",
            "6": "tcp",
            "17": "udp",
            # Add other protocols as needed
        }
        return protocol_map.get(str(protocol_code), protocol_code)

    def get_all_instances_bw(self, unit='mbps'):
        # Divisor mapping
        unit_map = {'bps': 1, 'kbps': 1000, 'mbps': 1000000, 'gbps': 1000000000}
        divisor = unit_map.get(unit.lower(), 1000000)
        # 1. Map ASGs to Instance IDs (Same as in PPS)
        asg_to_id = {}
        try:
            paginator = self.asg_client.get_paginator('describe_auto_scaling_groups')
            for page in paginator.paginate():
                for group in page['AutoScalingGroups']:
                    if group['Instances']:
                        asg_to_id[group['AutoScalingGroupName']] = group['Instances'][0]['InstanceId']
        except: pass

        # 2. Time Window logic
        end_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
        start_time = end_time - datetime.timedelta(minutes=15)
        period = 300

        # 3. Fetch Metrics (NetworkIn instead of NetworkPacketsIn)
        metrics = self.cw_client.list_metrics(Namespace='AWS/EC2', MetricName='NetworkIn')
        results = {}

        for m in metrics.get('Metrics', []):
            # 1. Dimension Validation (Prevents IndexError if the list is empty)
            if not m.get('Dimensions'):
                continue
            
            raw_dim = m['Dimensions'][0]['Value']
            resolved_id = asg_to_id.get(raw_dim, raw_dim)

            try:
                res = self.cw_client.get_metric_data(
                    MetricDataQueries=[
                        {'Id': 'i_raw', 'MetricStat': {'Metric': m, 'Period': period, 'Stat': 'Sum'}, 'ReturnData': False},
                        {'Id': 'o_raw', 'MetricStat': {'Metric': {'Namespace': 'AWS/EC2', 'MetricName': 'NetworkOut', 'Dimensions': m['Dimensions']}, 'Period': period, 'Stat': 'Sum'}, 'ReturnData': False},
                        {'Id': 'in', 'Expression': f'(i_raw*8)/({period}*{divisor})', 'ReturnData': True},
                        {'Id': 'out', 'Expression': f'(o_raw*8)/({period}*{divisor})', 'ReturnData': True},
                        {'Id': 'total', 'Expression': f'((i_raw+o_raw)*8)/({period}*{divisor})', 'ReturnData': True}
                    ],
                    StartTime=start_time, EndTime=end_time
                )
                
                # 2. Safe value extraction
                data = {'in': 0.0, 'out': 0.0, 'total': 0.0}
                for r in res.get('MetricDataResults', []):
                    # We verify that 'Values' exists and has at least one element
                    if r.get('Values') and len(r['Values']) > 0:
                        data[r['Id']] = r['Values'][0]
                
                # 3. Filtering and Deduplication
                total_val = data['total']
                if total_val > 0:
                    if resolved_id not in results or total_val > results[resolved_id]['total']:
                        results[resolved_id] = {
                            'id': resolved_id,
                            'in': data['in'],
                            'out': data['out'],
                            'total': total_val,
                            'name': self.get_instance_name(resolved_id) if resolved_id.startswith('i-') else raw_dim
                        }
            except Exception as e:
                # If a specific metric fails, skip to the next one without breaking the script
                continue
        
        return sorted(results.values(), key=lambda x: x['total'], reverse=True)

    def get_all_instances_pps(self):
        # 1. Map ASGs to Instance IDs using the pre-initialized client
        asg_to_id = {}
        try:
            paginator = self.asg_client.get_paginator('describe_auto_scaling_groups')
            for page in paginator.paginate():
                for group in page['AutoScalingGroups']:
                    if group['Instances']:
                        asg_to_id[group['AutoScalingGroupName']] = group['Instances'][0]['InstanceId']
        except: pass

        # 2. Time Window logic (remains the same)
        end_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
        start_time = end_time - datetime.timedelta(minutes=15)
        period = 300

        # 3. Fetch Metrics using self.cw_client
        metrics = self.cw_client.list_metrics(Namespace='AWS/EC2', MetricName='NetworkPacketsIn')
        results = {}

        for m in metrics['Metrics']:
            raw_dim = m['Dimensions'][0]['Value']
            resolved_id = asg_to_id.get(raw_dim, raw_dim)

            res = self.cw_client.get_metric_data(
                MetricDataQueries=[
                    {'Id': 'i_raw', 'MetricStat': {'Metric': m, 'Period': period, 'Stat': 'Sum'}, 'ReturnData': False},
                    {'Id': 'o_raw', 'MetricStat': {'Metric': {'Namespace': 'AWS/EC2', 'MetricName': 'NetworkPacketsOut', 'Dimensions': m['Dimensions']}, 'Period': period, 'Stat': 'Sum'}, 'ReturnData': False},
                    {'Id': 'in', 'Expression': f'i_raw/{period}', 'ReturnData': True},
                    {'Id': 'out', 'Expression': f'o_raw/{period}', 'ReturnData': True},
                    {'Id': 'total', 'Expression': f'(i_raw+o_raw)/{period}', 'ReturnData': True}
                ],
                StartTime=start_time, EndTime=end_time
            )
            
            data = {r['Id']: r['Values'][0] if r['Values'] else 0 for r in res['MetricDataResults']}
            
            if data.get('total', 0) > 0:
                # Deduplication logic: keep the entry with highest traffic for the same ID
                if resolved_id not in results or data['total'] > results[resolved_id]['total']:
                    results[resolved_id] = {
                        'id': resolved_id,
                        'in': data['in'],
                        'out': data['out'],
                        'total': data['total'],
                        'name': self.get_instance_name(resolved_id) if resolved_id.startswith('i-') else raw_dim
                    }
        
        return sorted(results.values(), key=lambda x: x['total'], reverse=True)

    def get_instance_bw(self, instance_id, hours, unit='mbps'):
        # Divisor mapping for formula: (Bytes * 8) / (period * divisor)
        unit_map = {
            'bps': 1,
            'kbps': 1000,
            'mbps': 1000000,
            'gbps': 1000000000
        }
        divisor = unit_map.get(unit.lower(), 1000000)
        end_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
        start_time = end_time - datetime.timedelta(hours=hours)
        period = 300 

        try:
            response = self.cw_client.get_metric_data(
                MetricDataQueries=[
                    {
                        'Id': 'i', 
                        'MetricStat': {
                            'Metric': {
                                'Namespace': 'AWS/EC2', 
                                'MetricName': 'NetworkIn', 
                                'Dimensions': [{'Name': 'InstanceId', 'Value': instance_id}]
                            }, 
                            'Period': period, 'Stat': 'Sum'
                        }, 
                        'ReturnData': False
                    },
                    {
                        'Id': 'o', 
                        'MetricStat': {
                            'Metric': {
                                'Namespace': 'AWS/EC2', 
                                'MetricName': 'NetworkOut', 
                                'Dimensions': [{'Name': 'InstanceId', 'Value': instance_id}]
                            }, 
                            'Period': period, 'Stat': 'Sum'
                        }, 
                        'ReturnData': False
                    },
                    # Metric Math for Mbps
                    {'Id': 'bw_in', 'Expression': f'(i*8)/({period}*{divisor})', 'ReturnData': True},
                    {'Id': 'bw_out', 'Expression': f'(o*8)/({period}*{divisor})', 'ReturnData': True}
                ],
                StartTime=start_time,
                EndTime=end_time,
                ScanBy='TimestampAscending'
            )
            
            results = {'timestamps': [], 'in': [], 'out': []}
            
            for res in response.get('MetricDataResults', []):
                if res['Id'] == 'bw_in':
                    results['timestamps'] = [t.strftime("%H:%M") for t in res['Timestamps']]
                    results['in'] = res['Values']
                elif res['Id'] == 'bw_out':
                    results['out'] = res['Values']
                    
            return results
        except Exception as e:
            raise ValueError(f"Error fetching BW data from CloudWatch: {e}")

    def get_instance_pps(self, instance_id, hours):
        """Fetches PPS metrics for a specific instance for graphing."""
        # 1. Setup Time Window (5-min offset for CW consistency)
        end_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
        start_time = end_time - datetime.timedelta(hours=hours)
        period = 300 

        try:
            # 2. Fetch Metrics using the centralized CW client
            response = self.cw_client.get_metric_data(
                MetricDataQueries=[
                    {
                        'Id': 'i', 
                        'MetricStat': {
                            'Metric': {
                                'Namespace': 'AWS/EC2', 
                                'MetricName': 'NetworkPacketsIn', 
                                'Dimensions': [{'Name': 'InstanceId', 'Value': instance_id}]
                            }, 
                            'Period': period, 
                            'Stat': 'Sum'
                        }, 
                        'ReturnData': False
                    },
                    {
                        'Id': 'o', 
                        'MetricStat': {
                            'Metric': {
                                'Namespace': 'AWS/EC2', 
                                'MetricName': 'NetworkPacketsOut', 
                                'Dimensions': [{'Name': 'InstanceId', 'Value': instance_id}]
                            }, 
                            'Period': period, 
                            'Stat': 'Sum'
                        }, 
                        'ReturnData': False
                    },
                    # We use Metric Math to calculate real average PPS over the 300s window
                    {'Id': 'pps_in', 'Expression': f'i / {period}', 'ReturnData': True},
                    {'Id': 'pps_out', 'Expression': f'o / {period}', 'ReturnData': True}
                ],
                StartTime=start_time,
                EndTime=end_time,
                ScanBy='TimestampAscending'
            )
            
            # 3. Format data for plotext
            results = {
                'timestamps': [],
                'in': [],
                'out': []
            }
            
            # Map results to our dictionary
            for res in response.get('MetricDataResults', []):
                if res['Id'] == 'pps_in':
                    results['timestamps'] = [t.strftime("%H:%M") for t in res['Timestamps']]
                    results['in'] = res['Values']
                elif res['Id'] == 'pps_out':
                    results['out'] = res['Values']
                    
            return results
        except Exception as e:
            raise ValueError(f"Error fetching PPS data from CloudWatch: {e}")


def handle_eni_command(args, aws_fetcher, stdout = True):
    current_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if stdout:
	    print(f"{current_time}")
    try:
        eni_info = aws_fetcher.get_eni_information(args.identifier)
        subnet_info = aws_fetcher.get_subnet_information(eni_info['SubnetId'])

        formatted_output = aws_fetcher.format_eni_output(eni_info, subnet_info)
        if stdout:
            print(_yaml_dump(formatted_output, sort_keys=False))
        else:
            return formatted_output
    except Exception as e:
        if stdout:
            print(e)
            return
        else:
            return e

def handle_subnet_command(args, aws_fetcher, stdout = True):
    current_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if stdout:
	    print(f"{current_time}")
    try:
        subnet_info = aws_fetcher.get_subnet_information_by_id_or_cidr(args.identifier)

        formatted_output = aws_fetcher.format_subnet_output(subnet_info)
        if stdout:
            print(_yaml_dump(formatted_output, sort_keys=False))
        else:
            return formatted_output
    except Exception as e:
        if stdout:
            print(e)
            return
        else:
            return e

def handle_rt_command(args, aws_fetcher, stdout = True):
    if not stdout and not args.filter_ip:
        raise ValueError("filter_ip is mandatory when using aws_tool as a module (rt command).")
    if args.filter_ip == "all":
        args.filter_ip = None
    current_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if stdout:
	    print(f"{current_time}")
    try:
        if args.identifier.startswith("tgw-rtb-"):
            tgw_rt_info = aws_fetcher.get_tgw_route_table_information_by_id(args.identifier)
            formatted_output = aws_fetcher.format_tgw_rt_output(tgw_rt_info, args.filter_ip)
        elif args.identifier.startswith("lgw-rtb-"):
            lgw_rt_info = aws_fetcher.get_lgw_route_table_information_by_id(args.identifier)
            formatted_output = aws_fetcher.format_lgw_rt_output(lgw_rt_info, args.filter_ip)
        else:
            route_table_info = aws_fetcher.get_route_table_information_by_id(args.identifier)
            formatted_output = aws_fetcher.format_rt_output(route_table_info, args.filter_ip)
        if stdout:
            print(_yaml_dump(formatted_output, sort_keys=False))
        else:
            return formatted_output
    except Exception as e:
        if stdout:
            print(e)
            return
        else:
            return e

def handle_pl_command(args, aws_fetcher, stdout = True):
    current_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if stdout:
	    print(f"{current_time}")
    try:
        cidr_blocks = aws_fetcher.get_managed_prefix_list_entries(args.prefix_list_id)
        output = {
            "Prefix List ID": args.prefix_list_id,
            "CIDR Blocks": cidr_blocks
        }
        if stdout:
            print(_yaml_dump(output, sort_keys=False))
        else:
            return output
    except Exception as e:
        if stdout:
            print(f"Error: {e}")
            return
        else:
            return f"Error: {e}"

def handle_vpc_command(args, aws_fetcher, stdout = True):
    current_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if stdout:
	    print(f"{current_time}")
    try:
        vpc_info = aws_fetcher.get_vpc_information(args.vpc_id)
        if stdout:
            print(_yaml_dump(vpc_info, sort_keys=False))
        else:
            return vpc_info
    except Exception as e:
        if stdout:
            print(e)
            return
        else:
            return e

def handle_sg_command(args, aws_fetcher, stdout = True):
    current_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if stdout:
	    print(f"{current_time}")
    try:
        sg_info = aws_fetcher.get_security_group_information(args.sg_id)
        formatted_output = aws_fetcher.format_sg_output(sg_info)
        if stdout:
            print(_yaml_dump(formatted_output, sort_keys=False))
        else:
            return formatted_output
    except Exception as e:
        if stdout:
            print(e)
            return
        else:
            return e

def handle_ec2_command(args, aws_fetcher, stdout = True):
    current_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if stdout:
	    print(f"{current_time}")
    try:
        ec2_info = aws_fetcher.get_instance_information(args.instance_id)
        if stdout:
            print(_yaml_dump(ec2_info, sort_keys=False))
        else:
            return ec2_info
    except Exception as e:
        if stdout:
            print(e)
            return
        else:
            return e

def handle_acl_command(args, aws_fetcher, stdout = True):
    current_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if stdout:
	    print(f"{current_time}")
    try:
        acl_info = aws_fetcher.get_network_acl_information(args.acl_id)
        formatted_output = aws_fetcher.format_acl_output(acl_info)
        if stdout:
            print(_yaml_dump(formatted_output, sort_keys=False))
        else:
            return formatted_output
    except Exception as e:
        if stdout:
            print(e)
            return
        else:
            return e


def handle_tgw_command(args, aws_fetcher, stdout = True):
    current_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if stdout:
	    print(f"{current_time}")
    try:
        tgw_info = aws_fetcher.get_transit_gateway_information(args.tgw_id)
        if stdout:
            print(_yaml_dump(tgw_info, sort_keys=False))
        else:
            return tgw_info
    except Exception as e:
        if stdout:
            print(e)
            return
        else:
            return e

def handle_dxgw_command(args, aws_fetcher, stdout = True):
    current_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if stdout:
	    print(f"{current_time}")
    try:
        dxgw_info = aws_fetcher.get_dxgw_information(args.dxgw_id)
        formatted_output = aws_fetcher.format_dxgw_output(dxgw_info)
        if stdout:
            print(_yaml_dump(formatted_output, sort_keys=False))
        else:
            return formatted_output
    except Exception as e:
        if stdout:
            print(e)
            return
        else:
            return e

def handle_dxvif_command(args, aws_fetcher, stdout = True):
    current_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if stdout:
	    print(f"{current_time}")
    try:
        dxvif_info = aws_fetcher.get_dxvif_information(args.dxvif_id)
        formatted_output = aws_fetcher.format_dxvif_output(dxvif_info)
        if stdout:
            print(_yaml_dump(formatted_output, sort_keys=False))
        else:
            return formatted_output
    except Exception as e:
        if stdout:
            print(e)
            return
        else:
            return e

def handle_dxcon_command(args, aws_fetcher, stdout = True):
    current_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if stdout:
	    print(f"{current_time}")
    try:
        dxcon_info = aws_fetcher.get_dxcon_information(args.dxcon_id)
        formatted_output = aws_fetcher.format_dxcon_output(dxcon_info)
        if stdout:
            print(_yaml_dump(formatted_output, sort_keys=False))
        else:
            return formatted_output
    except Exception as e:
        if stdout:
            print(e)
            return
        else:
            return e

def handle_flowlog_command(args, aws_fetcher, stdout = True):
    follow = getattr(args, 'follow', False)
    interval = getattr(args, 'interval', 5)
    next_token = None
    
    while True:
        current_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        if stdout and not follow:
            print(f"{current_time}")
            
        try:
            flowlog_info, next_token = aws_fetcher.get_flowlog_information(args.fl_id, args.eni_id, args.hours, args.filter, next_token=next_token)
            if flowlog_info:
                if stdout:
                    print(_yaml_dump(flowlog_info, sort_keys=False))
                elif not follow:
                    return flowlog_info
                else:
                    pass
            
            if not follow:
                break
                
            time.sleep(interval)
            
        except Exception as e:
            if stdout:
                print(e)
            if not follow:
                return e if not stdout else None
            time.sleep(interval)

def handle_find_command(args, aws_fetcher=None, stdout = True):
    result = AwsFinder(args.resource_id, args.profile, args.region, getattr(args, 'verify_ssl', True))
    if stdout:
        print(result)
    else:
        return result

def handle_inspect_command(args, aws_fetcher, stdout=True):
    """Generic inspector that dispatches based on identifier prefix."""
    identifier = args.identifier
    id_lower = identifier.lower().replace("-lists ", "").strip()

    # Create a copy of args to avoid modifying the original
    import copy
    handler_args = copy.copy(args)
    handler_args.identifier = id_lower

    handler = None
    if id_lower.startswith('i-'):
        handler = handle_ec2_command
        handler_args.instance_id = id_lower
    elif id_lower.startswith('vpc-'):
        handler = handle_vpc_command
        handler_args.vpc_id = id_lower
    elif id_lower.startswith('subnet-'):
        handler = handle_subnet_command
        handler_args.identifier = id_lower # Subnet handler uses identifier
    elif id_lower.startswith('eni-'):
        handler = handle_eni_command
        handler_args.identifier = id_lower # ENI handler uses identifier
    elif id_lower.startswith('rtb-') or id_lower.startswith('tgw-rtb-'):
        handler = handle_rt_command
        handler_args.identifier = id_lower
        handler_args.filter_ip = getattr(args, 'filter_ip', None) # RT command expects filter_ip
    elif id_lower.startswith('tgw-'):
        handler = handle_tgw_command
        handler_args.tgw_id = id_lower
    elif id_lower.startswith('sg-'):
        handler = handle_sg_command
        handler_args.sg_id = id_lower
    elif id_lower.startswith('acl-'):
        handler = handle_acl_command
        handler_args.acl_id = id_lower
    elif id_lower.startswith('dxgw-') or (len(id_lower) == 36 and id_lower.count('-') == 4):
        handler = handle_dxgw_command
        handler_args.dxgw_id = id_lower
    elif id_lower.startswith('dxcon-'):
        handler = handle_dxcon_command
        handler_args.dxcon_id = id_lower
    elif id_lower.startswith('dxvif-'):
        handler = handle_dxvif_command
        handler_args.dxvif_id = id_lower
    elif id_lower.startswith('pl-'):
        handler = handle_pl_command
        handler_args.prefix_list_id = id_lower
    if handler:        return handler(handler_args, aws_fetcher, stdout=stdout)
    else:
        msg = f"Unknown identifier type: {identifier}"
        if stdout:
            print(msg)
        return msg

def handle_info_command(args, aws_fetcher=None, stdout=True):
    import json
    try:
        _lazy_init_aws()
        profiles = list(boto3.Session().available_profiles)
        regions = ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "us-gov-east-1", "us-gov-west-1", "ca-central-1", "eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3", "eu-north-1", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-southeast-1", "ap-southeast-2", "ap-south-1", "sa-east-1"]
        info = {"profiles": profiles, "regions": regions}
        if stdout:
            print(json.dumps(info))
        else:
            return info
    except Exception as e:
        if stdout:
            print(json.dumps({"error": str(e)}))
        else:
            return {"error": str(e)}

def handle_inventory_command(args, aws_fetcher, stdout=True):
    import json
    try:
        inventory = aws_fetcher.get_full_inventory()
        if stdout:
            print(json.dumps(inventory))
        else:
            return inventory
    except Exception as e:
        if stdout:
            print(json.dumps({"error": str(e)}))
        else:
            return {"error": str(e)}

def handle_flowlog_toggle_command(args, aws_fetcher, stdout=True):
    """Enable or disable flow logs for an ENI."""
    import json
    eni_id = args.identifier
    action = args.action # 'enable' or 'disable'
    
    try:
        if action == 'enable':
            log_group = f"/aws/connpy/flowlogs/{eni_id}"
            response = aws_fetcher.ec2_client.create_flow_logs(
                ResourceIds=[eni_id],
                ResourceType='NetworkInterface',
                TrafficType='ALL',
                LogDestinationType='cloud-watch-logs',
                LogGroupName=log_group,
                DeliverLogsPermissionArn=args.role_arn if hasattr(args, 'role_arn') and args.role_arn else None
            )
            res = {"status": "success", "message": f"Flow logs enabled for {eni_id}", "details": response}
        else:
            flow_logs = aws_fetcher.ec2_client.describe_flow_logs(
                Filters=[{'Name': 'resource-id', 'Values': [eni_id]}]
            )
            fl_ids = [fl['FlowLogId'] for fl in flow_logs.get('FlowLogs', [])]
            if fl_ids:
                aws_fetcher.ec2_client.delete_flow_logs(FlowLogIds=fl_ids)
                res = {"status": "success", "message": f"Flow logs disabled for {eni_id}"}
            else:
                res = {"status": "error", "message": f"No flow logs found for {eni_id}"}
        
        if stdout:
            print(json.dumps(res))
        return res
    except Exception as e:
        res = {"status": "error", "message": str(e)}
        if stdout:
            print(json.dumps(res))
        return res

def handle_console_command(args, aws_fetcher, connapp, stdout=True):
    import json as _json
    current_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    is_headless = getattr(connapp, 'is_mock', False) if connapp else True
    
    if stdout and not is_headless:
        print(f"{current_time}")
    try:
        # Resolve instance ID
        instance_info = aws_fetcher.get_instance_information(args.identifier)
        instance_id = instance_info['id']

        # Prefer ~/.ssh/id_rsa if it exists
        default_key_path = os.path.expanduser("~/.ssh/id_rsa")
        if os.path.exists(default_key_path) and os.path.exists(default_key_path + ".pub"):
            key_path = default_key_path
            pub_key_path = default_key_path + ".pub"
        else:
            # Fallback: generate temporary key
            key_path = tempfile.NamedTemporaryFile(delete=False).name
            pub_key_path = key_path + ".pub"
            subprocess.run(["ssh-keygen", "-t", "rsa", "-b", "2048", "-f", key_path, "-N", ""], check=True)
            if stdout and not is_headless:
                print(f"Generated temporary key at {key_path}")

        # Push public key to AWS
        send_key_cmd = [
            "aws", "ec2-instance-connect", "send-serial-console-ssh-public-key",
            "--instance-id", instance_id,
            "--serial-port", str(args.port),
            "--ssh-public-key", f"file://{pub_key_path}",
            "--region", args.region,
            "--profile", args.profile
        ]
        if not getattr(args, 'verify_ssl', True):
            send_key_cmd.append("--no-verify-ssl")

        result = subprocess.run(send_key_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            if is_headless:
                print(_json.dumps({"error": f"Failed to send SSH key: {result.stderr.strip()}"}))
            else:
                print("Error sending SSH key:\n", result.stderr)
            sys.exit(1)

        # Connect to AWS serial console
        ssh_user = f"{instance_id}.port{args.port}"
        ssh_host = f"serial-console.ec2-instance-connect.{args.region}.aws"
        
        if is_headless:
            interact_params = {
                "protocol": "ssh",
                "host": ssh_host,
                "user": ssh_user,
                "name": f"console-{instance_id}@aws",
                "base_node": "console@aws",
            }
            # If no base node exists on the server, include key as fallback
            if key_path != default_key_path:
                interact_params["options"] = f"-i {key_path}"
            print(_json.dumps({"__interact__": interact_params}))
            return
            
        if stdout:
            print(f"Connecting to EC2 Serial Console on {ssh_host} as {ssh_user}...")
        if connapp:
            node = connapp.config._getallnodes("console@aws")
            if node:
                device = connapp.config.getitem(node[0])
                device['host'] = ssh_host
                device['user'] = ssh_user
                instance = connapp.node(f"console-{instance_id}@aws", **device, config=connapp.config)
                instance.interact()
            else:
                subprocess.run(["ssh", "-i", key_path, f"{ssh_user}@{ssh_host}"])
        else:
            subprocess.run(["ssh", "-i", key_path, f"{ssh_user}@{ssh_host}"])

    except Exception as e:
        if is_headless:
            print(_json.dumps({"error": str(e)}))
        elif stdout:
            print(f"Failed to connect to serial console: {e}")
            sys.exit(1)
        else:
            return str(e)



def handle_ssm_command(args, aws_fetcher, connapp, stdout=True):
    import sys
    try:
        instance_info = aws_fetcher.get_instance_information(args.identifier)
        instance_id = instance_info['id']
        
        is_headless = not sys.stdout.isatty()
        
        # 1. If remote (headless), return JSON payload.
        if is_headless:
            import json as _json
            interact_params = {
                "protocol": "ssm",
                "host": instance_id,
                "name": f"ssm-{instance_id}@aws",
                "base_node": "ssm@aws",
                "tags": {"region": args.region, "profile": args.profile}
            }
            print(_json.dumps({"__interact__": interact_params}))
            return

        if stdout:
            print(f"Connecting to EC2 instance {instance_id} via SSM...")

        # 2. If within connpy CLI, use Pexpect (core.node)
        if connapp:
            node = connapp.config._getallnodes("ssm@aws")
            if node:
                device = connapp.config.getitem(node[0]).copy()
            else:
                # If no ssm@aws base node, initialize an empty one
                device = {}
                
            device['host'] = instance_id
            device['protocol'] = "ssm"
            
            # Preserve existing tags (e.g. prompt, console) if any
            existing_tags = device.get('tags', {})
            if not isinstance(existing_tags, dict):
                existing_tags = {}
                
            existing_tags['region'] = args.region
            existing_tags['profile'] = args.profile
            device['tags'] = existing_tags
            
            # Instantiate connpy core and connect
            instance = connapp.node(f"ssm-{instance_id}@aws", **device, config=connapp.config)
            instance.interact()
            
        # 3. Fallback: Ejecucion directa sin connpy
        else:
            import subprocess
            subprocess.run(["aws", "ssm", "start-session", "--target", instance_id, "--region", args.region, "--profile", args.profile])
            
    except Exception as e:
        import sys
        if not sys.stdout.isatty():
            import json as _json
            print(_json.dumps({"error": str(e)}))
        elif stdout:
            print(f"Error: {e}")

def handle_connect_command(args, connapp, stdout=True):
    _lazy_init_k8s()
    ctx = []
    # <--- CHANGE 1: The regex now accepts an optional number after 'p' or 's'.
    # This allows matching with 'mi-dc-p', 'mi-dc-s1', 'mi-dc-p2', etc.
    _ENV_RE = re.compile(r'^([a-zA-Z0-9\-]+)-([sp])(\d*)$', re.IGNORECASE)
    namespaces = []
    
    # <--- CHANGE 2: We improved the 'choose' function to work with lists of
    # strings and also with lists of objects (like k8s pods).
    # Shows name to the user but returns the complete object, simplifying code.
    def choose(list_items, name, action):
        if not list_items:
            return None
        
        # If list contains objects with 'metadata' (like pods), use the name for options.
        if hasattr(list_items[0], 'metadata'):
            choices = [item.metadata.name for item in list_items]
        else:
            choices = list_items

        if connapp:
            from connpy.cli.helpers import choose as cli_choose
            selected_name = cli_choose(connapp, choices, name, action)
        else:
            questions = [inquirer.List(name, message=f"Pick {name} to {action}:", choices=choices, carousel=True)]
            answer = inquirer.prompt(questions)
            selected_name = answer[name] if answer else None

        if selected_name is None:
            return None
        
        # Returns the complete object corresponding to the chosen name.
        if hasattr(list_items[0], 'metadata'):
            for item in list_items:
                if item.metadata.name == selected_name:
                    return item
        
        # If it was a list of strings, return the string.
        return selected_name

    try:
        contexts, current = k8s_config.list_kube_config_contexts()
        if contexts:
            for c in contexts:
                if "name" in c:
                    ctx.append(c["name"])
    except Exception as e:
        if stdout:
            print(f"Error reading kubeconfig: {e}")
            sys.exit(1)
    if not ctx:
        print(f"No contexts found.")
        sys.exit(2)

    env_map = {}
    for name in ctx:
        m = _ENV_RE.match(name)
        if not m:
            continue
        base, role = m.group(1), m.group(2).lower()
        # <--- CHANGE 3: We save the contexts in a list for each role ('p' or 's').
        # Now env_map can have: {'mi-dc': {'p': ['mi-dc-p1', 'mi-dc-p2'], 's': ['mi-dc-s1']}}
        env_map.setdefault(base, {}).setdefault(role, []).append(name)

    # If no contexts match the pattern, use original flow (fallback)
    if not env_map:
        chosen_ctx_name = ctx[0]
        if len(ctx) > 1:
            chosen_ctx_name = choose(ctx, "context", "connect")
        if chosen_ctx_name is None:
            sys.exit(7)
        
        ctx = [chosen_ctx_name] # Update ctx for the rest of the flow to use
        k8s_config.load_kube_config(context=ctx[0])
        v1 = k8s_client.CoreV1Api()
        ns_list = v1.list_namespace()
        for ns in ns_list.items:
            namespaces.append(ns.metadata.name)
        
        filtered_ns = [item for item in namespaces if item.startswith("cs-")]
        if not filtered_ns:
            print("No XRD namespaces found.")
            sys.exit(2)
        
        ns_selected = filtered_ns[0]
        if len(filtered_ns) > 1:
            ns_selected = choose(filtered_ns, "namespace", "connect")
        if ns_selected is None:
            sys.exit(7)
        
        pods = v1.list_namespaced_pod(namespace=ns_selected).items
        if not pods:
            print(f"No pods found in ns: {ns_selected}, cx: {ctx[0]}")
            sys.exit(2)
            
        chosen_pod = pods[0]
        if len(pods) > 1:
            chosen_pod = choose(pods, "pod", "connect")
        if chosen_pod is None:
            sys.exit(7)
        pod_name = chosen_pod.metadata.name # Get the name of the pod object
        
        if connapp:
            node = connapp.config._getallnodes("connect@aws")
            if node:
                device = connapp.config.getitem(node[0])
                device["options"] = f"--context={ctx[0]} -n {ns_selected}"
                device["host"] = pod_name
                if args.local:
                    device["user"] = "@xrd"
                    device["password"] = ["@xrd"]
                instance = connapp.node(pod_name, **device, config=connapp.config)
                instance.interact()
            else:
                command = f"kubectl --context={ctx[0]} exec -it -n {ns_selected} {pod_name} -- /pkg/bin/xr_cli.sh"
                subprocess.run(shlex.split(command))
        else:
            command = f"kubectl --context={ctx[0]} exec -it -n {ns_selected} {pod_name} -- /pkg/bin/xr_cli.sh"
            subprocess.run(shlex.split(command))
        return

    # --- START OF NEW IMPROVED FLOW ---
    
    env_list = sorted(env_map.keys())
    chosen_env = env_list[0]
    if len(env_list) > 1:
        chosen_env = choose(env_list, "environment", "connect")
    if chosen_env is None:
        sys.exit(7)

    # <--- CHANGE 4: Search namespaces in ALL clusters of the chosen environment.
    ns_by_context = {}
    all_ns = set()
    # Create a unique list of all contexts (p1, p2, s1...)
    contexts_to_scan = env_map[chosen_env].get("p", []) + env_map[chosen_env].get("s", [])

    for ctx_name in contexts_to_scan:
        try:
            k8s_config.load_kube_config(context=ctx_name)
            v1 = k8s_client.CoreV1Api()
            ns_list = v1.list_namespace()
            # Save namespaces for each specific context
            context_namespaces = {ns.metadata.name for ns in ns_list.items}
            ns_by_context[ctx_name] = context_namespaces
            all_ns.update(context_namespaces) # Add to the total set of namespaces
        except Exception as e:
            if stdout:
                print(f"Warning: Error listing namespaces for {ctx_name}: {e}")

    filtered_ns = [n for n in sorted(all_ns) if n.startswith("cs-")]
    if not filtered_ns:
        print(f"No XRD namespaces found across all clusters for environment '{chosen_env}'.")
        sys.exit(2)
    
    ns_selected = filtered_ns[0]
    if len(filtered_ns) > 1:
        ns_selected = choose(filtered_ns, "namespace", "connect")
    if ns_selected is None:
        sys.exit(7)

    # <--- CHANGE 5: Determine in which context(s) the namespace exists and ask if there is more than one.
    # We no longer think about 'roles' (p/s) but specific contexts ('mi-dc-p1', 'mi-dc-s2').
    present_in_contexts = [ctx for ctx, ns_set in ns_by_context.items() if ns_selected in ns_set]
    
    if not present_in_contexts:
        print(f"Namespace {ns_selected} was not found in any available context for {chosen_env}.")
        sys.exit(2)

    selected_ctx = present_in_contexts[0]
    if len(present_in_contexts) > 1:
        # If namespace exists in 'mi-dc-p1' and 'mi-dc-s2', user chooses which to connect.
        selected_ctx = choose(present_in_contexts, "context", f"for namespace {ns_selected}")
    if selected_ctx is None:
        sys.exit(7)

    # Load final context and choose pod
    k8s_config.load_kube_config(context=selected_ctx)
    v1 = k8s_client.CoreV1Api()
    pods = v1.list_namespaced_pod(namespace=ns_selected).items
    if not pods:
        print(f"No pods found in ns: {ns_selected}, cx: {selected_ctx}")
        sys.exit(2)
        
    chosen_pod = pods[0]
    if len(pods) > 1:
        chosen_pod = choose(pods, "pod", "connect")
    if chosen_pod is None:
        sys.exit(7)
    pod_name = chosen_pod.metadata.name

    is_headless = not sys.stdout.isatty()
    if is_headless:
        import json as _json
        interact_params = {
            "protocol": "kubectl",
            "host": pod_name,
            "base_node": "connect@aws",
            "options": f"--context={selected_ctx} -n {ns_selected}",
            "tags": {"kube_command": "/pkg/bin/xr_cli.sh"}
        }
        if getattr(args, "local", False):
            interact_params["user"] = "@xrd"
            interact_params["password"] = ["@xrd"]
        print(_json.dumps({"__interact__": interact_params}))
        return

    if connapp:
        node = connapp.config._getallnodes("connect@aws")
        if node:
            device = connapp.config.getitem(node[0])
            device["options"] = f"--context={selected_ctx} -n {ns_selected}"
            device["host"] = pod_name
            if getattr(args, "local", False):
                device["user"] = "@xrd"
                device["password"] = ["@xrd"]
            instance = connapp.node(pod_name, **device, config=connapp.config)
            instance.interact()
        else:
            command = f"kubectl --context={selected_ctx} exec -it -n {ns_selected} {pod_name} -- /pkg/bin/xr_cli.sh"
            subprocess.run(shlex.split(command))
    else:
        command = f"kubectl --context={selected_ctx} exec -it -n {ns_selected} {pod_name} -- /pkg/bin/xr_cli.sh"
        subprocess.run(shlex.split(command))

def handle_bw_command(args, aws_fetcher, stdout=True):
    _lazy_init_plot()
    current_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    if not args.instance_id:
        if stdout:
            print(f"Fetching Throughput list ({args.unit})... {current_time}")
        try:
            # Pass the unit to the fetcher so the list comes pre-calculated
            bw_list = aws_fetcher.get_all_instances_bw(unit=args.unit)
            
            if stdout:
                # The header now injects the chosen unit
                u = args.unit.upper()
                header = f"{'Instance ID':<20} | {f'In ({u})':<10} | {f'Out ({u})':<10} | {f'Total ({u})':<10} | {'Name'}"
                print("\n" + header)
                print("-" * 125)
                for r in bw_list:
                    # Use .2f to maintain precision in KB or MB
                    print(f"{r['id']:<20} | {r['in']:<10.2f} | {r['out']:<10.2f} | {r['total']:<10.2f} | {r['name']}")
            else:
                return bw_list
        except Exception as e:
            if stdout:
                print(f"Error listing Throughput: {e}")
                sys.exit(1)
            return str(e)

    else:
        try:
            instance_info = aws_fetcher.get_instance_information(args.instance_id)
            target_id = instance_info['id']
            target_name = instance_info['name']
            
            if getattr(args, 'json_output', False):
                import json
                print(json.dumps(aws_fetcher.get_instance_bw(target_id, args.time, unit=args.unit)))
                return
            elif not stdout:
                return aws_fetcher.get_instance_bw(target_id, args.time, unit=args.unit)

            if stdout:
                print(f"Starting live BW monitor for {target_name} ({target_id})...")
                print("Press Ctrl+C to stop.")
                
            while True:
                # Fetcher should convert from Bytes to Mbps here
                data = aws_fetcher.get_instance_bw(target_id, args.time, unit=args.unit)
                
                if not data['in']:
                    print(f"Waiting for CloudWatch cycle... {datetime.datetime.now().strftime('%H:%M:%S')}")
                else:
                    x_indices = list(range(len(data['in'])))
                    
                    plt.clf()
                    plt.theme('dark')
                    plt.plot(x_indices, data['in'], label='BW In (Mbps)', color='blue')
                    plt.plot(x_indices, data['out'], label='BW Out (Mbps)', color='orange')
                    
                    # Formatting X Axis
                    step = max(1, len(data['timestamps']) // 10)
                    plt.xticks(x_indices[::step], data['timestamps'][::step])
                    
                    plt.title(f"Bandwidth Monitor: {target_id} | {target_name}")
                    plt.ylabel(f"Throughput ({args.unit})")
                    plt.xlabel("Time (UTC) - Offset 5m")
                    plt.show()
                
                time.sleep(60)
                
        except KeyboardInterrupt:
            if stdout:
                print("\nMonitoring stopped by user.")
        except Exception as e:
            if stdout:
                print(f"Failed to monitor BW: {e}")
                sys.exit(1)
            else:
                return str(e)

def handle_pps_command(args, aws_fetcher, stdout=True):
    _lazy_init_plot()
    current_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    if not args.instance_id:
        if stdout:
            print(f"Fetching PPS list... {current_time}")
        try:
            pps_list = aws_fetcher.get_all_instances_pps()
            if stdout:
                header = f"{'Instance ID':<20} | {'In':<10} | {'Out':<10} | {'Total':<10} | {'Name'}"
                print("\n" + header)
                print("-" * 115)
                for r in pps_list:
                    print(f"{r['id']:<20} | {r['in']:<10.1f} | {r['out']:<10.1f} | {r['total']:<10.1f} | {r['name']}")
            else:
                return pps_list
        except Exception as e:
            if stdout:
                print(f"Error listing PPS: {e}")
                sys.exit(1)
            return str(e)

    else:
        try:
            instance_info = aws_fetcher.get_instance_information(args.instance_id)
            target_id = instance_info['id']
            target_name = instance_info['name']
            
            if getattr(args, 'json_output', False):
                import json
                print(json.dumps(aws_fetcher.get_instance_pps(target_id, args.time)))
                return
            elif not stdout:
                return aws_fetcher.get_instance_pps(target_id, args.time)

            if stdout:
                print(f"Starting live PPS monitor for {target_name} ({target_id})...")
                print("Press Ctrl+C to stop.")
                
            while True:
                data = aws_fetcher.get_instance_pps(target_id, args.time)
                
                if not data['in']:
                    print(f"Waiting for CloudWatch cycle... {datetime.datetime.now().strftime('%H:%M:%S')}")
                else:
                    x_indices = list(range(len(data['in'])))
                    
                    plt.clf()
                    plt.theme('dark')
                    plt.plot(x_indices, data['in'], label='PPS In', color='blue')
                    plt.plot(x_indices, data['out'], label='PPS Out', color='orange')
                    
                    # Formatting X Axis
                    step = max(1, len(data['timestamps']) // 10)
                    plt.xticks(x_indices[::step], data['timestamps'][::step])
                    
                    plt.title(f"PPS Monitor: {target_id} | {target_name}")
                    plt.ylabel("Packets Per Second")
                    plt.xlabel("Time (UTC) - Offset 5m")
                    plt.show()
                
                time.sleep(60)
                
        except KeyboardInterrupt:
            if stdout:
                print("\nMonitoring stopped by user.")
        except Exception as e:
            if stdout:
                print(f"Failed to monitor PPS: {e}")
                sys.exit(1)
            else:
                return str(e)

def handle_open_command(args, aws_fetcher, stdout=True):
    import urllib.parse
    import requests
    import subprocess
    import json as _json

    if not getattr(args, 'profile', None) or not getattr(args, 'region', None):
        msg = "Error: Both --profile and --region are required for the open command."
        if stdout:
            print(msg)
        return msg

    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        creds = session.get_credentials()
        if not creds:
            raise ValueError(f"No credentials found for profile '{args.profile}'")
        
        creds = creds.get_frozen_credentials()
        
        session_data = {
            "sessionId": creds.access_key,
            "sessionKey": creds.secret_key
        }
        if creds.token:
            session_data["sessionToken"] = creds.token
            
        session_json = _json.dumps(session_data)
        
        token_url = f"https://signin.aws.amazon.com/federation?Action=getSigninToken&SessionType=json&Session={urllib.parse.quote(session_json)}"
        r = requests.get(token_url)
        if r.status_code != 200:
            raise ValueError(f"Failed to get SigninToken from AWS: {r.text}")
        signin_token = r.json().get("SigninToken")
        if not signin_token:
            raise ValueError(f"No SigninToken in AWS response: {r.text}")
        
        destination = f"https://{args.region}.console.aws.amazon.com/console/home?region={args.region}"
        console_url = f"https://signin.aws.amazon.com/federation?Action=login&Issuer=connpy&Destination={urllib.parse.quote(destination)}&SigninToken={signin_token}"
        
        granted_uri = f"ext+granted-containers:name={urllib.parse.quote(args.profile)}&url={urllib.parse.quote(console_url)}"
        
        if stdout:
            print(f"Opening console for profile '{args.profile}' in container via Firefox extension...")
            
        import webbrowser
        webbrowser.open(granted_uri)
        return "Console opened successfully."
    except Exception as e:
        msg = f"Error opening console in container: {e}"
        if stdout:
            print(msg)
        return msg

class Parser:
    def __init__(self):
        #build parser
        # Set defaults from environment variables if available
        default_region = os.getenv('AWS_REGION')
        default_profile = os.getenv('AWS_PROFILE')
        self.parser = argparse.ArgumentParser(prog="awspy", description='Fetch AWS networking information.')
        self.description = 'Fetch AWS networking information'
        self.parser.add_argument('-r', '--region', help='AWS region', default=default_region)
        self.parser.add_argument('-p', '--profile', help='AWS profile', default=default_profile)
        self.parser.add_argument('--no-verify-ssl', action='store_false', dest='verify_ssl', 
                                                help='Disable SSL certificate verification')

        subparsers = self.parser.add_subparsers(title='Commands', dest='command', metavar="")

        # ENI subparser
        parser_eni = subparsers.add_parser('eni', help='Fetch ENI information')
        parser_eni.add_argument('identifier', help='ENI identifier (e.g., IP address, ENI ID)')
        parser_eni.set_defaults(func=handle_eni_command)

        # Subnet subparser
        parser_subnet = subparsers.add_parser('subnet', help='Fetch Subnet information')
        parser_subnet.add_argument('identifier', help='Subnet identifier (e.g., CIDR, Subnet ID)')
        parser_subnet.set_defaults(func=handle_subnet_command)

        # Route Table subparser
        parser_rt = subparsers.add_parser('rt', help='Fetch Route Table information')
        parser_rt.add_argument('identifier', help='Route Table ID')
        parser_rt.add_argument('filter_ip', nargs='?', help='Optional IP/Subnet for route filtering')
        parser_rt.set_defaults(func=handle_rt_command)

        # PL (Prefix List) subparser
        parser_pl = subparsers.add_parser('pl', help='Fetch Prefix List CIDRs')
        parser_pl.add_argument('prefix_list_id', help='Prefix List ID')
        parser_pl.set_defaults(func=handle_pl_command)

        # VPC subparser
        parser_vpc = subparsers.add_parser('vpc', help='Fetch VPC information')
        parser_vpc.add_argument('vpc_id', help='VPC ID')
        parser_vpc.set_defaults(func=handle_vpc_command)

        # SG (Security Group) subparser
        parser_sg = subparsers.add_parser('sg', help='Fetch Security Group information')
        parser_sg.add_argument('sg_id', help='Security Group ID')
        parser_sg.set_defaults(func=handle_sg_command)

        # EC2 subparser
        parser_ec2 = subparsers.add_parser('ec2', help='Fetch EC2 instance information')
        parser_ec2.add_argument('instance_id', help='EC2 instance ID or Name')
        parser_ec2.set_defaults(func=handle_ec2_command)

        # ACL (Network ACL) subparser
        parser_acl = subparsers.add_parser('acl', help='Fetch Network ACL information')
        parser_acl.add_argument('acl_id', help='Network ACL ID')
        parser_acl.set_defaults(func=handle_acl_command)

        # TGW subparser
        parser_tgw = subparsers.add_parser('tgw', help='Fetch Transit Gateway information')
        parser_tgw.add_argument('tgw_id', help='Transit Gateway ID or Name')
        parser_tgw.set_defaults(func=handle_tgw_command)

        # DXGW subparser
        parser_dxgw = subparsers.add_parser('dxgw', help='Fetch Direct Connect Gateway information')
        parser_dxgw.add_argument('dxgw_id', help='Direct Connect Gateway ID')
        parser_dxgw.set_defaults(func=handle_dxgw_command)

        # dx-vif subparser
        parser_dxgw = subparsers.add_parser('vif', help='Fetch Direct Connect Gateway VIF information')
        parser_dxgw.add_argument('dxvif_id', help='Direct Connect Virtual Interface ID')
        parser_dxgw.set_defaults(func=handle_dxvif_command)

        # dx-con subparser
        parser_dxgw = subparsers.add_parser('dxcon', help='Fetch Direct Connect Gateway Connection information')
        parser_dxgw.add_argument('dxcon_id', help='Direct Connect Connection ID')
        parser_dxgw.set_defaults(func=handle_dxcon_command)

        # flowlog subparser
        parser_flowlog = subparsers.add_parser('flowlog', help='Fetch Flowlogs for specific ENI')
        parser_flowlog.add_argument('fl_id', help='FlowLog ID')
        parser_flowlog.add_argument('eni_id', help='ENI ID')
        parser_flowlog.set_defaults(func=handle_flowlog_command)
        parser_flowlog.add_argument('--hours', type=int, default=1, help='Number of hours to capture (default: 1)')
        parser_flowlog.add_argument('--filter', type=str, default=None, help='Optional filter for flow logs')
        parser_flowlog.add_argument('--follow', action='store_true', help='Stream flow logs in real-time')
        parser_flowlog.add_argument('--interval', type=int, default=5, help='Polling interval in seconds for stream (default: 5)')

        # Find subparser
        parser_find = subparsers.add_parser('find', help='Find resource location')
        parser_find.add_argument('resource_id', help='Resource ID')
        parser_find.set_defaults(func=handle_find_command)
        
        # Console subparser
        parser_console = subparsers.add_parser('console', help='Connect to EC2 serial console')
        parser_console.add_argument('identifier', help='Instance ID or Name tag')
        parser_console.add_argument('--port', type=int, default=0, help='Serial port number (default: 0)')
        parser_console.add_argument('--user', default='ec2-user', help='SSH username (default: ec2-user)')
        parser_console.set_defaults(func=handle_console_command)


        # SSM subparser
        parser_ssm = subparsers.add_parser('ssm', help='Connect to EC2 via SSM')
        parser_ssm.add_argument('identifier', help='Instance ID or Name tag')
        parser_ssm.set_defaults(func=handle_ssm_command)

        # Connect subparser
        parser_connect = subparsers.add_parser('connect', help='Connect to XRD vrouter')
        parser_connect.add_argument(
            "-l", "--local",
            action="store_true",
            dest="local",
            default=False,
            help=argparse.SUPPRESS
                )
        parser_connect.set_defaults(func=handle_connect_command)

        # Open subparser
        parser_open = subparsers.add_parser('open', help='Open AWS Console in Firefox Multi-Account Containers via assume')
        parser_open.set_defaults(func=handle_open_command)

        # PPS parser
        parser_pps = subparsers.add_parser('pps', help='Monitor Packets Per Second (PPS) performance')
        parser_pps.add_argument('-i', '--instance-id', help='Instance ID or Name Tag to graph (ASCII top mode)')
        parser_pps.add_argument('-t', '--time', type=int, default=1, help='Hours to look back for the graph')
        parser_pps.set_defaults(func=handle_pps_command)

        # Throughput (Bandwidth) parser
        parser_bw = subparsers.add_parser('bw', aliases=['throughput'], help='Monitor Throughput/Bandwidth performance')
        parser_bw.add_argument('-i', '--instance-id', help='Instance ID or Name Tag to graph (ASCII top mode)')
        parser_bw.add_argument('-t', '--time', type=int, default=1, help='Hours to look back for the graph')
        # You can add an optional unit if your scripts support it (bps, kbps, mbps)
        parser_bw.add_argument('-u', '--unit', choices=['bps', 'kbps', 'mbps', 'gbps'], default='mbps', help='Unit for the graph (default: mbps)')
        parser_bw.set_defaults(func=handle_bw_command)

def format_aws_error(e):
    """Format technical AWS errors into clean, readable messages."""
    error_str = str(e)
    
    # Handle Boto3 ClientError structure if possible
    if hasattr(e, 'response') and 'Error' in e.response:
        code = e.response['Error'].get('Code', 'UnknownError')
        message = e.response['Error'].get('Message', error_str)
        
        # Prettify common codes
        if 'NotFound' in code:
            return f"Resource NOT FOUND: {message}"
        if 'AccessDenied' in code or 'Forbidden' in code:
            return f"ACCESS DENIED: {message}"
        if 'ValidationError' in code:
            return f"VALIDATION ERROR: {message}"
            
        return f"{code}: {message}"
    
    # Fallback for generic errors: strip the common "An error occurred..." boilerplate
    import re
    clean_msg = re.sub(r'An error occurred \([^)]+\) when calling the [^ ]+ operation: ', '', error_str)
    return clean_msg

def _fzf_match(value, options, name="Option"):
    if not value or value in options:
        return value
        
    def score_match(query, candidate):
        query = query.lower()
        candidate = candidate.lower()
        
        if query == candidate:
            return 1000
            
        parts = candidate.split('-')
        acronym = "".join(p[0] for p in parts if p)
        if query == acronym:
            return 500
            
        import re
        pattern = ".*".join(re.escape(c) for c in query)
        if not re.search(pattern, candidate):
            return 0
            
        score = 100
        idx = 0
        match_initials = 0
        for char in query:
            next_idx = candidate.find(char, idx)
            if next_idx == -1:
                break
            if next_idx == 0 or candidate[next_idx-1] == '-':
                match_initials += 1
            idx = next_idx + 1
            
        score += match_initials * 10
        score -= len(candidate)
        return score

    scored_options = [(opt, score_match(value, opt)) for opt in options]
    matches = [(opt, score) for opt, score in scored_options if score > 0]
    
    if not matches:
        return value
        
    matches.sort(key=lambda x: x[1], reverse=True)
    
    top_score = matches[0][1]
    best_matches = [opt for opt, score in matches if score == top_score]
    
    if len(best_matches) == 1:
        return best_matches[0]
    else:
        raise ValueError(f"Ambiguous {name} '{value}'. Best matches: {', '.join(best_matches)}")

def _resolve_args(args):
    _lazy_init_aws()
    try:
        profiles = list(boto3.Session().available_profiles)
    except:
        profiles = []
    try:
        regions = list(boto3.Session().get_available_regions('ec2'))
    except:
        regions = ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]

    if hasattr(args, 'region') and args.region:
        args.region = _fzf_match(args.region, regions, "region")
    if hasattr(args, 'profile') and args.profile:
        args.profile = _fzf_match(args.profile, profiles, "profile")


def _aws_tool_handler(ai_instance, command, identifier=None, profile=None, region=None, filter_ip=None, **kwargs):
    """AWS tool handler for the AI system. Called by ai.py dispatch."""
    import json as _json
    if command == 'rt' and not filter_ip:
        return "Error: 'filter_ip' is MANDATORY for route table queries. Provide an IP or subnet to filter (use 'all' for full table)."

    try:
        class Args:
            def __init__(self, **entries): self.__dict__.update(entries)
        p = profile
        r = region
        if command != 'find' and not r:
             r = os.getenv('AWS_REGION') or ai_instance.config.config.get("aws", {}).get("region") or "us-east-1"
        
        try:
            _lazy_init_aws()
            try:
                profiles = list(boto3.Session().available_profiles)
            except:
                profiles = []
            try:
                regions = list(boto3.Session().get_available_regions('ec2'))
            except:
                regions = ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]
            if p: p = _fzf_match(p, profiles, "profile")
            if r: r = _fzf_match(r, regions, "region")
        except ValueError as e:
            return f"Error: {e}"

        
        args = Args(command=command, identifier=identifier, resource_id=identifier,
                    vpc_id=identifier, sg_id=identifier, instance_id=identifier,
                    acl_id=identifier, tgw_id=identifier, dxgw_id=identifier,
                    dxvif_id=identifier, dxcon_id=identifier, prefix_list_id=identifier,
                    filter_ip=filter_ip, profile=p, region=r, verify_ssl=True)
        if command == 'find':
            fetcher = None
        else:
            if not p:
                p = os.getenv('AWS_PROFILE') or ai_instance.config.config.get("aws", {}).get("profile")
            if not r:
                r = os.getenv('AWS_REGION') or ai_instance.config.config.get("aws", {}).get("region")
            
            if not p or not r:
                return "Error: Both 'profile' and 'region' must be specified for this command. If you don't know them, use the 'find' command first to locate the resource."
            
            args.profile = p
            args.region = r
            fetcher = AwsFetcher(profile=p, region=r)
        handlers = {
            "eni": handle_eni_command, "subnet": handle_subnet_command,
            "rt": handle_rt_command, "pl": handle_pl_command,
            "vpc": handle_vpc_command, "sg": handle_sg_command,
            "ec2": handle_ec2_command, "acl": handle_acl_command,
            "tgw": handle_tgw_command, "dxgw": handle_dxgw_command,
            "vif": handle_dxvif_command, "dxcon": handle_dxcon_command,
            "find": handle_find_command, "open": handle_open_command
        }
        if command not in handlers:
            return f"Error: Unknown AWS command '{command}'."
        data = handlers[command](args, fetcher, stdout=False)
        return ai_instance._truncate(_json.dumps(data, default=str))
    except Exception as e:
        return f"Error executing AWS command: {format_aws_error(e)}"


def _aws_status_formatter(args):
    """Format status line for AWS tool calls in the AI UI."""
    return f"[bold blue]Engineer: [AWS] {args.get('command', '')} {args.get('identifier', '')}"


def _register_aws_ai_tools(ai_instance):
    """Called by ClassHook.modify on every new ai instance to register AWS tools."""
    tool_definition = {
        "type": "function",
        "function": {
            "name": "aws_tool",
            "description": "Interacts with AWS resources. MANDATORY: Use 'rt' for ALL route tables (VPC, TGW, LGW). If identifier starts with 'tgw-rtb-', use 'rt'. Use 'tgw' ONLY for the Transit Gateway resource itself. Always use 'filter_ip' with 'rt' if an IP is relevant (use 'all' for full table).",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "enum": ["eni", "subnet", "rt", "pl", "vpc", "sg", "ec2", "acl", "tgw", "dxgw", "vif", "dxcon", "find", "open"]},
                    "identifier": {"type": "string", "description": "Resource ID (e.g. eni-..., subnet-..., tgw-rtb-...)."},
                    "profile": {"type": "string"},
                    "region": {"type": "string"},
                    "filter_ip": {"type": "string", "description": "IP/Subnet to filter results in 'rt' or 'tgw' commands."}
                },
                "required": ["command", "identifier"]
            }
        }
    }

    ai_instance.register_ai_tool(
        tool_definition=tool_definition,
        handler=_aws_tool_handler,
        target="engineer",
        engineer_prompt="- AWS Cloud Auditing: Use 'aws_tool' to query ENIs, VPCs, Route Tables (VPC/TGW), Security Groups, ACLs, Direct Connect resources. MANDATORY: Use 'filter_ip' for route table queries (use 'all' to see full table).",
        architect_prompt="  * Audit AWS: ENIs, VPCs, Route Tables (VPC/TGW), SGs, ACLs, Direct Connect (aws_tool).",
        status_formatter=_aws_status_formatter
    )


class Preload:
    def __init__(self, connapp):

        # Register AWS tools with the AI system
        connapp.ai.modify(_register_aws_ai_tools)

        try:
            @connapp.app.route("/aws_info", methods=["POST"])
            def aws_info():
                try:
                    _lazy_init_aws()
                    profiles = boto3.Session().available_profiles
                    regions = ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]
                    parser = Parser()
                    subparsers_action = next(action for action in parser.parser._actions if isinstance(action, argparse._SubParsersAction))
                    subparsers = [key for key in subparsers_action.choices.keys()]
                    return {"regions": regions, "profiles": profiles, "commands": subparsers}
                except Exception as e:
                    return {"result": format_aws_error(e)}

            @connapp.app.route("/aws_command", methods=["POST"])
            def aws_command():
                try:
                    _lazy_init_flask()
                    data = request.get_json()
                    command = data["command"]
                    fake_args = shlex.split(command)
                    parser = Parser()

                    # Check for help flags in the main parser
                    if '-h' in fake_args or '--help' in fake_args:
                        subparsers_action = next(action for action in parser.parser._actions if isinstance(action, argparse._SubParsersAction))
                        subparsers = [key for key in subparsers_action.choices.keys()]
                        for item in subparsers:
                            if item in fake_args:
                                help_message = subparsers_action.choices[item].format_help()
                                break
                        else:
                            help_message = parser.parser.format_help()
                        return {"result": str(help_message)}

                    args = parser.parser.parse_args(fake_args)
                    warnings.simplefilter('ignore', InsecureRequestWarning)

                    try:
                        _resolve_args(args)
                    except ValueError as e:
                        return {"result": f"Error: {str(e)}"}


                    if args.command == 'find':
                        if hasattr(args, 'func'):
                            result = args.func(args, stdout=False)
                            return {"result": str(result)}
                    else:
                        if not args.region or not args.profile:
                            return {"result": "Both --region and --profile must be specified for this command or use environment variables AWS_REGION and AWS_PROFILE."}
                        aws_fetcher = AwsFetcher(args.profile, args.region, getattr(args, 'verify_ssl', True))
                        if hasattr(args, 'func'):
                            result = args.func(args, aws_fetcher, stdout=False)
                            return result

                except Exception as e:
                    return {"result": format_aws_error(e)}

        except:
            pass

class Entrypoint:
    def __init__(self, args, parser, connapp):
        _lazy_init_aws()
        # Suppress only the single InsecureRequestWarning from urllib3 needed
        warnings.simplefilter('ignore', InsecureRequestWarning)

        # Normalize all possible AWS identifiers to lowercase globally
        id_fields = ['identifier', 'resource_id', 'instance_id', 'vpc_id', 'subnet_id', 'eni_id', 'tgw_id', 'sg_id', 'acl_id', 'dxgw_id', 'dxcon_id', 'dxvif_id', 'eni_id']
        for field in id_fields:
            val = getattr(args, field, None)
            if isinstance(val, str):
                setattr(args, field, val.lower())

        try:
            _resolve_args(args)
        except ValueError as e:
            parser.error(str(e))

        if args.command:
            if args.command == 'find':
                if hasattr(args, 'func'):
                    args.func(args)
            elif args.command == 'connect':
                if hasattr(args, 'func'):
                    args.func(args ,connapp)
            else:
                if not args.region or not args.profile:
                    parser.error("Both --region and --profile must be specified for this command or use environment variables AWS_REGION and AWS_PROFILE.")
                aws_fetcher = AwsFetcher(args.profile, args.region, getattr(args, 'verify_ssl', True))
                if hasattr(args, 'func'):
                    if args.command == 'console' or args.command == 'ssm':
                        args.func(args, aws_fetcher,connapp)
                    else:
                        args.func(args, aws_fetcher)
        else:
            parser.print_help()

def _connpy_tree(info=None):
    """Return a completion tree node for the aws plugin.
    
    This is the new plugin completion API. The main completion engine
    integrates this node directly into the CLI tree under "aws".
    """
    regions = ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]
    try:
        import boto3 as _boto3
        profiles = list(_boto3.Session().available_profiles)
    except Exception:
        profiles = []

    # --- Subcommand-specific state machines ---

    flowlog_dict = {}
    flowlog_dict.update({
        "__exclude_used__": True,
        "--filter": {"*": flowlog_dict},
        "--hours":  {"*": flowlog_dict},
        "*": flowlog_dict,  # absorb positional args (fl_id, eni_id)
    })

    pps_dict = {}
    pps_dict.update({
        "__exclude_used__": True,
        "--instance-id": {"*": pps_dict},
        "--time":         {"*": pps_dict},
        "*": pps_dict,
    })

    bw_dict = {}
    bw_dict.update({
        "__exclude_used__": True,
        "--instance-id": {"*": bw_dict},
        "--time":         {"*": bw_dict},
        "--unit": ["bps", "kbps", "mbps", "gbps"],
        "*": bw_dict,
    })

    console_dict = {}
    console_dict.update({
        "__exclude_used__": True,
        "--port": {"*": console_dict},
        "--user": {"*": console_dict},
        "*": console_dict,
    })

    ssm_dict = {}
    ssm_dict.update({
        "__exclude_used__": True,
        "*": ssm_dict,
    })

    # --- Top-level aws node (global flags + subcommands, self-referential) ---
    # Global flags --profile / --region can appear before the subcommand in any order.
    # "*" absorbs unknown positional words (e.g. the value after --profile).
    # "__exclude_used__" ensures already-typed flags are not re-suggested.
    aws_top = {}
    aws_top.update({
        "__exclude_used__": True,
        "--profile": {"*": aws_top, "__extra__": lambda w: profiles},
        "--region":  {"*": aws_top, "__extra__": lambda w: regions},
        "-p":        {"*": aws_top, "__extra__": lambda w: profiles},
        "-r":        {"*": aws_top, "__extra__": lambda w: regions},
        "--no-verify-ssl": aws_top,   # boolean flag, loops back immediately
        "--help": None,
        # Subcommands
        "find":    None,
        "eni":     None,
        "subnet":  None,
        "rt":      None,
        "pl":      None,
        "vpc":     None,
        "sg":      None,
        "ec2":     None,
        "acl":     None,
        "tgw":     None,
        "dxgw":    None,
        "vif":     None,
        "dxcon":   None,
        "flowlog": flowlog_dict,
        "console": console_dict,
        "ssm":     ssm_dict,
        "connect": {"-l": None, "--local": None},
        "pps":     pps_dict,
        "bw":      bw_dict,
    })
    return aws_top

if __name__ == "__main__":
    parser = Parser()
    args = parser.parser.parse_args()
    Entrypoint(args,parser.parser, None)




