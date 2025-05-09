#!/usr/bin/python3

import argparse
import boto3
from botocore.exceptions import BotoCoreError
import sys
import yaml
import datetime
import ipaddress
import re
import os
import warnings
from urllib3.exceptions import InsecureRequestWarning
from flask import request
import shlex
import subprocess
import tempfile


def AwsFinder(resource_id, profiles = None, regions = None, verify_ssl = True):
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
                find_session = boto3.Session(profile_name=profile, region_name=region)
                find_ec2 = find_session.client('ec2', verify=verify)
                find_dx = find_session.client('directconnect', verify=verify)

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
                except BotoCoreError:
                    # Error in describe_subnets, continue to next region
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
                except BotoCoreError:
                    # Error in describe_subnets, continue to next region
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
        verify = None if verify_ssl else False
        self.session = boto3.Session(profile_name=profile, region_name=region)
        self.ec2_client = self.session.client('ec2', verify=verify)
        self.dx_client = self.session.client('directconnect', verify=verify)
        self.log_client = self.session.client('logs', verify=verify)

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

    def get_flowlog_information(self, fl_id, eni_id, hours, filter_arg):
        try:
            end_time = datetime.datetime.now(datetime.timezone.utc)
            start_time = end_time - datetime.timedelta(hours=hours)
            start_timestamp_ms = int(start_time.timestamp() * 1000)
            end_timestamp_ms = int(end_time.timestamp() * 1000)
            flow_logs = self.ec2_client.describe_flow_logs(FlowLogIds=[fl_id])
            log_group_name = flow_logs['FlowLogs'][0]['LogGroupName'] if flow_logs['FlowLogs'] else None
            streams = self.log_client.describe_log_streams(
                    logGroupName=log_group_name,
                    logStreamNamePrefix=eni_id
                    )
            log_stream_name = streams['logStreams'][0]['logStreamName'] if streams['logStreams'] else None
            flowlog = self.log_client.get_log_events(
                logGroupName=log_group_name,
                logStreamName=log_stream_name,
                startFromHead=True,
                startTime=start_timestamp_ms,
                endTime=end_timestamp_ms
            )
            if filter_arg:
                events = [event for event in flowlog['events'] if filter_arg in event['message']]
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
                    start_time = int(parts[10])
                    action = parts[12]
                    status = parts[13]
                    if not event_time in formatted_messages:
                        formatted_messages[event_time] = []
                    formatted_message = f"{src_ip} {src_port} -> {dst_ip} {dst_port} - Protocol: {protocol_num} - {action} - {status}"
                    formatted_messages[event_time].append(formatted_message)
            return formatted_messages

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

        # Fetch Transit Gateway attachments for the VPC
        tgw_attachments_response = self.ec2_client.describe_transit_gateway_attachments(Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}])
        tgw_attachments = tgw_attachments_response.get('TransitGatewayAttachments', [])

        tgw_associations = []
        for attachment in tgw_attachments:
            if 'Association' in attachment and 'TransitGatewayRouteTableId' in attachment['Association']:
                tgw_associations.append({
                    'tgw': attachment['TransitGatewayId'],
                    'tgw-route-table': attachment['Association']['TransitGatewayRouteTableId']
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

def handle_eni_command(args, aws_fetcher, stdout = True):
    current_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if stdout:
	    print(f"{current_time}")
    try:
        eni_info = aws_fetcher.get_eni_information(args.identifier)
        subnet_info = aws_fetcher.get_subnet_information(eni_info['SubnetId'])

        formatted_output = aws_fetcher.format_eni_output(eni_info, subnet_info)
        if stdout:
            print(yaml.dump(formatted_output, sort_keys=False))
        else:
            return formatted_output
    except Exception as e:
        if stdout:
            print(e)
            sys.exit(1)
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
            print(yaml.dump(formatted_output, sort_keys=False))
        else:
            return formatted_output
    except Exception as e:
        if stdout:
            print(e)
            sys.exit(1)
        else:
            return e

def handle_rt_command(args, aws_fetcher, stdout = True):
    current_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if stdout:
	    print(f"{current_time}")
    try:
        if args.identifier.startswith("tgw-rtb-"):
            tgw_rt_info = aws_fetcher.get_tgw_route_table_information_by_id(args.identifier)
            formatted_output = aws_fetcher.format_tgw_rt_output(tgw_rt_info, args.filter_ip)
        elif args.identifier.startswith("lgw-rtb-"):
            formatted_output = aws_fetcher.get_lgw_route_table_information_by_id(args.identifier)
            # formatted_output = aws_fetcher.format_tgw_rt_output(tgw_rt_info, args.filter_ip)
        else:
            route_table_info = aws_fetcher.get_route_table_information_by_id(args.identifier)
            formatted_output = aws_fetcher.format_rt_output(route_table_info, args.filter_ip)
        if stdout:
            print(yaml.dump(formatted_output, sort_keys=False))
        else:
            return formatted_output
    except Exception as e:
        if stdout:
            print(e)
            sys.exit(1)
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
            print(yaml.dump(output, sort_keys=False))
        else:
            return output
    except Exception as e:
        if stdout:
            print(f"Error: {e}")
            sys.exit(1)
        else:
            return f"Error: {e}"

def handle_vpc_command(args, aws_fetcher, stdout = True):
    current_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if stdout:
	    print(f"{current_time}")
    try:
        vpc_info = aws_fetcher.get_vpc_information(args.vpc_id)
        if stdout:
            print(yaml.dump(vpc_info, sort_keys=False))
        else:
            return vpc_info
    except Exception as e:
        if stdout:
            print(e)
            sys.exit(1)
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
            print(yaml.dump(formatted_output, sort_keys=False))
        else:
            return formatted_output
    except Exception as e:
        if stdout:
            print(e)
            sys.exit(1)
        else:
            return e

def handle_ec2_command(args, aws_fetcher, stdout = True):
    current_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if stdout:
	    print(f"{current_time}")
    try:
        ec2_info = aws_fetcher.get_instance_information(args.instance_id)
        if stdout:
            print(yaml.dump(ec2_info, sort_keys=False))
        else:
            return ec2_info
    except Exception as e:
        if stdout:
            print(e)
            sys.exit(1)
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
            print(yaml.dump(formatted_output, sort_keys=False))
        else:
            return formatted_output
    except Exception as e:
        if stdout:
            print(e)
            sys.exit(1)
        else:
            return e


def handle_tgw_command(args, aws_fetcher, stdout = True):
    current_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if stdout:
	    print(f"{current_time}")
    try:
        tgw_info = aws_fetcher.get_transit_gateway_information(args.tgw_id)
        if stdout:
            print(yaml.dump(tgw_info, sort_keys=False))
        else:
            return tgw_info
    except Exception as e:
        if stdout:
            print(e)
            sys.exit(1)
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
            print(yaml.dump(formatted_output, sort_keys=False))
        else:
            return formatted_output
    except Exception as e:
        if stdout:
            print(e)
            sys.exit(1)
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
            print(yaml.dump(formatted_output, sort_keys=False))
        else:
            return formatted_output
    except Exception as e:
        if stdout:
            print(e)
            sys.exit(1)
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
            print(yaml.dump(formatted_output, sort_keys=False))
        else:
            return formatted_output
    except Exception as e:
        if stdout:
            print(e)
            sys.exit(1)
        else:
            return e

def handle_flowlog_command(args, aws_fetcher, stdout = True):
    current_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if stdout:
	    print(f"{current_time}")
    try:
        flowlog_info = aws_fetcher.get_flowlog_information(args.fl_id, args.eni_id, args.hours, args.filter)
        if stdout:
            print(yaml.dump(flowlog_info, sort_keys=False))
        else:
            return flowlog_info
    except Exception as e:
        if stdout:
            print(e)
            sys.exit(1)
        else:
            return e

def handle_find_command(args, stdout = True):
    result = AwsFinder(args.resource_id, args.profile, args.region, args.verify_ssl)
    if stdout:
        print(result)
    else:
        return result

def handle_console_command(args, aws_fetcher, connapp, stdout=False):
    current_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if stdout:
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
            if stdout:
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
        if not args.verify_ssl:
            send_key_cmd.append("--no-verify-ssl")

        result = subprocess.run(send_key_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print("Error sending SSH key:\n", result.stderr)
            sys.exit(1)

        # Connect to AWS serial console
        ssh_user = f"{instance_id}.port{args.port}"
        ssh_host = f"serial-console.ec2-instance-connect.{args.region}.aws"
        if stdout:
            print(f"Connecting to EC2 Serial Console on {ssh_host} as {ssh_user}...")
        if connapp:
            node = connapp.config._getallnodes("console@aws")
            device = connapp.config.getitem(node[0])
            device['host'] = ssh_host
            device['user'] = ssh_user
            instance = connapp.node("console", **device ,config=connapp.config)
            instance.interact()
        else:
            subprocess.run(["ssh", "-i", key_path, f"{ssh_user}@{ssh_host}"])

    except Exception as e:
        if stdout:
            print(f"Failed to connect to serial console: {e}")
            sys.exit(1)
        else:
            return str(e)

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
        parser_dxgw = subparsers.add_parser('con', help='Fetch Direct Connect Gateway Connection information')
        parser_dxgw.add_argument('dxcon_id', help='Direct Connect Connection ID')
        parser_dxgw.set_defaults(func=handle_dxcon_command)

        # flowlog subparser
        parser_flowlog = subparsers.add_parser('flowlog', help='Fetch Flowlogs for specific ENI')
        parser_flowlog.add_argument('fl_id', help='FlowLog ID')
        parser_flowlog.add_argument('eni_id', help='ENI ID')
        parser_flowlog.set_defaults(func=handle_flowlog_command)
        parser_flowlog.add_argument('--hours', type=int, default=1, help='Number of hours to capture (default: 1)')
        parser_flowlog.add_argument('--filter', type=str, default=None, help='Optional filter for flow logs')

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

class Preload:
    def __init__(self, connapp):

        try:
            @connapp.app.route("/aws_info", methods=["POST"])
            def aws_info():
                try:
                    profiles = boto3.Session().available_profiles
                    regions = ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]
                    parser = Parser()
                    subparsers_action = next(action for action in parser.parser._actions if isinstance(action, argparse._SubParsersAction))
                    subparsers = [key for key in subparsers_action.choices.keys()]
                    return {"regions": regions, "profiles": profiles, "commands": subparsers}
                except Exception as e:
                    return {"result": str(e)}

            @connapp.app.route("/aws_command", methods=["POST"])
            def aws_command():
                try:
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

                    if args.command == 'find':
                        if hasattr(args, 'func'):
                            result = args.func(args, stdout=False)
                            return {"result": str(result)}
                    else:
                        if not args.region or not args.profile:
                            return {"result": "Both --region and --profile must be specified for this command or use environment variables AWS_REGION and AWS_PROFILE."}
                        aws_fetcher = AwsFetcher(args.profile, args.region, args.verify_ssl)
                        if hasattr(args, 'func'):
                            result = args.func(args, aws_fetcher, stdout=False)
                            return result

                except Exception as e:
                    return {"result": str(e)}

        except:
            pass

class Entrypoint:
    def __init__(self, args, parser, connapp):
        # Suppress only the single InsecureRequestWarning from urllib3 needed
        warnings.simplefilter('ignore', InsecureRequestWarning)
        if args.command:
            if args.command == 'find':
                if hasattr(args, 'func'):
                    args.func(args)
            else:
                if not args.region or not args.profile:
                    parser.error("Both --region and --profile must be specified for this command or use environment variables AWS_REGION and AWS_PROFILE.")
                aws_fetcher = AwsFetcher(args.profile, args.region, args.verify_ssl)
                if hasattr(args, 'func'):
                    if args.command == 'console':
                        args.func(args, aws_fetcher,connapp)
                    else:
                        args.func(args, aws_fetcher)
        else:
            parser.print_help()

def _connpy_completion(wordsnumber, words, info = None):
    mandatory_options = ["--profile", "--region"]
    mandatory_options_short = ["--profile", "--region", "-p", "-r"]
    if wordsnumber == 3:
        result = ["--profile", "--region", "--no-verify-ssl", "find", "eni", "subnet", "rt", "pl", "vpc", "sg", "ec2", "acl", "tgw", "dxgw", "vif", "con", "flowlog",  "console", "--help", "--no-verify-ssl"]
    elif wordsnumber == 4:
        if words[1] == "--no-verify-ssl":
            result = ["--profile", "--region", "find", "eni", "subnet", "rt", "pl", "vpc", "sg", "ec2", "acl", "tgw", "dxgw", "vif", "con", "flowlog", "console"]
        elif words[1] in ["-r", "--region"]:
            result = ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]
        elif words[1] in ["-p", "--profile"]:
            result = boto3.Session().available_profiles
        elif words[1] == "flowlog":
            result = ["--filter", "--hours"]
    elif wordsnumber == 5:
        if words[1] in mandatory_options_short:
            result = [item for item in mandatory_options if not any(word in item for word in words[:-1])]
            result.extend(["find", "eni", "subnet", "rt", "pl", "vpc", "sg", "ec2", "acl", "tgw", "dxgw", "vif", "con", "flowlog", "console", "--no-verify-ssl"])
        elif words[2] in ["-r", "--region"]:
            result = ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]
        elif words[2] in ["-p", "--profile"]:
            result = boto3.Session().available_profiles
        elif words[2] == "flowlog":
            result = ["--filter", "--hours"]
    elif wordsnumber == 6:
        if words[2] in mandatory_options_short or words[3] == "--no-verify-ssl":
            result = [item for item in mandatory_options if not any(word in item for word in words[:-1])]
            result.extend(["find", "eni", "subnet", "rt", "pl", "vpc", "sg", "ec2", "acl", "tgw", "dxgw", "vif", "con", "flowlog", "console"])
        elif words[3] in ["-r", "--region"]:
            result = ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]
        elif words[3] in ["-p", "--profile"]:
            result = boto3.Session().available_profiles
        elif words[3] == "flowlog" or (words[1] == "flowlog" and words[2] not in ["--filter"]):
            result = ["--filter", "--hours"]
    elif wordsnumber == 7:
        if words[1] in mandatory_options_short and words[3] in mandatory_options_short:
            result = ["find", "eni", "subnet", "rt", "pl", "vpc", "sg", "ec2", "acl", "tgw", "dxgw", "vif", "con", "flowlog", "console", "--help", "--no-verify-ssl"]
        elif words[4] in ["-r", "--region"]:
            result = ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]
        elif words[4] in ["-p", "--profile"]:
            result = boto3.Session().available_profiles
        elif words[4] == "flowlog" or (words[2] == "flowlog" and words[3] not in ["--filter"]):
            result = ["--filter", "--hours"]
    elif wordsnumber > 7 and ( words[3] == "flowlog" or words[4] == "flowlog" or words[5] == "flowlog" or words[6] == "flowlog"):
        if not words[-2] in ["--filter", "--hours"]:
            result = [item for item in ["--filter", "--hours"] if not any(word in item for word in words[:-1])]
    elif wordsnumber == 8:
        if "--no-verify-ssl" in words:
            if (words[1] in mandatory_options_short or words[2] in mandatory_options_short) and (words[3] in mandatory_options_short or words[4] in mandatory_options):
                result = ["find", "eni", "subnet", "rt", "pl", "vpc", "sg", "ec2", "acl", "tgw", "dxgw", "vif", "con", "flowlog", "console", "--help"]
    return result

if __name__ == "__main__":
    parser = Parser()
    args = parser.parser.parse_args()
    Entrypoint(args,parser.parser, None)
