from pprint import pprint
import requests
import os
import sys
import urllib.parse
import tempfile
import hcl2
import hvac
from rich.console import Console
from rich.table import Table

console = Console()

# Tell the user if they need to upgrade python
print(" ")
if not sys.version_info >= (3, 7):
    print(
        "This script may not work as expected - please upgrade to python 3.7 or greater"
    )

# https://realpython.com/python-command-line-arguments/#the-anatomy-of-python-command-line-arguments
opts = [opt for opt in sys.argv[1:] if opt.startswith("-")]
args = [arg for arg in sys.argv[1:] if not arg.startswith("-")]

# Get Vault token assigned at login via Vault CLI
vault_token_path = os.path.expanduser("~/.vault-token")
with open(vault_token_path, "r") as file:
    vault_user_token = file.read()

# Set variables for Vault API
vault_headers = {"X-Vault-Token": vault_user_token}
vault_params = {"list": "true"}

# Set header for Okta API
okta_headers = {
    "Authorization": "SSWS" + os.environ["OKTA_TOKEN"],
    "Content-Type": "application/json",
    "Accept": "application/json",
}

# If the -path option is used, find all users with access to the provided path
#   1. Create a dictionary of policies and capabilities, organized by path (info_by_path)
#   2. Create a dictionary of Okta groups and users, organized by policy (info_by_policy)
#   3. Associate path with users that can access the path
# Otherwise, print the access available to provided user
if "-path" in opts:
    # 1. Make a dictionary of policies and capabilities organized by path
    #
    # info_by_path
    # { <path> : [{<policy> : {'capabilities' : <capabilities>}},
    #             {<policy> : {'capabilities' : <capabilities>}},
    #             {<policy> : {'capabilities' : <capabilities>}}]
    #
    #   <path> : [{<policy> : {'capabilities' : <capabilities>}},
    #             {<policy> : {'capabilities' : <capabilities>}},] }

    # Get the path provided by the user
    user_provided_path = args[0]
    print("You have provided the path " + user_provided_path)
    # 'secret/data/foo/bar/something'

    # Get list of policies that grant access to user-provided path implicitly
    #   For example, a rule that grants access to
    #       secret/+/foo/*
    #   ...implicitly grants access to the path
    #       secret/+/foo/bar/something
    path_segments = user_provided_path.split("/")
    # ['secret', 'data', 'foo', 'bar', 'something']

    policy_names = []
    possible_paths = ["*", user_provided_path]

    alternate_path_segments = path_segments.copy()

    if path_segments[1] == "data" or path_segments[1] == "metadata":
        alternate_path_segments[1] = "+"
    else:
        alternate_path_segments[1] = "data"
        print(
            "Listing users that may have access to the 'data' path, but not the 'metadata' path..."
        )

    alternate_path = "/".join(alternate_path_segments)
    possible_paths.append(alternate_path)

    last_segment = path_segments[len(path_segments) - 1]

    last_segment_wildcard_handled = False

    for count, segment in reversed(list(enumerate(path_segments))):
        # print('count: ' + str(count))
        # print('segment:' + segment)

        # Don't pop any more segments if you're already at 'secret/+/<something>/*', because 'secret/+/*' is represented by '*' and is already in the possible_paths variable
        if count == 2:
            break

        # Move on to the next segment, if the user provided a path ending in '*'
        # For example, if the user provided 'secret/data/foo/bar/*', the next possible parent path is 'secret/data/foo/*'
        if last_segment == "*" and last_segment_wildcard_handled is not True:
            path_segments.pop()
            alternate_path_segments.pop()
            last_segment_wildcard_handled = True
            continue

        path_segments.pop()
        alternate_path_segments.pop()
        # ['secret','data','foo','bar']
        # ['secret', '+', 'foo', 'bar']

        parent_path = "/".join(path_segments) + "/*"
        alternate_path = "/".join(alternate_path_segments) + "/*"
        print("adding " + parent_path)
        print("adding " + alternate_path)
        # secret/data/foo/bar/*
        # secret/+/foo/bar/*

        possible_paths.extend([parent_path, alternate_path])
        # ['*', 'secret/data/foo/bar/*', 'secret/+/foo/bar/*']

    print(
        "Granting access to any of these paths will grant access to the path you provided:"
    )
    pprint(possible_paths)
    print("")
    print("")

    info_by_path = {}
    info_by_policy = {}

    # List all policies in Vault
    print("Getting all the policies in Vault")

    x = requests.get(
        "https://<VAULT URL>:<PORT>/v1/sys/policies/acl",
        headers=vault_headers,
        params=vault_params,
    )

    all_policies = x.json()["data"]["keys"]
    #   ['<POLICY 1>',
    #  '<POLICY 2>',
    #  '<POLICY 3>',
    #  '<POLICY 4>',
    #  '<POLICY 5>',
    #  '<POLICY 6>',...]

    print("Getting rules the policies apply")

    # Get rules applied by all policies
    for policy in all_policies:
        # Omit root policy - the API describes it with a mostly empty json blob, so the script breaks
        if policy == "root":
            continue

        z = requests.get(
            "https://<VAULT URL>:<PORT>/v1/sys/policy/{}".format(policy),
            headers=vault_headers,
        )

        policy_details = z.json()
        #  {'auth': None,
        #   'data'          : {'name'   :    '<POLICY NAME>',
        #                       'rules' :    'path "secret/+/<SOMEPATH>" {\n'
        #                                    '  capabilities = ["read", "list"]\n'
        #                                    '}\n'
        #                                    '\n'
        #                                    'path "secret/+/<SOMEPATH>" {\n'
        #                                    '  capabilities = ["read", "list"]\n'
        #                                    '}\n',
        #   'lease_duration': 0,
        #   'lease_id'      : '',
        #   'name'          : '<POLICY NAME>',
        #   'renewable'     : False,
        #   'request_id'    : '<REQUEST ID>',
        #   'rules'         : 'path "secret/+/<SOMEPATH>" {\n'
        #                     '  capabilities = ["read", "list"]\n'
        #                     '}\n'
        #                     '\n'
        #                     'path "secret/+/<SOMEPATH>" {\n'
        #                     '  capabilities = ["read", "list"]\n'
        #                     '}\n',
        #  'warnings': None,
        #  'wrap_info': None}

        rules_element = hcl2.loads(policy_details["rules"])
        # {'path': [ {'auth/approle/<SOMEPATH>'              : {'capabilities': ['create','update','delete','list']}},
        #            {'auth/approle/<SOMEPATH>'   : {'capabilities': ['create','update','delete']}}, ]}

        rules = rules_element["path"]
        #       [ {'auth/approle/<SOMETPATH>'              : {'capabilities': ['create','update','delete','list']}},
        #         {'auth/approle/<SOMEPATH>'   : {'capabilities': ['create','update','delete']}},
        #         {'auth/approle/<SOMEPATH>': {'capabilities': ['read']}},
        #         {'auth/approle/<SOMEPATH>': {'capabilities': ['read', 'list']}} ]

        # For each item in each rules list, add path as key to info_by_path dictionary.
        for rule in rules:
            capabilities_by_policy = {}

            # Get path as string
            path_list = list(rule)
            path = path_list[0]

            # Get capabilities granted on that path by this policy
            capabilities = rule[path]
            # {'capabilities': ['create','update','delete','list']}}

            # Add item to <policy> : <capabilities> dictionary for this path
            # Ignore policies that deny access
            if capabilities["capabilities"][0] != "deny":
                capabilities_by_policy[policy] = capabilities

                # TODO: Use setdefault()

                # If path is already in info_by_policy, add <policy> : <capabilities> dictionary to list in value
                # Otherwise add <path> : <policy : capabilities> to info_by_policy
                if path in info_by_path:
                    info_by_path[path].append(capabilities_by_policy)
                else:
                    info_by_path[path] = [capabilities_by_policy]
            # { "secret/+/<SOMEPATH>":
            #       [{ "<POLICY>":
            #           {"capabilities": ["read", "list", "create", "update", "delete"]}}],
            #
            #   "secret/+/<SOMEPATH>":
            #       [{ "<POLICY>":
            #           {"capabilities": ["create", "update", "delete", "read", "list"]}}],
            #
            #   "secret/+/<SOMEPATH>":
            #       [{"<POLICY>":
            #           {"capabilities": ["create", "read", "update", "delete", "list"]}}], }
            elif path in possible_paths:
                print(
                    policy
                    + " policy denies access to this path, because it denies access to "
                    + path
                )
            # {'<POLICY>': {'capabilities': ['create','update','read','delete']}}

    print("Getting Okta groups referenced in Vault config")

    # Get all Okta groups referenced in the Vault config
    a = requests.get(
        "https://<VAULT URL>:<PORT>/v1/auth/okta/groups",
        headers=vault_headers,
        params=vault_params,
    )

    vault_known_groups_response = a.json()
    vault_known_groups = vault_known_groups_response["data"]["keys"]
    #  ['<OKTA GROUP 1>',
    #  '<OKTA GROUP 2>',
    #  '<OKTA GROUP 3>', ... ]

    print("Getting Okta groups in Okta")
    print("")
    print("")

    # Get all groups in Okta
    e = requests.get(
        "https://<YOUR DOMAIN>.okta.com/api/v1/groups",
        headers=okta_headers,
    )

    okta_known_groups_response = e.json()
    #     [{'_links': {'apps': {'href': 'https://<YOUR DOMAIN>.okta.com/api/v1/groups/00gbgo4o4dOOHiMdk357/apps'},
    #              'logo': [{'href': '<SOME URL FOR LOGO>',
    #                        'name': 'medium',
    #                        'type': 'image/png'},
    #                       {'href': '<SOME URL FOR LOGO>',
    #                        'name': 'large',
    #                        'type': 'image/png'}],
    #              'owners': {'href': 'https://<YOUR DOMAIN>.okta.com/api/v1/groups/<GROUP ID>/owners'},
    #              'users': {'href': 'https://<YOUR DOMAIN>.okta.com/api/v1/groups/<GROUP ID>/users'}},
    #   'created': '2021-08-16T21:47:23.000Z',
    #   'id': '<ID>',
    #   'lastMembershipUpdated': '2021-08-24T19:20:16.000Z',
    #   'lastUpdated': '2021-10-20T23:21:04.000Z',
    #   'objectClass': ['okta:user_group'],
    #   'profile': {'description': '<DESCRIPTION>',
    #               'name': '<OKTA GROUP NAME>'
    #                       '<OKTA GROUP NAME'},
    #   'type': 'OKTA_GROUP'},
    #  {'_links': {'apps': {'href': 'https://<YOUR DOMAIN>.okta.com/api/v1/groups/<GROUP ID>/apps'},
    #              'logo': [{'href': '<SOME URL FOR LOGO>',
    #                        'name': 'medium',
    #                        'type': 'image/png'},
    #                       {'href': '<SOME URL FOR LOGO>',
    #                        'name': 'large',
    #                        'type': 'image/png'}],
    #              'owners': {'href': 'https://<YOUR DOMAIN>.okta.com/api/v1/groups/00g53m21pj6R0pOPI357/owners'},
    #              'users': {'href': 'https://<YOUR DOMAIN>.okta.com/api/v1/groups/00g53m21pj6R0pOPI357/users'}},
    #   'created': '2020-08-12T22:18:28.000Z',
    #   'id': '<ID>',
    #   'lastMembershipUpdated': '2023-08-06T18:21:02.000Z',
    #   'lastUpdated': '2021-10-20T23:56:20.000Z',
    #   'objectClass': ['okta:user_group'],
    #   'profile': {'description': '<DESCRIPTION',
    #               'name': '<OKTA GROUP NAME>'},
    #   'type': 'OKTA_GROUP'},]

    okta_known_groups = []

    # Gather names of all Okta groups in a list
    for group in okta_known_groups_response:
        okta_known_groups.append(group["profile"]["name"].lower())

    # Discard any Okta groups referenced in the Vault config that don't actually exist in Okta
    confirmed_groups = [
        group for group in vault_known_groups if group in okta_known_groups
    ]
    # ['<OKTA GROUP 1>',
    #  '<OKTA GROUP 2>',
    #  '<OKTA GROUP 3>',
    #  '<OKTA GROUP 4>',]

    # Make dictionary that organizes users by policy
    for group in confirmed_groups:
        # Get policies
        b = requests.get(
            "https://<VAULT URL>:<PORT>/v1/auth/okta/groups/{}".format(group),
            headers=vault_headers,
        )

        okta_group_policies_response = b.json()

        okta_group_policies = okta_group_policies_response["data"]["policies"]
        #       ['<POLICY 1>',
        #        '<POLICY 2>',
        #        '<POLICY 3>',
        #        '<POLICY 4>',
        #        '<POLICY 5>',
        #        '<POLICY 6>']

        # Get the ID https://developer.okta.com/docs/reference/api/groups/#find-groups
        # (You'll need this to retrieve membership for each group)
        c = requests.get(
            "https://<YOUR DOMAIN>.okta.com/api/v1/groups/?q={}".format(group),
            headers=okta_headers,
        )

        okta_group_response = c.json()
        # [ {"_links": {
        #       "apps": {"href": "https://<YOUR DOMAIN>.okta.com/api/v1/groups/<GROUP ID>/apps"},
        #                "logo": [{"href": "<SOME URL FOR LOGO>",
        #                           "name": "medium",
        #                           "type": "image/png",},
        #                         {"href": "<SOME URL FOR LOGO>",
        #                           "name": "large",
        #                            "type": "image/png",},],
        #               "owners": {"href": "https://<YOUR DOMAIN>.okta.com/api/v1/groups/<GROUP ID>/owners"},
        #               "users": {"href": "https://<YOUR DOMAIN>.okta.com/api/v1/groups/<GROUP ID>/users"},},
        #         "created": "2023-07-20T21:34:51.000Z",
        #         "id": "<GROUP ID>",
        #         "lastMembershipUpdated": "2023-07-20T21:35:19.000Z",
        #         "lastUpdated": "2023-07-20T21:34:51.000Z",
        #         "objectClass": ["okta:user_group"],
        #         "profile": {
        #             "description": "<DESCRIPTION>",
        #             "name": "<OKTA GROUP NAME>",
        #         },
        #         "type": "OKTA_GROUP",
        #     }
        # ]

        # pprint('okta_group_response:')
        # pprint(okta_group_response)
        # print('')
        # print('')

        # Note: We sometimes get more than one okta group dictionary object in the response, but everything after okta_group_response[0] is a partial match.
        okta_group_id = okta_group_response[0]["id"]

        # Get users https://developer.okta.com/docs/reference/api/groups/#list-group-members
        d = requests.get(
            "https://<YOUR DOMAIN>.okta.com/api/v1/groups/{}/users".format(
                okta_group_id
            ),
            headers=okta_headers,
        )

        users_response = d.json()
        emails = []

        # Get all active users
        for user in users_response:
            if user["status"] == "ACTIVE":
                email = user["profile"]["email"]
                emails.append(email)
                # TODO: Remove after testing
                if emails == []:
                    pprint("This group is empty: " + group)

        # Add to dictionary of Okta groups and users (scoped to this loop)
        users_by_group = {}

        users_by_group[group] = emails
        # {'app-vault-programbuildapi-kv-admin': ['<USER1>@<YOURDOMAIN>.com',
        #                                         '<USER2>@<YOURDOMAIN>.com',
        #                                         '<USER3>@<YOURDOMAIN>.com']}

        # Add to dictionary of policies
        for policy in okta_group_policies:
            if policy in info_by_policy:
                info_by_policy[policy].append(users_by_group)

            else:
                info_by_policy[policy] = [users_by_group]

    # Get list of policies that grant access to user-provided path (info_by_path)

    possible_paths.append(user_provided_path)
    # ['*',
    # 'secret/data/foo/bar/*',
    # 'secret/+/foo/bar/*',
    # 'secret/data/foo/*',
    # 'secret/+/foo/*',
    # 'secret/data/*',
    # 'secret/+/*',
    # 'secret/data/foo/bar/something']

    chosen_policies = []

    for path in possible_paths:
        # if path in info_by_path:
        #     print(path + ' is in info_by_path')

        if info_by_path.get(path) is not None and path != "*":
            # print('The following should not be empty')
            # print(info_by_path.get(path))
            chosen_policies.extend(info_by_path[path])

    print("")
    print("")
    print(
        "If a user has access to any of these paths, they will also have access to the path you provided:"
    )
    pprint(possible_paths)
    print("")
    print("")

    print(
        "Users are given access through the following policies (not including the root policy):"
    )
    pprint(chosen_policies)
    print("")
    print("")

    for policy in chosen_policies:
        policy = list(policy)
        policy_names.append(policy[0])
    # ['<POLICY1>',
    #  '<POLICY2>',
    #  '<POLICY3>',
    #  '<POLICY4>',
    #  '<POLICY5>',
    #  '<POLICY6>',]

    chosen_users = []

    # Get a list of Okta groups that exist and have these policies applied
    for policy in policy_names:
        # Ignore policies that do not exist in the info_by_policy dictionary (they are applied to an Okta group that doesn't exist)
        if policy in info_by_policy:
            chosen_okta_groups = info_by_policy[policy]

            #           [{'team card fulfillment': ['<USER1>@<YOURDOMAIN>.com',
            #                                       '<USER2>@<YOURDOMAIN>.com',
            #                                       '<USER3>@<YOURDOMAIN>.com',
            #                                       '<USER4>@<YOURDOMAIN>.com',
            #                                       '<USER5>@<YOURDOMAIN>.com']},
            #            {'team-pem-engineers'   :  ['<USER6>@<YOURDOMAIN>.com',
            #                                        '<USER7>@<YOURDOMAIN>.com',
            #                                        '<USER8>@<YOURDOMAIN>.com',
            #                                        '<USER9>@<YOURDOMAIN>.com',
            #                                        '<USER10>@<YOURDOMAIN>.com']}]

            print(
                "The following Okta groups exist and have the %s policy applied to them"
                % (policy)
            )
            pprint(chosen_okta_groups)
            print("")
            print("")

            for group in chosen_okta_groups:
                #                 {'team card fulfillment': ['<USER1>@<YOURDOMAIN>.com',
                #                                            '<USER2>@<YOURDOMAIN>.com',
                #                                            '<USER3>@<YOURDOMAIN>.com',
                #                                            '<USER4>@<YOURDOMAIN>.com',
                #                                            '<USER5>@<YOURDOMAIN>.com']}
                chosen_users.extend(list(group.values())[0])

    chosen_users = set(chosen_users)

    pprint("Users with access to the path:")
    pprint(chosen_users)
    print("")
    print("")

    # info_by_path
    #   {path : [ {policy : {capabilities}},
    #             {policy : {capabilities}}, ]}

    # info_by_policy
    #   {policy : [ {okta group : [users]},
    #               {okta group : [users] ]}

else:
    email = args[0]
    okta_groups = []
    all_mapped_groups = []
    applied_rules = []

    # Find out if user has an active Okta account
    r = requests.get(
        "https://<YOURDOMAIN>.okta.com/api/v1/users/{}".format(email),
        headers=okta_headers,
    )

    user = r.json()

    print("")

    if user["status"] == "ACTIVE":
        print("User's Okta account is ACTIVE")
        print("")

        # Create table to render info later
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Okta group", style="dim", max_width=None, overflow="fold")
        table.add_column("Vault Policy", max_width=None, overflow="fold")
        table.add_column("Path", max_width=None, overflow="fold")
        table.add_column("Permissions", max_width=None, overflow="fold")

        # Find Okta groups the user belongs to, according to Okta
        s = requests.get(
            "https://<YOUR DOMAIN>.okta.com/api/v1/users/{}/groups".format(email),
            headers=okta_headers,
        )

        groups = s.json()

        for group in groups:
            okta_groups.append(group["profile"]["name"])

        # Find all Okta groups that Vault knows about
        t = requests.get(
            "https://<VAULT URL>:<PORT>/v1/auth/okta/groups",
            headers=vault_headers,
            params=vault_params,
        )

        vault_groups_response = t.json()
        all_mapped_groups = vault_groups_response["data"]["keys"]

        # vault_groups_response
        # [
        # "data" : ["some value": "blah"
        #           "keys: "blahblah"]
        # "apple" : "some other value"
        # "orange" : "some even more other value"
        #  ]

        # Vault saves Okta group names in lowercase; Make the names sourced from Okta comparable
        lowercase_okta_groups = [s.lower() for s in okta_groups]

        # Alternate methods:
        # lowercase_okta_groups = list(map(str.lower, okta_groups))
        # lowercase_okta_groups = (s.lower() for s in okta_groups)

        # Get Okta groups that grant the user access to Vault paths
        access_groups = [
            x for x in all_mapped_groups for y in lowercase_okta_groups if x == y
        ]

        print("")
        print(
            "Vault policies are applied to the user via their membership to these Okta groups:"
        )
        pprint(access_groups)
        print("")

        full_map = {}

        for group in access_groups:
            policies = []

            if group == "groupless (Vault-defined)":
                # Add the Vault 'group'-inherited policies to the list
                policies = groupless_policies

            else:
                # Query Vault API for list of policies applied to the Okta group
                u = requests.get(
                    "https://<VAULT URL>:<PORT>/v1/auth/okta/groups/{}".format(
                        urllib.parse.quote(group)
                    ),
                    headers=vault_headers,
                )
                policy_response = u.json()
                policies.extend(policy_response["data"]["policies"])

            # If there is not an entry for the Okta group (or Vault group), make one
            if group not in full_map:
                full_map[group] = {}

            for policy in policies:
                # If there is not an entry for the policy, add it
                if policy not in full_map[group]:
                    # get rules associated with policy
                    v = requests.get(
                        "https://<VAULT URL>:<PORT>/v1/sys/policy/{}".format(policy),
                        headers=vault_headers,
                    )

                    rules_response = v.json()
                    rules = rules_response["rules"]

                    # Create a temp file to write rules HCL to
                    # https://github.com/amplify-education/python-hcl2/blob/main/hcl2/api.py
                    rules_temp = tempfile.NamedTemporaryFile(
                        prefix="pathfinder_", mode="w+t"
                    )

                    try:
                        rules_temp.writelines(rules)
                        rules_temp.seek(0)

                        # Convert rules HCL to dict and add to nested dictionary
                        with open(rules_temp.name, "r") as rules_json:
                            obj = hcl2.load(rules_json)

                            full_map[group][policy] = obj

                            for path_dict in full_map[group][policy]["path"]:
                                for path in path_dict:
                                    capabilities = path_dict[path]["capabilities"]
                                    table.add_row(
                                        group, policy, path, " ".join(capabilities)
                                    )

                    finally:
                        rules_temp.close()

        print("")
        print("Group membership, policies, and paths accessible to user")
        console.print(table)

    else:
        print(
            "User's Okta account is DEACTIVATED - they no longer have access to any Vault paths"
        )
