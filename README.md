# pathfinder

Python script that queries the Okta and Vault APIs and determines what Okta groups grant human access to what Vault paths.  This script assumes your humans are authenticating to Vault via Okta.  You can query by path or by user! 

## Do this before using script
- Install [homebrew](https://brew.sh/).  
- Install [dependencies for pyenv](https://realpython.com/intro-to-pyenv/#build-dependencies), then install [pyenv itself](https://realpython.com/intro-to-pyenv/#using-the-pyenv-installer).  
- Use pyenv to [install python 3.7](https://realpython.com/intro-to-pyenv/#using-pyenv-to-install-python) or later.  Select that version for use.
- Use pip to install the packages in requirements.txt
```sh 
$> pip install -r requirements.txt
```
- Set an environment variable called `OKTA_TOKEN` to an Okta API key that can read the group membership of all users in Okta.  
- Set an environment variable called `VAULT-ADDR` to the URL of your Vault instance
- Make sure you are in an Okta group that has has Read,List access to all secrets engine paths in Vault
- Log into Vault using the [Vault CLI](https://developer.hashicorp.com/vault/downloads).  User authentication looks like this:
```sh
$> vault login -method=okta username=clazarou # MFA via Okta Verify required

Success! You are now authenticated. The token information displayed below
is already stored in the token helper. You do NOT need to run "vault login"
again. Future Vault requests will automatically use this token.

Key                  Value
---                  -----
token                foo
token_accessor       bar
token_duration       768h
token_renewable      true
token_policies         ["default" "some-policy-1" "some-policy-2" "some-policy-3"]
identity_policies      []
policies               ["default" "some-policy-1" "some-policy-2" "some-policy-3"]
token_meta_policies    "some-policy-1" "some-policy-2" "some-policy-3"
token_meta_username    clazarou
```

## Run pathfinder.py: Find all the Vault paths a specific user can access
Run the script and provide the user's email as an argument

```python pathfinder.py username@somedomain.com```

## Run pathfinder.py: Find all the users that can access a specific Vault path

```python pathfinder.py -path <some path>```

## Common Errors
```sh
$> python pathfinder.py username@somedomain.com

User's Okta account is ACTIVE

Traceback (most recent call last):
  File "/Users/clazarou/blah/blah/pathfinder.py", line 66, in <module>
    all_mapped_groups = vault_groups_response["data"]["keys"]
KeyError: 'data'
```
If you see a KeyError like the above, you may need to authenticate to Vault again and save your new token to the VAULT_TOKEN environment variable.
