import http.client
import json
import subprocess

# Fonction pour obtenir un token
def get_token(client_id, tenant_id, username, password, scope):
    scope = f"openid profile offline_access {scope}"
    body = (
        f"client_id={client_id}&grant_type=password&username={username}"
        f"&password={password}&scope={scope}&client_info=1"
    )
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    conn = http.client.HTTPSConnection("login.microsoftonline.com")
    conn.request("POST", f"/{tenant_id}/oauth2/v2.0/token", body, headers)
    response = conn.getresponse()
    data = response.read()
    conn.close()
    token_response = json.loads(data)
    if "access_token" in token_response:
        access_token = token_response['access_token']
        print("[+] Access token acquired successfully.")
        return access_token
    else:
        print(f"[-] Failed to acquire token: {token_response.get('error_description', 'Unknown error')}")
        return None

# Obtenir le token Graph API
def get_graph_token(client_id, tenant_id, username, password):
    return get_token(client_id, tenant_id, username, password, "https://graph.microsoft.com/.default")

# Obtenir le token ARM
def get_arm_token(client_id, tenant_id, username, password):
    return get_token(client_id, tenant_id, username, password, "https://management.azure.com/.default")

# Fonction pour exécuter des commandes PowerShell
def run_powershell_command(command):
    try:
        result = subprocess.run(
            ["powershell", "-Command", command],
            capture_output=True,
            text=True,
            shell=True
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        print(f"Erreur lors de l'exécution de la commande PowerShell : {e}")
        return -1, "", str(e)

# Exécution des commandes pour un type de ressource avec Graph API
def execute_graph_by_type(token, resource_type):
    commands = {
        "users": "Get-MgUser -All | ConvertTo-Json -Depth 3",
        "groups": "Get-MgGroup -All | ConvertTo-Json -Depth 3",
        "apps": "Get-MgApplication -All | ConvertTo-Json -Depth 3",
    }
    if resource_type == "all":
        for cmd in commands.values():
            ps_command = f'$Token="{token}"; {cmd}'
            print(f"Exécution Graph API : {cmd}")
            return_code, stdout, stderr = run_powershell_command(ps_command)
            if return_code == 0:
                print("Résultat :")
                print(stdout)
            else:
                print(f"Erreur lors de l'exécution : {stderr}")
    else:
        cmd = commands.get(resource_type, None)
        if cmd:
            ps_command = f'$Token="{token}"; {cmd}'
            print(f"Exécution Graph API : {cmd}")
            return_code, stdout, stderr = run_powershell_command(ps_command)
            if return_code == 0:
                print("Résultat :")
                print(stdout)
            else:
                print(f"Erreur lors de l'exécution : {stderr}")
        else:
            print("Type de ressource invalide pour Graph API.")

# Exécution des commandes pour un type de ressource avec ARM
def execute_arm_by_type(token, tenant_id, account_id, resource_type):
    commands = {
        "keyvaults": "Get-AzKeyVault | ConvertTo-Json -Depth 3",
        "resources": "Get-AzResource | ConvertTo-Json -Depth 3",
        "subscriptions": "Get-AzSubscription | ConvertTo-Json -Depth 3",
    }
    if resource_type == "all":
        for cmd in commands.values():
            ps_command = (
                f'$Token="{token}"; $TenantId="{tenant_id}"; '
                f'Connect-AzAccount -AccessToken $Token -AccountId "{account_id}" -TenantId $TenantId; '
                f'{cmd}'
            )
            print(f"Exécution ARM : {cmd}")
            return_code, stdout, stderr = run_powershell_command(ps_command)
            if return_code == 0:
                print("Résultat :")
                print(stdout)
            else:
                print(f"Erreur lors de l'exécution : {stderr}")
    else:
        cmd = commands.get(resource_type, None)
        if cmd:
            ps_command = (
                f'$Token="{token}"; $TenantId="{tenant_id}"; '
                f'Connect-AzAccount -AccessToken $Token -AccountId "{account_id}" -TenantId $TenantId; '
                f'{cmd}'
            )
            print(f"Exécution ARM : {cmd}")
            return_code, stdout, stderr = run_powershell_command(ps_command)
            if return_code == 0:
                print("Résultat :")
                print(stdout)
            else:
                print(f"Erreur lors de l'exécution : {stderr}")
        else:
            print("Type de ressource invalide pour ARM.")

# Fonction principale
if __name__ == "__main__":
    print("Bienvenue dans AzureEnum !\n")
    client_id = input("[1] - Entrez le client ID : ")
    tenant_id = input("[2] - Entrez le Tenant ID : ")
    username = input("[3] - Entrez l'username : ")
    password = input("[4] - Entrez le password : ")
    account_id = input("[5] - Entrez l'Account ID (ex: utilisateur@domaine.com) : ")

    while True:
        print("\n[1] - Connecter et énumérer via Graph API")
        print("[2] - Connecter et énumérer via ARM")
        print("[3] - Quitter")

        choix = input("\nChoisissez une option (1, 2, 3) : ")

        if choix == "1":
            token = get_graph_token(client_id, tenant_id, username, password)
            if token:
                print("\n[1] - Énumérer les utilisateurs")
                print("[2] - Énumérer les groupes")
                print("[3] - Énumérer les applications")
                print("[4] - Tout énumérer")
                resource_choice = input("\nChoisissez une option : ")
                resource_map = {"1": "users", "2": "groups", "3": "apps", "4": "all"}
                execute_graph_by_type(token, resource_map.get(resource_choice, "all"))
        elif choix == "2":
            token = get_arm_token(client_id, tenant_id, username, password)
            if token:
                print("\n[1] - Énumérer les KeyVaults")
                print("[2] - Énumérer les ressources")
                print("[3] - Énumérer les abonnements")
                print("[4] - Tout énumérer")
                resource_choice = input("\nChoisissez une option : ")
                resource_map = {"1": "keyvaults", "2": "resources", "3": "subscriptions", "4": "all"}
                execute_arm_by_type(token, tenant_id, account_id, resource_map.get(resource_choice, "all"))
        elif choix == "3":
            print("Au revoir!")
            break
        else:
            print("Option invalide, réessayez.")
