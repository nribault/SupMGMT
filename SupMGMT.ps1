#Requires -Version 5.1
# -*- coding: utf-8 -*-
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

<#
Ce script permet de configurer un serveur ou poste de travail Windows afin d'être supervisé via SNMP, WinRM et WMI.
Il génère un compte local du type supervision-xxxxxx et lui affecte les bon droits au niveau groupe, Winmgmt et dcom
Configure winrm pour une utilisation à distance.
Il install également l'agent SNMP, créé une communauté SNMP et applique la stratégie pour permettre un accès extérieur.
Le Ping est également accepté afin de virifier le statu global de l'hôte.

Auteur : Nicolas RIBAULT
Date : 04/04/2025
#>

# Vérification des droits administrateur
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Ce script nécessite des droits administrateur. Relancement en tant qu'administrateur..."
    
    # Création d'une nouvelle instance PowerShell avec les droits administrateur
    $NewProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell"
    $NewProcess.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    $NewProcess.Verb = "runas"
    
    try {
        [System.Diagnostics.Process]::Start($NewProcess)
        exit
    }
    catch {
        Write-Error "Impossible de relancer le script en tant qu'administrateur. Veuillez exécuter PowerShell en tant qu'administrateur manuellement."
        exit
    }
}

# Fonction pour générer un mot de passe complexe
function New-ComplexPassword {
    param (
        [int]$Length = 18
    )
    
    # Définir les ensembles de caractères
    $UpperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray()
    $LowerCase = "abcdefghijklmnopqrstuvwxyz".ToCharArray()
    $Numbers = "0123456789".ToCharArray()
    $SpecialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?".ToCharArray()
    
    # Créer un tableau pour stocker les caractères du mot de passe
    $PasswordChars = @()
    
    # Ajouter un caractère de chaque type
    $PasswordChars += $UpperCase | Get-Random -Count 1
    $PasswordChars += $LowerCase | Get-Random -Count 1
    $PasswordChars += $Numbers | Get-Random -Count 1
    $PasswordChars += $SpecialChars | Get-Random -Count 1
    
    # Créer un tableau avec tous les caractères possibles
    $AllChars = $UpperCase + $LowerCase + $Numbers + $SpecialChars
    
    # Ajouter des caractères aléatoires jusqu'à atteindre la longueur souhaitée
    $RemainingLength = $Length - 4
    $PasswordChars += $AllChars | Get-Random -Count $RemainingLength
    
    # Mélanger le tableau de caractères
    $PasswordChars = $PasswordChars | Get-Random -Count $PasswordChars.Count
    
    # Convertir en chaîne
    return -join $PasswordChars
}

# Fonction pour générer un nom d'utilisateur aléatoire
function New-RandomUsername {
    $Prefix = "supervision-"
    $RandomSuffix = -join ((48..57) + (97..122) | Get-Random -Count 6 | ForEach-Object {[char]$_})
    return $Prefix + $RandomSuffix
}

# Fonction pour créer un compte local
function New-LocalSupervisionAccount {
    param (
        [string]$Username,
        [string]$Password
    )
    
    try {
        # Vérification si le compte existe déjà
        $ExistingUser = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue
        if ($ExistingUser) {
            Write-Warning "Le compte $Username existe déjà. Suppression du compte existant..."
            Remove-LocalUser -Name $Username -ErrorAction Stop
        }
        
        # Création du compte
        $SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
        $UserParams = @{
            Name = $Username
            Password = $SecurePassword
            PasswordNeverExpires = $true
            UserMayNotChangePassword = $true
            ErrorAction = 'Stop'
        }
        New-LocalUser @UserParams
        
        # Restreindre les droits d'accès
        $UserSID = (Get-LocalUser -Name $Username).SID
        $DenyLogonLocally = "SeDenyInteractiveLogonRight"
        $DenyLogonRemote = "SeDenyRemoteInteractiveLogonRight"

        
        # Sauvegarder la configuration actuelle
        secedit /export /cfg current.inf /areas USER_RIGHTS
        
        # Modifier les droits
        $CurrentConfig = Get-Content current.inf
        $CurrentConfig += "`n$DenyLogonLocally = *$UserSID"
        $CurrentConfig += "`n$DenyLogonRemote = *$UserSID"
        $CurrentConfig | Set-Content current.inf
        
        # Appliquer les modifications
        secedit /configure /db secedit.sdb /cfg current.inf /areas USER_RIGHTS
        
        # Nettoyer les fichiers temporaires
        Remove-Item current.inf -Force -ErrorAction SilentlyContinue
        Remove-Item secedit.sdb -Force -ErrorAction SilentlyContinue
        
        # Ajouter au groupe Performance Log Users (en fonction de la langue)
        $PerformanceLogGroupNames = @(
            "Performance Log Users",
            "Utilisateurs du journal de performances"
        )
        
        $GroupFound = $false
        foreach ($GroupName in $PerformanceLogGroupNames) {
            try {
                $Group = Get-LocalGroup -Name $GroupName -ErrorAction Stop
                if ($Group) {
                    Add-LocalGroupMember -Group $GroupName -Member $Username -ErrorAction Stop
                    Write-Host "Utilisateur ajouté au groupe '$GroupName'" -ForegroundColor Green
                    $GroupFound = $true
                    break
                }
            }
            catch {
                Write-Debug "Groupe '$GroupName' non trouvé"
            }
        }
        
        if (-not $GroupFound) {
            Write-Warning "Aucun groupe Performance Log Users n'a été trouvé. Veuillez vérifier manuellement l'appartenance au groupe."
        }
        
        # Vérification de l'appartenance au groupe
        $UserGroups = Get-LocalGroup | Where-Object { (Get-LocalGroupMember -Group $_).Name -contains "$env:COMPUTERNAME\$Username" }
        Write-Host "`nGroupes de l'utilisateur :" -ForegroundColor Cyan
        $UserGroups | ForEach-Object { Write-Host "- $($_.Name)" -ForegroundColor Yellow }
        
        Write-Host "`nCompte $Username créé avec succès." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Erreur lors de la création du compte : $_"
        return $false
    }
}

# Fonction pour générer une communauté SNMP sécurisée
function New-SecureSNMPCommunity {
    param (
        [int]$Length = 16
    )
    
    # Définir les ensembles de caractères
    $UpperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray()
    $LowerCase = "abcdefghijklmnopqrstuvwxyz".ToCharArray()
    $Numbers = "0123456789".ToCharArray()
    
    # Créer un tableau pour stocker les caractères de la communauté
    $CommunityChars = @()
    
    # Ajouter au moins un caractère de chaque type
    $CommunityChars += $UpperCase | Get-Random -Count 1
    $CommunityChars += $LowerCase | Get-Random -Count 1
    $CommunityChars += $Numbers | Get-Random -Count 1
    
    # Créer un tableau avec tous les caractères possibles
    $AllChars = $UpperCase + $LowerCase + $Numbers
    
    # Ajouter des caractères aléatoires jusqu'à atteindre la longueur souhaitée
    $RemainingLength = $Length - 3
    $CommunityChars += $AllChars | Get-Random -Count $RemainingLength
    
    # Mélanger le tableau de caractères
    $CommunityChars = $CommunityChars | Get-Random -Count $CommunityChars.Count
    
    # Convertir en chaîne
    return -join $CommunityChars
}

# Fonction pour configurer SNMP
function Set-SNMPConfiguration {
    param (
        [string]$Community,
        [string]$ProbeIP = "any"
    )
    
    try {
        # Vérifier si le service SNMP est installé
        $SNMPService = Get-Service -Name "SNMP" -ErrorAction SilentlyContinue
        if (-not $SNMPService) {
            Write-Host "Installation du service SNMP..." -ForegroundColor Yellow
            
            # Détecter le type de système d'exploitation
            $OSInfo = Get-WmiObject -Class Win32_OperatingSystem
            $IsServer = $OSInfo.ProductType -eq 2  # 2 = Server, 1 = Workstation
            
            if ($IsServer) {
                # Installation sur Windows Server
                Write-Host "Installation sur Windows Server..." -ForegroundColor Yellow
                $InstallResult = Install-WindowsFeature -Name "SNMP-Service" -IncludeManagementTools -ErrorAction Stop
                
                if ($InstallResult.RestartNeeded) {
                    Write-Host "Un redémarrage est nécessaire pour terminer l'installation de SNMP." -ForegroundColor Yellow
                    Write-Host "Veuillez redémarrer le système et relancer le script." -ForegroundColor Yellow
                    return $false
                }
            }
            else {
                # Installation sur Windows 10/11
                Write-Host "Installation sur Windows 10/11..." -ForegroundColor Yellow
                $InstallResult = Add-WindowsCapability -Online -Name "SNMP.Client~~~~0.0.1.0" -ErrorAction Stop
                
                if ($InstallResult.RestartNeeded) {
                    Write-Host "Un redémarrage est nécessaire pour terminer l'installation de SNMP." -ForegroundColor Yellow
                    Write-Host "Veuillez redémarrer le système et relancer le script." -ForegroundColor Yellow
                    return $false
                }
            }
            
            # Attendre que le service soit installé
            Write-Host "`nAttente de l'installation du service..." -ForegroundColor Yellow
            $Timeout = 30
            $Counter = 0
            while (-not (Get-Service -Name "SNMP" -ErrorAction SilentlyContinue) -and $Counter -lt $Timeout) {
                Start-Sleep -Seconds 1
                $Counter++
            }
            
            if ($Counter -ge $Timeout) {
                throw "Le service SNMP n'a pas été installé après $Timeout secondes."
            }
        }
        
        # Vérifier si le service est maintenant disponible
        $SNMPService = Get-Service -Name "SNMP" -ErrorAction SilentlyContinue
        if (-not $SNMPService) {
            throw "Le service SNMP n'est pas disponible. Veuillez vérifier que le composant est bien installé."
        }
        
        # Configurer la communauté SNMP
        $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities"
        if (-not (Test-Path $RegPath)) {
            New-Item -Path $RegPath -Force | Out-Null
        }
        
        # Supprimer les anciennes communautés
        Remove-ItemProperty -Path $RegPath -Name * -ErrorAction SilentlyContinue
        
        # Ajouter la nouvelle communauté avec droits en lecture seule
        New-ItemProperty -Path $RegPath -Name $Community -Value 4 -PropertyType DWORD -Force | Out-Null
        
        # Configurer les permissions d'accès
        $PermittedManagersPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"
        
        if ($ProbeIP -eq "any") {
            # Supprimer la clé PermittedManagers pour autoriser toutes les IP
            if (Test-Path $PermittedManagersPath) {
                Remove-Item -Path $PermittedManagersPath -Recurse -Force
                Write-Host "Communauté SNMP configurée pour toutes les adresses IP." -ForegroundColor Green
            }
        }
        else {
            # Créer la clé et ajouter l'IP spécifique
            if (-not (Test-Path $PermittedManagersPath)) {
                New-Item -Path $PermittedManagersPath -Force | Out-Null
            }
            New-ItemProperty -Path $PermittedManagersPath -Name "1" -Value $ProbeIP -PropertyType String -Force | Out-Null
            Write-Host "Communauté SNMP configurée pour l'adresse IP : $ProbeIP" -ForegroundColor Green
        }
        
        # Redémarrer le service SNMP
        Write-Host "Redémarrage du service SNMP..." -ForegroundColor Yellow
        Restart-Service -Name "SNMP" -Force -ErrorAction Stop
        
        Write-Host "Communauté SNMP '$Community' configurée avec succès." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Erreur lors de la configuration SNMP : $_"
        Write-Host "`nPour installer SNMP manuellement :" -ForegroundColor Yellow
        
        if ($IsServer) {
            Write-Host "Sur Windows Server, via PowerShell en tant qu'administrateur :" -ForegroundColor Yellow
            Write-Host "Install-WindowsFeature -Name 'SNMP-Service' -IncludeManagementTools" -ForegroundColor Yellow
        }
        else {
            Write-Host "Sur Windows 10/11, via PowerShell en tant qu'administrateur :" -ForegroundColor Yellow
            Write-Host "Add-WindowsCapability -Online -Name 'SNMP.Client~~~~0.0.1.0'" -ForegroundColor Yellow
        }
        
        return $false
    }
}

# Fonction pour autoriser le ping entrant
function Enable-ICMPEchoRequest {
    try {
        Write-Host "Configuration du pare-feu pour autoriser le ping..." -ForegroundColor Yellow
        
        # Vérifier si la règle existe déjà
        $ExistingRule = Get-NetFirewallRule -DisplayName "Autoriser le ping entrant" -ErrorAction SilentlyContinue
        
        if (-not $ExistingRule) {
            # Créer la règle pour autoriser le ping entrant
            New-NetFirewallRule -DisplayName "Autoriser le ping entrant" `
                               -Direction Inbound `
                               -Protocol ICMPv4 `
                               -IcmpType 8 `
                               -Action Allow `
                               -Enabled True `
                               -ErrorAction Stop
            
            Write-Host "Règle de pare-feu créée pour autoriser le ping entrant." -ForegroundColor Green
        }
        else {
            # Activer la règle existante
            Set-NetFirewallRule -DisplayName "Autoriser le ping entrant" -Enabled True -ErrorAction Stop
            Write-Host "Règle de pare-feu existante activée pour autoriser le ping entrant." -ForegroundColor Green
        }
        
        return $true
    }
    catch {
        Write-Error "Erreur lors de la configuration du pare-feu pour le ping : $_"
        return $false
    }
}

# Fonction pour activer une règle de pare-feu
function Enable-FirewallRule {
    param (
        [Parameter(Mandatory=$true)]
        [string]$RuleName
    )
    
    try {
        Write-Host "Activation de la règle de pare-feu '$RuleName'..." -ForegroundColor Yellow
        Enable-NetFirewallRule -DisplayName $RuleName -ErrorAction Stop
        Write-Host "Règle de pare-feu '$RuleName' activée avec succès." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Erreur lors de l'activation de la règle de pare-feu '$RuleName' : $_"
        return $false
    }
}

# Fonction pour configurer les autorisations WMI
function Set-WMIPermissions {
    param (
        [string]$Username
    )
    
    try {
        Write-Host "Configuration des autorisations WMI..." -ForegroundColor Yellow
        
        # Activer la règle de pare-feu WMI-IN
        Enable-FirewallRule -RuleName "Windows Management Instrumentation (WMI-In)"
        
        # Configurer les droits du Service Control Manager
        Write-Host "Configuration des droits du Service Control Manager..." -ForegroundColor Yellow
        $SCMCommand = 'sc.exe sdset SCMANAGER "D:(A;;CCLCRPRC;;;AU)(A;;CCLCRPWPRC;;;SY)(A;;KA;;;BA)S:(AU;FA;KA;;;WD)(AU;OIIOFA;GA;;;WD)"'
        $SCMResult = Invoke-Expression $SCMCommand
        
        if ($LASTEXITCODE -ne 0) {
            throw "Échec de la configuration des droits SCM. Code de sortie : $LASTEXITCODE"
        }
        
        # Définir les constantes pour les droits WMI
        $OBJECT_INHERIT_ACE_FLAG    = 0x1
        $CONTAINER_INHERIT_ACE_FLAG = 0x2
        $ACCESS_ALLOWED_ACE_TYPE    = 0x0
        $ACCESS_DENIED_ACE_TYPE     = 0x1
        
        $WBEM_ENABLE            = 0x01
        $WBEM_METHOD_EXECUTE    = 0x02
        $WBEM_FULL_WRITE_REP    = 0x04
        $WBEM_PARTIAL_WRITE_REP = 0x08
        $WBEM_WRITE_PROVIDER    = 0x10
        $WBEM_REMOTE_ACCESS     = 0x20
        $WBEM_RIGHT_SUBSCRIBE   = 0x40
        $WBEM_RIGHT_PUBLISH     = 0x80
        $READ_CONTROL           = 0x20000
        $WRITE_DAC              = 0x40000
        
        # Obtenir l'objet de sécurité WMI
        $InvokeParams = @{
            Namespace = "root\cimv2"
            Path = "__systemsecurity=@"
        }
        
        $Output = Invoke-WmiMethod @InvokeParams -Name "GetSecurityDescriptor"
        if ($Output.ReturnValue -ne 0) {
            throw "Échec de GetSecurityDescriptor : $($Output.ReturnValue)"
        }
        
        $ACL = $Output.Descriptor
        
        # Obtenir le compte utilisateur
        $GetParams = @{
            Class = "Win32_Account"
            Filter = "Domain='$env:COMPUTERNAME' and Name='$Username'"
        }
        
        $Win32Account = Get-WmiObject @GetParams
        if ($null -eq $Win32Account) {
            throw "Compte non trouvé : $Username"
        }
        
        # Construire le masque d'accès avec tous les droits nécessaires
        $AccessMask = $WBEM_ENABLE + $WBEM_METHOD_EXECUTE + $WBEM_REMOTE_ACCESS + $READ_CONTROL
        
        # Créer une nouvelle entrée ACE
        $ACE = (New-Object System.Management.ManagementClass("Win32_Ace")).CreateInstance()
        $ACE.AccessMask = $AccessMask
        $ACE.AceFlags = $CONTAINER_INHERIT_ACE_FLAG
        
        # Configurer le trustee
        $Trustee = (New-Object System.Management.ManagementClass("Win32_Trustee")).CreateInstance()
        $Trustee.SidString = $Win32Account.SID
        $ACE.Trustee = $Trustee
        $ACE.AceType = $ACCESS_ALLOWED_ACE_TYPE
        
        # Ajouter la nouvelle ACE à la DACL existante
        $ACL.DACL += $ACE
        
        # Appliquer les modifications
        $SetParams = @{
            Name = "SetSecurityDescriptor"
            ArgumentList = $ACL
        } + $InvokeParams
        
        $Output = Invoke-WmiMethod @SetParams
        if ($Output.ReturnValue -ne 0) {
            throw "Échec de SetSecurityDescriptor : $($Output.ReturnValue)"
        }
        
        Write-Host "Autorisations WMI configurées avec succès pour $Username." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Erreur lors de la configuration des autorisations WMI : $_"
        return $false
    }
}

# Fonction pour configurer WinRM
function Set-WinRMConfiguration {
    try {
        Write-Host "Configuration de WinRM..." -ForegroundColor Yellow
        
        # Exécuter la configuration rapide de WinRM
        $Result = winrm quickconfig -quiet -force
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "WinRM configuré avec succès." -ForegroundColor Green
            return $true
        }
        else {
            throw "Échec de la configuration WinRM. Code de sortie : $LASTEXITCODE"
        }
    }
    catch {
        Write-Error "Erreur lors de la configuration WinRM : $_"
        return $false
    }
}

# Fonction principale
function Initialize-Supervision {
    # Génération des identifiants
    $Username = New-RandomUsername
    $Password = New-ComplexPassword
    $SNMPCommunity = New-SecureSNMPCommunity
    
    Write-Host "Configuration de la supervision pour $env:COMPUTERNAME" -ForegroundColor Cyan
    Write-Host "Nom d'utilisateur généré : $Username" -ForegroundColor Yellow
    Write-Host "Mot de passe généré : $Password" -ForegroundColor Yellow
    Write-Host "Communauté SNMP générée : $SNMPCommunity" -ForegroundColor Yellow
    
    # Demande de confirmation à l'utilisateur
    Write-Host "`nVeuillez sauvegarder ces identifiants avant de continuer." -ForegroundColor Yellow
    $Confirmation = Read-Host "Avez-vous sauvegardé les identifiants et souhaitez-vous continuer ? (O/N)"
    
    if ($Confirmation -ne "O") {
        Write-Host "Opération annulée par l'utilisateur." -ForegroundColor Red
        exit
    }
    
    # Création du compte
    if (New-LocalSupervisionAccount -Username $Username -Password $Password) {
        Write-Host "`nCompte créé avec succès." -ForegroundColor Green
    }
    else {
        Write-Host "`nLa création du compte a échoué. Veuillez vérifier les messages d'erreur ci-dessus." -ForegroundColor Red
        exit
    }
    
    # Configuration SNMP
    if (Set-SNMPConfiguration -Community $SNMPCommunity) {
        Write-Host "Configuration SNMP terminée avec succès." -ForegroundColor Green
    }
    else {
        Write-Host "`nLa configuration SNMP a échoué. Veuillez vérifier les messages d'erreur ci-dessus." -ForegroundColor Red
    }
    
    # Autorisation du ping
    if (Enable-ICMPEchoRequest) {
        Write-Host "Configuration du ping terminée avec succès." -ForegroundColor Green
    }
    else {
        Write-Host "`nLa configuration du ping a échoué. Veuillez vérifier les messages d'erreur ci-dessus." -ForegroundColor Red
    }
    
    # Configuration des autorisations WMI
    if (Set-WMIPermissions -Username $Username) {
        Write-Host "Configuration WMI terminée avec succès." -ForegroundColor Green
    }
    else {
        Write-Host "`nLa configuration WMI a échoué. Veuillez vérifier les messages d'erreur ci-dessus." -ForegroundColor Red
    }
    
    # Configuration WinRM
    if (Set-WinRMConfiguration) {
        Write-Host "Configuration WinRM terminée avec succès." -ForegroundColor Green
    }
    else {
        Write-Host "`nLa configuration WinRM a échoué. Veuillez vérifier les messages d'erreur ci-dessus." -ForegroundColor Red
    }
    
    # TODO: Implémenter les autres fonctionnalités
    # - Configuration des droits
}

# Démarrage du script
Initialize-Supervision

# Pause à la fin du script
Write-Host "`nAppuyez sur une touche pour quitter..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
