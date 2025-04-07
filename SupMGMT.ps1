<#
Ce script permet de configurer un serveur ou poste de travail Windows afin d'�tre supervis� via SNMP, WinRM et WMI.
Il g�n�re un compte local du type supervision-xxxxxx et lui affecte les bon droits au niveau groupe, Winmgmt et dcom
Configure winrm pour une utilisation � distance.
Il install �galement l'agent SNMP, cr�� une communaut� SNMP et applique la strat�gie pour permettre un acc�s ext�rieur.
Le Ping est �galement accept� afin de virifier le statu global de l'h�te.

Auteur : Nicolas RIBAULT
Date : 04/04/2025
#>

# V�rification des droits administrateur
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Ce script n�cessite des droits administrateur. Relancement en tant qu'administrateur..."
    
    # Cr�ation d'une nouvelle instance PowerShell avec les droits administrateur
    $NewProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell"
    $NewProcess.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    $NewProcess.Verb = "runas"
    
    try {
        [System.Diagnostics.Process]::Start($NewProcess)
        exit
    }
    catch {
        Write-Error "Impossible de relancer le script en tant qu'administrateur. Veuillez ex�cuter PowerShell en tant qu'administrateur manuellement."
        exit
    }
}

# Fonction pour g�n�rer un mot de passe complexe
function New-ComplexPassword {
    param (
        [int]$Length = 18
    )
    
    # D�finir les ensembles de caract�res
    $UpperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray()
    $LowerCase = "abcdefghijklmnopqrstuvwxyz".ToCharArray()
    $Numbers = "0123456789".ToCharArray()
    $SpecialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?".ToCharArray()
    
    # Cr�er un tableau pour stocker les caract�res du mot de passe
    $PasswordChars = @()
    
    # Ajouter un caract�re de chaque type
    $PasswordChars += $UpperCase | Get-Random -Count 1
    $PasswordChars += $LowerCase | Get-Random -Count 1
    $PasswordChars += $Numbers | Get-Random -Count 1
    $PasswordChars += $SpecialChars | Get-Random -Count 1
    
    # Cr�er un tableau avec tous les caract�res possibles
    $AllChars = $UpperCase + $LowerCase + $Numbers + $SpecialChars
    
    # Ajouter des caract�res al�atoires jusqu'� atteindre la longueur souhait�e
    $RemainingLength = $Length - 4
    $PasswordChars += $AllChars | Get-Random -Count $RemainingLength
    
    # M�langer le tableau de caract�res
    $PasswordChars = $PasswordChars | Get-Random -Count $PasswordChars.Count
    
    # Convertir en cha�ne
    return -join $PasswordChars
}

# Fonction pour g�n�rer un nom d'utilisateur al�atoire
function New-RandomUsername {
    $Prefix = "supervision-"
    $RandomSuffix = -join ((48..57) + (97..122) | Get-Random -Count 6 | ForEach-Object {[char]$_})
    return $Prefix + $RandomSuffix
}

# Fonction pour cr�er un compte local
function New-LocalSupervisionAccount {
    param (
        [string]$Username,
        [string]$Password
    )
    
    try {
        # V�rification si le compte existe d�j�
        $ExistingUser = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue
        if ($ExistingUser) {
            Write-Warning "Le compte $Username existe d�j�. Suppression du compte existant..."
            Remove-LocalUser -Name $Username -ErrorAction Stop
        }
        
        # Cr�ation du compte
        $SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
        $UserParams = @{
            Name = $Username
            Password = $SecurePassword
            PasswordNeverExpires = $true
            UserMayNotChangePassword = $true
            ErrorAction = 'Stop'
        }
        New-LocalUser @UserParams
        
        # Restreindre les droits d'acc�s
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
                    Write-Host "Utilisateur ajout� au groupe '$GroupName'" -ForegroundColor Green
                    $GroupFound = $true
                    break
                }
            }
            catch {
                Write-Debug "Groupe '$GroupName' non trouv�"
            }
        }
        
        if (-not $GroupFound) {
            Write-Warning "Aucun groupe Performance Log Users n'a �t� trouv�. Veuillez v�rifier manuellement l'appartenance au groupe."
        }
        
        # V�rification de l'appartenance au groupe
        $UserGroups = Get-LocalGroup | Where-Object { (Get-LocalGroupMember -Group $_).Name -contains "$env:COMPUTERNAME\$Username" }
        Write-Host "`nGroupes de l'utilisateur :" -ForegroundColor Cyan
        $UserGroups | ForEach-Object { Write-Host "- $($_.Name)" -ForegroundColor Yellow }
        
        Write-Host "`nCompte $Username cr�� avec succ�s." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Erreur lors de la cr�ation du compte : $_"
        return $false
    }
}

# Fonction pour g�n�rer une communaut� SNMP s�curis�e
function New-SecureSNMPCommunity {
    param (
        [int]$Length = 16
    )
    
    # D�finir les ensembles de caract�res
    $UpperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray()
    $LowerCase = "abcdefghijklmnopqrstuvwxyz".ToCharArray()
    $Numbers = "0123456789".ToCharArray()
    
    # Cr�er un tableau pour stocker les caract�res de la communaut�
    $CommunityChars = @()
    
    # Ajouter au moins un caract�re de chaque type
    $CommunityChars += $UpperCase | Get-Random -Count 1
    $CommunityChars += $LowerCase | Get-Random -Count 1
    $CommunityChars += $Numbers | Get-Random -Count 1
    
    # Cr�er un tableau avec tous les caract�res possibles
    $AllChars = $UpperCase + $LowerCase + $Numbers
    
    # Ajouter des caract�res al�atoires jusqu'� atteindre la longueur souhait�e
    $RemainingLength = $Length - 3
    $CommunityChars += $AllChars | Get-Random -Count $RemainingLength
    
    # M�langer le tableau de caract�res
    $CommunityChars = $CommunityChars | Get-Random -Count $CommunityChars.Count
    
    # Convertir en cha�ne
    return -join $CommunityChars
}

# Fonction pour configurer SNMP
function Set-SNMPConfiguration {
    param (
        [string]$Community,
        [string]$ProbeIP = "any"
    )
    
    try {
        # V�rifier si le service SNMP est install�
        $SNMPService = Get-Service -Name "SNMP" -ErrorAction SilentlyContinue
        if (-not $SNMPService) {
            Write-Host "Installation du service SNMP..." -ForegroundColor Yellow
            
            # D�tecter le type de syst�me d'exploitation
            $OSInfo = Get-WmiObject -Class Win32_OperatingSystem
            $IsServer = $OSInfo.ProductType -eq 2  # 2 = Server, 1 = Workstation
            
            if ($IsServer) {
                # Installation sur Windows Server
                Write-Host "Installation sur Windows Server..." -ForegroundColor Yellow
                $InstallResult = Install-WindowsFeature -Name "SNMP-Service" -IncludeManagementTools -ErrorAction Stop
                
                if ($InstallResult.RestartNeeded) {
                    Write-Host "Un red�marrage est n�cessaire pour terminer l'installation de SNMP." -ForegroundColor Yellow
                    Write-Host "Veuillez red�marrer le syst�me et relancer le script." -ForegroundColor Yellow
                    return $false
                }
            }
            else {
                # Installation sur Windows 10/11
                Write-Host "Installation sur Windows 10/11..." -ForegroundColor Yellow
                $InstallResult = Add-WindowsCapability -Online -Name "SNMP.Client~~~~0.0.1.0" -ErrorAction Stop
                
                if ($InstallResult.RestartNeeded) {
                    Write-Host "Un red�marrage est n�cessaire pour terminer l'installation de SNMP." -ForegroundColor Yellow
                    Write-Host "Veuillez red�marrer le syst�me et relancer le script." -ForegroundColor Yellow
                    return $false
                }
            }
            
            # Attendre que le service soit install�
            Write-Host "`nAttente de l'installation du service..." -ForegroundColor Yellow
            $Timeout = 30
            $Counter = 0
            while (-not (Get-Service -Name "SNMP" -ErrorAction SilentlyContinue) -and $Counter -lt $Timeout) {
                Start-Sleep -Seconds 1
                $Counter++
            }
            
            if ($Counter -ge $Timeout) {
                throw "Le service SNMP n'a pas �t� install� apr�s $Timeout secondes."
            }
        }
        
        # V�rifier si le service est maintenant disponible
        $SNMPService = Get-Service -Name "SNMP" -ErrorAction SilentlyContinue
        if (-not $SNMPService) {
            throw "Le service SNMP n'est pas disponible. Veuillez v�rifier que le composant est bien install�."
        }
        
        # Configurer la communaut� SNMP
        $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities"
        if (-not (Test-Path $RegPath)) {
            New-Item -Path $RegPath -Force | Out-Null
        }
        
        # Supprimer les anciennes communaut�s
        Remove-ItemProperty -Path $RegPath -Name * -ErrorAction SilentlyContinue
        
        # Ajouter la nouvelle communaut� avec droits en lecture seule
        New-ItemProperty -Path $RegPath -Name $Community -Value 4 -PropertyType DWORD -Force | Out-Null
        
        # Configurer les permissions d'acc�s
        $PermittedManagersPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"
        
        if ($ProbeIP -eq "any") {
            # Supprimer la cl� PermittedManagers pour autoriser toutes les IP
            if (Test-Path $PermittedManagersPath) {
                Remove-Item -Path $PermittedManagersPath -Recurse -Force
                Write-Host "Communaut� SNMP configur�e pour toutes les adresses IP." -ForegroundColor Green
            }
        }
        else {
            # Cr�er la cl� et ajouter l'IP sp�cifique
            if (-not (Test-Path $PermittedManagersPath)) {
                New-Item -Path $PermittedManagersPath -Force | Out-Null
            }
            New-ItemProperty -Path $PermittedManagersPath -Name "1" -Value $ProbeIP -PropertyType String -Force | Out-Null
            Write-Host "Communaut� SNMP configur�e pour l'adresse IP : $ProbeIP" -ForegroundColor Green
        }
        
        # Red�marrer le service SNMP
        Write-Host "Red�marrage du service SNMP..." -ForegroundColor Yellow
        Restart-Service -Name "SNMP" -Force -ErrorAction Stop
        
        Write-Host "Communaut� SNMP '$Community' configur�e avec succ�s." -ForegroundColor Green
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
        
        # V�rifier si la r�gle existe d�j�
        $ExistingRule = Get-NetFirewallRule -DisplayName "Autoriser le ping entrant" -ErrorAction SilentlyContinue
        
        if (-not $ExistingRule) {
            # Cr�er la r�gle pour autoriser le ping entrant
            New-NetFirewallRule -DisplayName "Autoriser le ping entrant" `
                               -Direction Inbound `
                               -Protocol ICMPv4 `
                               -IcmpType 8 `
                               -Action Allow `
                               -Enabled True `
                               -ErrorAction Stop
            
            Write-Host "R�gle de pare-feu cr��e pour autoriser le ping entrant." -ForegroundColor Green
        }
        else {
            # Activer la r�gle existante
            Set-NetFirewallRule -DisplayName "Autoriser le ping entrant" -Enabled True -ErrorAction Stop
            Write-Host "R�gle de pare-feu existante activ�e pour autoriser le ping entrant." -ForegroundColor Green
        }
        
        return $true
    }
    catch {
        Write-Error "Erreur lors de la configuration du pare-feu pour le ping : $_"
        return $false
    }
}

# Fonction pour activer une r�gle de pare-feu
function Enable-FirewallRule {
    param (
        [Parameter(Mandatory=$true)]
        [string]$RuleName
    )
    
    try {
        Write-Host "Activation de la r�gle de pare-feu '$RuleName'..." -ForegroundColor Yellow
        Enable-NetFirewallRule -DisplayName $RuleName -ErrorAction Stop
        Write-Host "R�gle de pare-feu '$RuleName' activ�e avec succ�s." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Erreur lors de l'activation de la r�gle de pare-feu '$RuleName' : $_"
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
        
        # Activer la r�gle de pare-feu WMI-IN
        Enable-FirewallRule -RuleName "Windows Management Instrumentation (WMI-In)"
        
        # Configurer les droits du Service Control Manager
        Write-Host "Configuration des droits du Service Control Manager..." -ForegroundColor Yellow
        $SCMCommand = 'sc.exe sdset SCMANAGER "D:(A;;CCLCRPRC;;;AU)(A;;CCLCRPWPRC;;;SY)(A;;KA;;;BA)S:(AU;FA;KA;;;WD)(AU;OIIOFA;GA;;;WD)"'
        $SCMResult = Invoke-Expression $SCMCommand
        
        if ($LASTEXITCODE -ne 0) {
            throw "�chec de la configuration des droits SCM. Code de sortie : $LASTEXITCODE"
        }
        
        # D�finir les constantes pour les droits WMI
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
        
        # Obtenir l'objet de s�curit� WMI
        $InvokeParams = @{
            Namespace = "root\cimv2"
            Path = "__systemsecurity=@"
        }
        
        $Output = Invoke-WmiMethod @InvokeParams -Name "GetSecurityDescriptor"
        if ($Output.ReturnValue -ne 0) {
            throw "�chec de GetSecurityDescriptor : $($Output.ReturnValue)"
        }
        
        $ACL = $Output.Descriptor
        
        # Obtenir le compte utilisateur
        $GetParams = @{
            Class = "Win32_Account"
            Filter = "Domain='$env:COMPUTERNAME' and Name='$Username'"
        }
        
        $Win32Account = Get-WmiObject @GetParams
        if ($null -eq $Win32Account) {
            throw "Compte non trouv� : $Username"
        }
        
        # Construire le masque d'acc�s avec tous les droits n�cessaires
        $AccessMask = $WBEM_ENABLE + $WBEM_METHOD_EXECUTE + $WBEM_REMOTE_ACCESS + $READ_CONTROL
        
        # Cr�er une nouvelle entr�e ACE
        $ACE = (New-Object System.Management.ManagementClass("Win32_Ace")).CreateInstance()
        $ACE.AccessMask = $AccessMask
        $ACE.AceFlags = $CONTAINER_INHERIT_ACE_FLAG
        
        # Configurer le trustee
        $Trustee = (New-Object System.Management.ManagementClass("Win32_Trustee")).CreateInstance()
        $Trustee.SidString = $Win32Account.SID
        $ACE.Trustee = $Trustee
        $ACE.AceType = $ACCESS_ALLOWED_ACE_TYPE
        
        # Ajouter la nouvelle ACE � la DACL existante
        $ACL.DACL += $ACE
        
        # Appliquer les modifications
        $SetParams = @{
            Name = "SetSecurityDescriptor"
            ArgumentList = $ACL
        } + $InvokeParams
        
        $Output = Invoke-WmiMethod @SetParams
        if ($Output.ReturnValue -ne 0) {
            throw "�chec de SetSecurityDescriptor : $($Output.ReturnValue)"
        }
        
        Write-Host "Autorisations WMI configur�es avec succ�s pour $Username." -ForegroundColor Green
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
        
        # Ex�cuter la configuration rapide de WinRM
        $Result = winrm quickconfig -quiet -force
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "WinRM configur� avec succ�s." -ForegroundColor Green
            return $true
        }
        else {
            throw "�chec de la configuration WinRM. Code de sortie : $LASTEXITCODE"
        }
    }
    catch {
        Write-Error "Erreur lors de la configuration WinRM : $_"
        return $false
    }
}

# Fonction principale
function Initialize-Supervision {
    # G�n�ration des identifiants
    $Username = New-RandomUsername
    $Password = New-ComplexPassword
    $SNMPCommunity = New-SecureSNMPCommunity
    
    Write-Host "Configuration de la supervision pour $env:COMPUTERNAME" -ForegroundColor Cyan
    Write-Host "Nom d'utilisateur g�n�r� : $Username" -ForegroundColor Yellow
    Write-Host "Mot de passe g�n�r� : $Password" -ForegroundColor Yellow
    Write-Host "Communaut� SNMP g�n�r�e : $SNMPCommunity" -ForegroundColor Yellow
    
    # Demande de confirmation � l'utilisateur
    Write-Host "`nVeuillez sauvegarder ces identifiants avant de continuer." -ForegroundColor Yellow
    $Confirmation = Read-Host "Avez-vous sauvegard� les identifiants et souhaitez-vous continuer ? (O/N)"
    
    if ($Confirmation -ne "O") {
        Write-Host "Op�ration annul�e par l'utilisateur." -ForegroundColor Red
        exit
    }
    
    # Cr�ation du compte
    if (New-LocalSupervisionAccount -Username $Username -Password $Password) {
        Write-Host "`nCompte cr�� avec succ�s." -ForegroundColor Green
    }
    else {
        Write-Host "`nLa cr�ation du compte a �chou�. Veuillez v�rifier les messages d'erreur ci-dessus." -ForegroundColor Red
        exit
    }
    
    # Configuration SNMP
    if (Set-SNMPConfiguration -Community $SNMPCommunity) {
        Write-Host "Configuration SNMP termin�e avec succ�s." -ForegroundColor Green
    }
    else {
        Write-Host "`nLa configuration SNMP a �chou�. Veuillez v�rifier les messages d'erreur ci-dessus." -ForegroundColor Red
    }
    
    # Autorisation du ping
    if (Enable-ICMPEchoRequest) {
        Write-Host "Configuration du ping termin�e avec succ�s." -ForegroundColor Green
    }
    else {
        Write-Host "`nLa configuration du ping a �chou�. Veuillez v�rifier les messages d'erreur ci-dessus." -ForegroundColor Red
    }
    
    # Configuration des autorisations WMI
    if (Set-WMIPermissions -Username $Username) {
        Write-Host "Configuration WMI termin�e avec succ�s." -ForegroundColor Green
    }
    else {
        Write-Host "`nLa configuration WMI a �chou�. Veuillez v�rifier les messages d'erreur ci-dessus." -ForegroundColor Red
    }
    
    # Configuration WinRM
    if (Set-WinRMConfiguration) {
        Write-Host "Configuration WinRM termin�e avec succ�s." -ForegroundColor Green
    }
    else {
        Write-Host "`nLa configuration WinRM a �chou�. Veuillez v�rifier les messages d'erreur ci-dessus." -ForegroundColor Red
    }
    
    # TODO: Impl�menter les autres fonctionnalit�s
    # - Configuration des droits
}

# D�marrage du script
Initialize-Supervision

# Pause � la fin du script
Write-Host "`nAppuyez sur une touche pour quitter..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
