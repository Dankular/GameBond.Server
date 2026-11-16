param(
    [string]$ImageTag,
    [string]$SshKeyPath = (Join-Path $env:USERPROFILE 'Desktop\privkey.ppk'),
    [switch]$EnableBackbone
)

$ErrorActionPreference = 'Stop'
# Docker Compose and PuTTY write routine progress to stderr. PowerShell 7 can
# promote native stderr lines to terminating errors when this preference is on.
$PSNativeCommandUseErrorActionPreference = $false

$PlinkPath = 'C:\Program Files (x86)\PuTTY\plink.exe'
$PscpPath = 'C:\Program Files (x86)\PuTTY\pscp.exe'
$AppsHostKey = 'ssh-ed25519 255 SHA256:aEUdaCw8C09l+TUWYKqOgf05ty6ojqKueAZ65lK3UwI'
$RegistryConfigOnApps = '/root/.docker/config.json'
$ImageName = 'gitea.app.khosa.co/dan/gamebond-server'
$Nodes = @(
    [pscustomobject]@{
        Name = 'IONOS'
        Host = '194.164.124.139'
        Project = 'gamebond-exit'
        WorkDir = '/opt/gamebond/releases/exit-64b7d7a'
        Service = 'server'
        Container = 'gamebond-exit-server-1'
        ConfigPath = '/opt/gamebond/releases/exit-64b7d7a/configs/server.json'
        BackboneConfig = 'backbone/ionos.json'
        BackbonePeerIPs = @('138.199.201.16', '195.154.119.136')
        HostKey = ''
    },
    [pscustomobject]@{
        Name = 'Apps'
        Host = '138.199.201.16'
        Project = 'gamebond-native'
        WorkDir = '/opt/gamebond/releases/native-live'
        Service = 'server'
        Container = 'gamebond-native-1'
        ConfigPath = '/opt/gamebond/releases/native-live/configs/local-server.json'
        BackboneConfig = 'backbone/apps.json'
        BackbonePeerIPs = @('194.164.124.139', '195.154.119.136')
        HostKey = $AppsHostKey
    },
    [pscustomobject]@{
        Name = 'sw01'
        Host = '195.154.119.136'
        Project = 'gamebond-native'
        WorkDir = '/opt/gamebond/releases/native-live'
        Service = 'server'
        Container = 'gamebond-native-1'
        ConfigPath = '/opt/gamebond/releases/native-live/configs/local-server.json'
        BackboneConfig = 'backbone/sw01.json'
        BackbonePeerIPs = @('194.164.124.139', '138.199.201.16')
        HostKey = ''
    }
)

if (-not (Test-Path -LiteralPath $PlinkPath) -or -not (Test-Path -LiteralPath $PscpPath)) {
    throw 'PuTTY plink.exe and pscp.exe are required.'
}
if (-not (Test-Path -LiteralPath $SshKeyPath)) {
    throw "SSH key not found: $SshKeyPath"
}

if ([string]::IsNullOrWhiteSpace($ImageTag)) {
    $ImageTag = (& git -C (Join-Path $PSScriptRoot '..') rev-parse --verify HEAD).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Could not resolve the current GameBond.Server commit.' }
}
if ($ImageTag -notmatch '^[0-9a-f]{40}$') {
    throw 'ImageTag must be a 40-character Gitea commit SHA.'
}
$Image = "$ImageName`:$ImageTag"

if ($EnableBackbone) {
    $localOverlay = Join-Path $PSScriptRoot '..\compose.backbone.legacy.yaml'
    $localFirewallTemplate = Join-Path $PSScriptRoot 'backbone\firewall-apply.sh'
    $localFirewallUnit = Join-Path $PSScriptRoot 'backbone\firewall.service'
    if (-not (Test-Path -LiteralPath $localOverlay) -or -not (Test-Path -LiteralPath $localFirewallTemplate) -or -not (Test-Path -LiteralPath $localFirewallUnit)) {
        throw 'Backbone overlay or firewall files are missing.'
    }
    foreach ($node in $Nodes) {
        $localConfig = Join-Path $PSScriptRoot $node.BackboneConfig
        if (-not (Test-Path -LiteralPath $localConfig)) {
            throw "Backbone configuration file is missing for $($node.Name): $localConfig"
        }
        $null = Get-Content -Raw -LiteralPath $localConfig | ConvertFrom-Json
    }
}

$TempRoot = Join-Path ([IO.Path]::GetTempPath()) "gamebond-deploy-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $TempRoot | Out-Null
$AuthLocal = Join-Path $TempRoot 'registry-config.json'
$DeployResults = @()

function Invoke-Plink {
    param($Node, [string]$RemoteCommand)

    $plinkArgs = @('-batch', '-i', $SshKeyPath)
    if ($Node.HostKey) { $plinkArgs += @('-hostkey', $Node.HostKey) }
    $plinkArgs += "root@$($Node.Host)"
    $plinkArgs += $RemoteCommand
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & $PlinkPath @plinkArgs 2>&1
        $nativeExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($nativeExitCode -ne 0) {
        throw "$($Node.Name) SSH command failed: $($output -join ' ')"
    }
    return ($output -join "`n").Trim()
}

function Copy-ToNode {
    param($Node, [string]$LocalPath, [string]$RemotePath)

    $pscpArgs = @('-batch', '-i', $SshKeyPath)
    if ($Node.HostKey) { $pscpArgs += @('-hostkey', $Node.HostKey) }
    $pscpArgs += $LocalPath
    $pscpArgs += "root@$($Node.Host):$RemotePath"
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & $PscpPath @pscpArgs 2>&1
        $nativeExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($nativeExitCode -ne 0) {
        throw "$($Node.Name) file staging failed: $($output -join ' ')"
    }
}

function Copy-FromNode {
    param($Node, [string]$RemotePath, [string]$LocalPath)

    $pscpArgs = @('-batch', '-i', $SshKeyPath)
    if ($Node.HostKey) { $pscpArgs += @('-hostkey', $Node.HostKey) }
    $pscpArgs += "root@$($Node.Host):$RemotePath"
    $pscpArgs += $LocalPath
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & $PscpPath @pscpArgs 2>&1
        $nativeExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($nativeExitCode -ne 0) {
        throw "$($Node.Name) file retrieval failed: $($output -join ' ')"
    }
}

$RemoteDeployCode = @'
import json, os, pathlib, shutil, stat, subprocess, sys, tempfile, time

name, project, work, service, container, auth_file, image, config_path, backbone_file, overlay_file, firewall_file, unit_file = sys.argv[1:]
compose_file = os.path.join(work, "compose.yaml")
env_file = os.path.join(work, "deploy.env")
compose = ["docker", "compose", "--project-name", project, "--env-file", env_file, "-f", compose_file]
overlay_target = os.path.join(work, "compose.backbone.legacy.yaml")
backbone_enabled = bool(config_path)
if backbone_enabled:
    compose += ["-f", overlay_target]
auth_dir = tempfile.mkdtemp(prefix="gb-registry-")
old_env = None
changed_env = False
old_config = None
old_overlay = None
overlay_existed = False
changed_backbone = False
old_backbone_active = False
firewall_active = False
old_firewall_script = None
old_firewall_unit = None
firewall_script_existed = False
firewall_unit_existed = False
changed_firewall = False

def run(args, **kwargs):
    kwargs.setdefault("stdout", subprocess.PIPE)
    kwargs.setdefault("stderr", subprocess.STDOUT)
    completed = subprocess.run(args, check=True, text=True, **kwargs)
    if completed.stdout:
        print(completed.stdout, end="")
    return completed

def write_atomic(path, data, old_stat=None, default_mode=0o644):
    fd, temp_path = tempfile.mkstemp(prefix=".gb-deploy-", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temp_path, stat.S_IMODE(old_stat.st_mode) if old_stat else default_mode)
        os.chown(temp_path, old_stat.st_uid if old_stat else 0, old_stat.st_gid if old_stat else 0)
        os.replace(temp_path, path)
    except Exception:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise

def set_image_value(contents, image):
    lines = contents.decode("utf-8").splitlines()
    matches = [i for i, line in enumerate(lines) if line.startswith("GAMEBOND_IMAGE=")]
    if len(matches) != 1:
        raise RuntimeError("deploy.env must contain exactly one GAMEBOND_IMAGE entry")
    lines[matches[0]] = "GAMEBOND_IMAGE=" + image
    return ("\n".join(lines) + "\n").encode("utf-8")

def set_backbone_value(contents, backbone):
    config = json.loads(contents)
    config["exit_backbone"] = backbone
    return (json.dumps(config, indent=2) + "\n").encode("utf-8")

try:
    details = json.loads(subprocess.check_output(["docker", "inspect", container], text=True))[0]
    labels = details["Config"].get("Labels") or {}
    if labels.get("com.docker.compose.project") != project or labels.get("com.docker.compose.service") != service:
        raise RuntimeError("live container Compose labels do not match the configured target")
    if labels.get("com.docker.compose.project.working_dir") != work:
        raise RuntimeError("live container Compose work directory does not match the configured target")

    current_health = (details["State"].get("Health") or {}).get("Status", details["State"].get("Status", "unknown"))
    current_env = pathlib.Path(env_file).read_text(encoding="utf-8")
    already_configured = not backbone_enabled
    if backbone_enabled:
        current_config = json.loads(pathlib.Path(config_path).read_text(encoding="utf-8"))
        requested_backbone = json.loads(pathlib.Path(backbone_file).read_text(encoding="utf-8"))
        ports = details.get("NetworkSettings", {}).get("Ports") or {}
        expected_ports = all(ports.get(port) for port in ("51820/udp", "51821/udp"))
        firewall_active = subprocess.run(["systemctl", "is-active", "--quiet", "gamebond-backbone-firewall.service"]).returncode == 0
        overlay_matches = os.path.isfile(overlay_target) and pathlib.Path(overlay_target).read_bytes() == pathlib.Path(overlay_file).read_bytes()
        firewall_matches = os.path.isfile("/usr/local/sbin/gamebond-backbone-firewall") and pathlib.Path("/usr/local/sbin/gamebond-backbone-firewall").read_bytes() == pathlib.Path(firewall_file).read_bytes()
        old_backbone_active = current_config.get("exit_backbone") is not None or expected_ports or firewall_active
        already_configured = current_config.get("exit_backbone") == requested_backbone and overlay_matches and firewall_matches and expected_ports and firewall_active
    if details["Config"].get("Image") == image and current_health == "healthy" and "GAMEBOND_IMAGE=" + image in current_env.splitlines() and already_configured:
        print(json.dumps({"host": name, "image": image, "image_id": details["Image"], "health": current_health, "skipped": True}))
        sys.exit(0)

    os.chmod(auth_file, 0o600)
    shutil.copyfile(auth_file, os.path.join(auth_dir, "config.json"))
    os.chmod(os.path.join(auth_dir, "config.json"), 0o600)
    pull_env = os.environ.copy()
    pull_env["DOCKER_CONFIG"] = auth_dir
    run(["docker", "pull", image], env=pull_env)

    old_env = pathlib.Path(env_file).read_bytes()
    env_stat = os.stat(env_file)

    if backbone_enabled:
        old_config = pathlib.Path(config_path).read_bytes()
        config_stat = os.stat(config_path)
        requested_backbone = json.loads(pathlib.Path(backbone_file).read_text(encoding="utf-8"))
        write_atomic(config_path, set_backbone_value(old_config, requested_backbone), config_stat)
        changed_backbone = True
        overlay_existed = os.path.exists(overlay_target)
        overlay_stat = os.stat(overlay_target) if overlay_existed else None
        if overlay_existed:
            old_overlay = pathlib.Path(overlay_target).read_bytes()
        write_atomic(overlay_target, pathlib.Path(overlay_file).read_bytes(), overlay_stat, 0o644)

        firewall_target = "/usr/local/sbin/gamebond-backbone-firewall"
        unit_target = "/etc/systemd/system/gamebond-backbone-firewall.service"
        os.makedirs(os.path.dirname(firewall_target), exist_ok=True)
        os.makedirs(os.path.dirname(unit_target), exist_ok=True)
        firewall_script_existed = os.path.exists(firewall_target)
        firewall_unit_existed = os.path.exists(unit_target)
        if firewall_script_existed:
            old_firewall_script = pathlib.Path(firewall_target).read_bytes()
        if firewall_unit_existed:
            old_firewall_unit = pathlib.Path(unit_target).read_bytes()
        shutil.copyfile(firewall_file, firewall_target)
        os.chmod(firewall_target, 0o755)
        shutil.copyfile(unit_file, unit_target)
        os.chmod(unit_target, 0o644)
        changed_firewall = True
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "enable", "--now", "gamebond-backbone-firewall.service"])
        run(["systemctl", "restart", "gamebond-backbone-firewall.service"])

    run(compose + ["config", "--quiet"])
    new_env = set_image_value(old_env, image)
    write_atomic(env_file, new_env, env_stat)
    changed_env = True

    run(compose + ["up", "-d", "--no-deps", "--force-recreate", service], cwd=work)
    container_id = subprocess.check_output(compose + ["ps", "-q", service], cwd=work, text=True).strip()
    if not container_id:
        raise RuntimeError("Compose returned no container ID")

    health = "starting"
    for _ in range(45):
        current = json.loads(subprocess.check_output(["docker", "inspect", container_id], text=True))[0]
        state = current["State"]
        health = (state.get("Health") or {}).get("Status", state.get("Status", "unknown"))
        if health == "healthy":
            break
        if state.get("Status") in ("exited", "dead"):
            raise RuntimeError("container entered " + state["Status"])
        time.sleep(2)
    if health != "healthy":
        raise RuntimeError("container health timed out: " + health)

    current = json.loads(subprocess.check_output(["docker", "inspect", container_id], text=True))[0]
    if current["Config"]["Image"] != image:
        raise RuntimeError("running container image does not match requested image")
    print(json.dumps({"host": name, "image": image, "image_id": current["Image"], "health": health}))
except Exception as error:
    print("DEPLOY_ERROR: " + repr(error))
    failed_id = locals().get("container_id")
    if failed_id:
        try:
            failed_logs = subprocess.run(["docker", "logs", "--tail", "40", failed_id], stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, text=True, check=False).stdout
            for line in failed_logs.splitlines():
                if any(word in line.lower() for word in ("error", "failed", "backbone", "wireguard", "bgp", "frr")):
                    print("CONTAINER_LOG: " + line[:1800])
        except Exception as log_error:
            print("CONTAINER_LOG_ERROR: " + repr(log_error))
    if (changed_env and old_env is not None) or (changed_backbone and old_config is not None) or changed_firewall:
        try:
            if changed_env and old_env is not None:
                write_atomic(env_file, old_env, os.stat(env_file))
            rollback_compose = compose
            if changed_backbone and old_config is not None:
                write_atomic(config_path, old_config, os.stat(config_path))
                if overlay_existed and old_backbone_active:
                    write_atomic(overlay_target, old_overlay, os.stat(overlay_target))
                else:
                    try:
                        os.unlink(overlay_target)
                    except FileNotFoundError:
                        pass
                    rollback_compose = compose[:-2]
            if changed_firewall:
                if not firewall_active:
                    subprocess.run(["systemctl", "disable", "--now", "gamebond-backbone-firewall.service"], check=False,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(["/usr/local/sbin/gamebond-backbone-firewall", "--remove"], check=False,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if firewall_script_existed:
                    write_atomic("/usr/local/sbin/gamebond-backbone-firewall", old_firewall_script, default_mode=0o755)
                else:
                    pathlib.Path("/usr/local/sbin/gamebond-backbone-firewall").unlink(missing_ok=True)
                if firewall_unit_existed:
                    write_atomic("/etc/systemd/system/gamebond-backbone-firewall.service", old_firewall_unit, default_mode=0o644)
                else:
                    pathlib.Path("/etc/systemd/system/gamebond-backbone-firewall.service").unlink(missing_ok=True)
                subprocess.run(["systemctl", "daemon-reload"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if firewall_active:
                    subprocess.run(["systemctl", "restart", "gamebond-backbone-firewall.service"], check=False,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(rollback_compose + ["up", "-d", "--no-deps", "--force-recreate", service], cwd=work,
                           check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    raise
finally:
    for path in (auth_file, backbone_file, overlay_file, firewall_file, unit_file):
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass
    shutil.rmtree(auth_dir, ignore_errors=True)
'@

try {
    # Apps is already authorized for the private Gitea registry. Stage its Docker
    # auth file only for the duration of this rollout; the script never prints it.
    Copy-FromNode $Nodes[1] $RegistryConfigOnApps $AuthLocal

    foreach ($node in $Nodes) {
        Write-Host "Deploying $Image to $($node.Name)"
        $nonce = [guid]::NewGuid().ToString('N')
        $remoteAuth = "/tmp/gb-registry-$nonce.json"
        Copy-ToNode $node $AuthLocal $remoteAuth

        $remoteConfig = ''
        $remoteOverlay = ''
        $remoteConfigPath = ''
        $remoteFirewall = ''
        $remoteFirewallUnit = ''
        if ($EnableBackbone) {
            $localConfig = Join-Path $PSScriptRoot $node.BackboneConfig
            $remoteConfig = "/tmp/gb-backbone-$nonce.json"
            $remoteOverlay = "/tmp/gb-backbone-overlay-$nonce.yaml"
            $remoteFirewall = "/tmp/gb-backbone-firewall-$nonce.sh"
            $remoteFirewallUnit = "/tmp/gb-backbone-firewall-$nonce.service"
            $remoteConfigPath = $node.ConfigPath
            $localFirewall = Join-Path $TempRoot "firewall-$($node.Name).sh"
            $localFirewallUnitPrepared = Join-Path $TempRoot "firewall-$($node.Name).service"
            $firewallText = (Get-Content -Raw -LiteralPath $localFirewallTemplate).Replace('__PEER_IPS__', ($node.BackbonePeerIPs -join ' ')).Replace('__LOCAL_PUBLIC_IP__', $node.Host).Replace("`r`n", "`n").Replace("`r", "`n")
            $unitText = (Get-Content -Raw -LiteralPath $localFirewallUnit).Replace("`r`n", "`n").Replace("`r", "`n")
            [System.IO.File]::WriteAllText($localFirewall, $firewallText, [System.Text.UTF8Encoding]::new($false))
            [System.IO.File]::WriteAllText($localFirewallUnitPrepared, $unitText, [System.Text.UTF8Encoding]::new($false))
            Copy-ToNode $node $localConfig $remoteConfig
            Copy-ToNode $node $localOverlay $remoteOverlay
            Copy-ToNode $node $localFirewall $remoteFirewall
            Copy-ToNode $node $localFirewallUnitPrepared $remoteFirewallUnit
        }

        $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($RemoteDeployCode))
        $remoteCommand = "printf '%s' '$payload' | base64 -d | python3 - '$($node.Name)' '$($node.Project)' '$($node.WorkDir)' '$($node.Service)' '$($node.Container)' '$remoteAuth' '$Image' '$remoteConfigPath' '$remoteConfig' '$remoteOverlay' '$remoteFirewall' '$remoteFirewallUnit'"
        $output = Invoke-Plink $node $remoteCommand
        $summaryLine = @($output -split "`r?`n" | Where-Object { $_.Trim().StartsWith('{') } | Select-Object -Last 1)
        if (-not $summaryLine) { throw "$($node.Name) deploy did not return a summary: $output" }
        $summary = $summaryLine[0] | ConvertFrom-Json
        $DeployResults += $summary
        Write-Host "$($summary.host): $($summary.image) ($($summary.health))"
    }

    $imageIds = @($DeployResults | Select-Object -ExpandProperty image_id | Sort-Object -Unique)
    if ($DeployResults.Count -ne $Nodes.Count -or $imageIds.Count -ne 1) {
        throw 'Rollout incomplete or deployed image IDs differ.'
    }

    $DeployResults | ConvertTo-Json -Depth 4
}
finally {
    if (Test-Path -LiteralPath $AuthLocal) { Remove-Item -LiteralPath $AuthLocal -Force }
    if (Test-Path -LiteralPath $TempRoot) {
        Get-ChildItem -LiteralPath $TempRoot -File -Force | Remove-Item -Force
        if (-not (Get-ChildItem -LiteralPath $TempRoot -Force | Select-Object -First 1)) {
            Remove-Item -LiteralPath $TempRoot -Force
        }
    }
}
