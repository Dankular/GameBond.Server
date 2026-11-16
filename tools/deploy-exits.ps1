param(
    [string]$ImageTag,
    [string]$SshKeyPath = (Join-Path $env:USERPROFILE 'Desktop\privkey.ppk')
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
        HostKey = ''
    },
    [pscustomobject]@{
        Name = 'Apps'
        Host = '138.199.201.16'
        Project = 'gamebond-native'
        WorkDir = '/opt/gamebond/releases/native-live'
        Service = 'server'
        Container = 'gamebond-native-1'
        HostKey = $AppsHostKey
    },
    [pscustomobject]@{
        Name = 'sw01'
        Host = '195.154.119.136'
        Project = 'gamebond-native'
        WorkDir = '/opt/gamebond/releases/native-live'
        Service = 'server'
        Container = 'gamebond-native-1'
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
    $output = & $PlinkPath @plinkArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
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
    $output = & $PscpPath @pscpArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "$($Node.Name) file staging failed: $($output -join ' ')"
    }
}

function Copy-FromNode {
    param($Node, [string]$RemotePath, [string]$LocalPath)

    $pscpArgs = @('-batch', '-i', $SshKeyPath)
    if ($Node.HostKey) { $pscpArgs += @('-hostkey', $Node.HostKey) }
    $pscpArgs += "root@$($Node.Host):$RemotePath"
    $pscpArgs += $LocalPath
    $output = & $PscpPath @pscpArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "$($Node.Name) file retrieval failed: $($output -join ' ')"
    }
}

$RemoteDeployCode = @'
import json, os, pathlib, shutil, stat, subprocess, sys, tempfile, time

name, project, work, service, container, auth_file, image = sys.argv[1:]
compose_file = os.path.join(work, "compose.yaml")
env_file = os.path.join(work, "deploy.env")
compose = ["docker", "compose", "--project-name", project, "--env-file", env_file, "-f", compose_file]
auth_dir = tempfile.mkdtemp(prefix="gb-registry-")
old_env = None
changed_env = False

def run(args, **kwargs):
    kwargs.setdefault("stdout", subprocess.PIPE)
    kwargs.setdefault("stderr", subprocess.STDOUT)
    completed = subprocess.run(args, check=True, text=True, **kwargs)
    if completed.stdout:
        print(completed.stdout, end="")
    return completed

def write_atomic(path, data, old_stat):
    fd, temp_path = tempfile.mkstemp(prefix=".gb-deploy-", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temp_path, stat.S_IMODE(old_stat.st_mode))
        os.chown(temp_path, old_stat.st_uid, old_stat.st_gid)
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

try:
    details = json.loads(subprocess.check_output(["docker", "inspect", container], text=True))[0]
    labels = details["Config"].get("Labels") or {}
    if labels.get("com.docker.compose.project") != project or labels.get("com.docker.compose.service") != service:
        raise RuntimeError("live container Compose labels do not match the configured target")
    if labels.get("com.docker.compose.project.working_dir") != work:
        raise RuntimeError("live container Compose work directory does not match the configured target")

    current_health = (details["State"].get("Health") or {}).get("Status", details["State"].get("Status", "unknown"))
    current_env = pathlib.Path(env_file).read_text(encoding="utf-8")
    if details["Config"].get("Image") == image and current_health == "healthy" and "GAMEBOND_IMAGE=" + image in current_env.splitlines():
        print(json.dumps({"host": name, "image": image, "image_id": details["Image"], "health": current_health, "skipped": True}))
        sys.exit(0)

    os.chmod(auth_file, 0o600)
    shutil.copyfile(auth_file, os.path.join(auth_dir, "config.json"))
    os.chmod(os.path.join(auth_dir, "config.json"), 0o600)
    pull_env = os.environ.copy()
    pull_env["DOCKER_CONFIG"] = auth_dir
    run(["docker", "pull", image], env=pull_env)

    run(compose + ["config", "--quiet"])
    old_env = pathlib.Path(env_file).read_bytes()
    env_stat = os.stat(env_file)
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
except Exception:
    if changed_env and old_env is not None:
        try:
            env_stat = os.stat(env_file)
            write_atomic(env_file, old_env, env_stat)
            subprocess.run(compose + ["up", "-d", "--no-deps", "--force-recreate", service], cwd=work,
                           check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    raise
finally:
    try:
        os.unlink(auth_file)
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

        $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($RemoteDeployCode))
        $remoteCommand = "printf '%s' '$payload' | base64 -d | python3 - '$($node.Name)' '$($node.Project)' '$($node.WorkDir)' '$($node.Service)' '$($node.Container)' '$remoteAuth' '$Image'"
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
    if ((Test-Path -LiteralPath $TempRoot) -and -not (Get-ChildItem -LiteralPath $TempRoot -Force | Select-Object -First 1)) {
        Remove-Item -LiteralPath $TempRoot -Force
    }
}
