
[CmdletBinding()]
param (

    [string]
    # Path to the configuration file stating which charts should be deployed
    $path = $env:HELM_CHARTS,

    [string[]]
    # Names of charts that should be deployed.
    # This does not override the enabled flag, but allows a subset of enabled chartts
    # to be deployed
    $names,

    [string]
    # Path to temporary directory for writing out templates
    $tempdir = "tmp/",

    [string]
    # Cloud provider being targeted
    $provider = $env:CLOUD_PLATFORM,

    [string]
    [Alias("resourcegroup")]
    # Identifier for finding the cluster
    # In the case of Azure this is the resource group name
    $identifier,

    [string]
    [Alias("aksname")]
    # Name of the cluster
    $clustername,

    [switch]
    # Specify a dryrun, which will output the helm command to run
    $dryrun
)

# Set defaults on undefined parameters
if ([String]::IsNullOrEmpty($path)) {
    $path = [IO.Path]::Join("deploy", "helm", "k8s_apps.yml")
}

# Check to see if the path exists
if (!(Test-Path -Path $path)) {
    Write-Error ("Specified file cannot be located: {0}" -f $path)
    return
}

# Determine if the tempdir path exists, if not create it
if (!(Test-Path -Path $tempdir)) {
    Write-Information ("Creating temporary dir: {0}" -f $tempdir)
    New-Item -Type Directory -Path $tempdir | Out-Null
}

# Read in the configuration, replacing parameters as necessary
$template_name = Split-Path -Path $path -Leaf
$target = [IO.Path]::Join($tempdir, $template_name)

# Expand the template for the values
$template = Get-Content -Path $path -Raw
if ([String]::IsNullOrEmpty($template)) {
    New-Item -Type File -Path $target -Force | Out-Null
} else {
    Expand-Template -Template $template -Target $target
}

$helm = Get-Content -Path $target -Raw | ConvertFrom-Yaml

Write-Host $(Get-Content -Path $target -Raw)

# Iterate around all the charts in the object
foreach ($chart in $helm.charts) {

    # if any names have been specified only run if the current chart is in that list
    if ($names.length -gt 0 -and $names -notcontains $chart.name) {
        Write-Warning -Message ("Skipping chart due to names list: {0} not in [{1}]" -f $chart.name, ($names -join ","))
    }

    # Skip the chart if not enabled
    if (!$chart.enabled) {
        Write-Warning -Message ("Chart is not enabled, skpping: {0}" -f $chart.name)
        continue
    }

    # Skip chart if it is not for this current cloud platform
    if ($chart.clouds.length -gt 0 -and $chart.clouds -notcontains $env:CLOUD_PLATFORM) {
        Write-Warning -Message ("Chart is not for this cloud platform: {0}" -f $env:CLOUD_PLATFORM)
        continue
    }

    # Check if the values_template file exists
    if (![String]::IsNullOrEmpty($chart.values_template) -and !(Test-Path -Path $chart.values_template)) {
        Write-Warning -Message ("Values template file cannnot be found: {0}" -f $chart.values_template)
        continue
    }

    $namespace = "default"
    if (![String]::IsNullOrEmpty($chart.namespace)) {
        $namespace = $chart.namespace
    }

    # Configure an array to hold the pareameters for the helm cmdlet
    $helm_args = @()
    $helm_args += "-install"
    $helm_args += "-chartpath `"{0}/{1}`"" -f $chart.location, $chart.name
    $helm_args += "-identifier {0}" -f $identifier
    $helm_args += "-target {0}" -f $clustername
    $helm_args += "-namespace {0}" -f $namespace
    $helm_args += "-provider {0}" -f $provider

    # Determine the release name
    $release_name = $chart.release_name
    if ([String]::IsNullOrEmpty($release_name)) {
        $release_name = $chart.name
    }
    $release_name = ($release_name -replace " |_", "-").ToLower()
    $helm_args += "-releasename {0}" -f $release_name

    # Determime the path for the rendered template
    # Only if a values template has been specified
    if (![String]::IsNullOrEmpty($chart.values_template)) {
        $template_name = Split-Path -Path $chart.values_template -Leaf
        $target = [IO.Path]::Join($tempdir, $template_name)

        # Expand the template for the values
        $template = Get-Content -Path $chart.values_template -Raw
        if ([String]::IsNullOrEmpty($template)) {
            New-Item -Type File -Path $target -Force | Out-Null
        } else {
            Expand-Template -Template $template -Target $target
        }

        $helm_args += "-valuepath {0}" -f $target
    }

    # If a repo has been set, run the command to add the repo to helm
    if (![String]::IsNullOrEmpty($chart.repo)) {
        $command = @"
Invoke-Helm -custom -arguments "repo add {0} {1}" -target foobar -provider azure -identifier foobar -namespace foobar -releasename foobar
"@ -f $chart.name, $chart.repo

        if ($dryrun) {
            Write-Host $command
        } else {
            Invoke-Expression $command
        }
    }

    # Build up the command to run
    $command = "Invoke-Helm {0}" -f ($helm_args -join " ")

    if ($dryrun) {
        Write-Host $command
    } else {
        Invoke-Expression $command
    }
}
