function Get-AuthHeader() {

    <#
    
    .SYNOPSIS
    Generates the correct authentication string to be used in the header
    
    #>

    [CmdletBinding()]
    param (

        [string]
        # Authentication type
        $authType = "basic",

        [securestring]
        # Credentials to be configured
        $credentials,

        [switch]
        # State if to base64 encode the string
        $encode
    )

    $authstr = "Authorization:"

    # switch based on the AuthType and setup the string to pass back
    switch ($authType) {

        "bearer" {
            $authstr += " Bearer"
        }

        default {
            $authstr += " Basic"
        }
    }

    # Create a base64 encoded string of the credentials that have been passed
    $creds = $credentials | ConvertFrom-SecureString -AsPlainText

    if ($encode.IsPresent) {

        $credentialsBytes = [System.Text.Encoding]::Unicode.GetBytes($creds)

        # Encode string content to Base64 string
        $credentialsEncoded =[Convert]::ToBase64String($credentialsBytes)

        # append the credentals onto the end of the authstr
        $authstr += " {0}" -f $credentialsEncoded
    } else {
        $authstr += " {0}" -f $creds
    }

    return $authstr
}
function Invoke-API() {

    <#
    
    .SYNOPSIS
    Internal function to call APIs for endpoints. It uses the Invoke-WebRequest cmdlet

    .DESCRIPTION
    The Amido-Build module has support for publishing content to Wikis via APIs, this cmdlet
    uses the Invoke-WebRequest cmdlet to configure the authentication headers and call
    the API based on the supplied host and path along with the necessary body
    
    #>

    [CmdletBinding()]
    param (

        [string]
        # Method that is to be used
        $method = "GET",

        [string]
        # url to be used to call the endpoint
        $url,

        [Alias("token")]
        [string]
        # Username to be used to connect to the API
        $credentials = [String]::Empty,

        [string]
        # Authentication type, default is basic
        $authType = "basic",

        [string]
        # Content type for the API call
        $contentType = "application/json",

        [string]
        # Body to be passed to the API call
        $body = "",

        [hashtable]
        # Form data to be posted,
        $formData = @{},

        [hashtable]
        # Headers that should be added to the request
        $headers
    )

    # Create a hash of the parameters to pass to Invoke-WebRequest
    $splat = @{
        method = $method
        uri = $url
        contentType = $contentType
        erroraction = "silentlycontinue"
        headers = @{}
    }

    # if headers have been supplied add them to the splat
    if ($headers.count -gt 0) {
        $splat.headers = $headers
    }

    # only set the authentication in the splat if credentials have been supploed
    if (![String]::IsNullOrEmpty($credentials)) {
        $splat.authentication = $authType
        
        # add in the credentials based on the type that has been requested
        switch ($authType) {

            { @("bearer", "oauth") -contains $_} {

                # Create a secuyre string of the credential
                $secPassword = ConvertTo-SecureString -String $credentials -AsPlainText -Force

                $splat.Token = $secPassword
            }

            default {
            
                # Split the credentials out so that the username and password can be
                # used for the PSCredential
                $username, $password = $credentials -split ":", 2
                $secPassword = ConvertTo-SecureString -String $password -AsPlainText -Force
                $psCred = New-Object System.Management.Automation.PSCredential ($userName, $secPassword)

                # Add the credentials
                $splat.Credential = $psCred
            }
        }
    }

    # Add in the body if it not empty and the method is PUT or POST
    # Set as form if the contenttype is multipart/form-data
    if (($formData.count -gt 0 -or ![String]::IsNullOrEmpty($body)) -and @("put", "post") -icontains $method) {
        if ($contentType -contains "multipart/form-data") {
            $splat.form = $formData
        } else {
            $splat.body = $body
        }
    }

    # Make the call to the API
    try {
        Invoke-WebRequest @splat
    } catch {
        $_.Exception
    }

}
class StopTaskException : System.Exception
{
    [int]$ExitCode

    StopTaskException(
        [int]$exitCode,
        [string]$message
    ) : Base($message) {
        $this.ExitCode = $exitCode
    }
}
function Connect-Azure() {

    <#

    .SYNOPSIS
    Connect to azure using environment variables for the parameters

    .DESCRIPTION
    In order to access resources and credentials in Azure, the AZ PowerShell module needs to connect
    to Azure using a Service Princpal. This cmdlet performs the login either by using data specified
    on the command line or by setting them as environment variables.

    This fuinction is not exported outside of the module.

    .EXAMPLE

    Connect to Azure using parameters set on the command line

    Connect-Azure -id 9bd211c0-92df-46d3-abb8-ba437f65096b -secret asd678asdlj9092314 -subscriptionId 77f2b631-0c5f-4bc9-a776-e8b0a5e7f5b8 -tenantId f0135c92-3088-40a7-8512-247762919ae1


    #>

    [CmdletBinding()]
    param (

        [Alias("clientid")]
        [string]
        # ID of the service principal
        $id = $env:ARM_CLIENT_ID,

        [string]
        # Secret for the service principal
        $secret = $env:ARM_CLIENT_SECRET,

        [string]
        # Subscription ID
        $subscriptionId = $env:ARM_SUBSCRIPTION_ID,

        [string]
        # Tenant ID
        $tenantId = $env:ARM_TENANT_ID

    )

    $result = Confirm-Parameters -list @("id", "secret", "subscriptionId", "tenantId")
    if (!$result) {
        return
    }

    # Create a secret to be used with the credential
    $pw = ConvertTo-SecureString -String $secret -AsPlainText -Force

    # Create the credential to log in
    $credential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList ($id, $pw)

    Connect-AzAccount -Credential $credential -Tenant $tenantId -Subscription $subscriptionId -ServicePrincipal
}
function Connect-EKS() {

  <#

  .SYNOPSIS
  Connect to azure using environment variables for the parameters

  .DESCRIPTION
  In order to access EKS, one must run external command `aws eks`. In order to
  match the protocol used for Connect-Azure, this is exported to separate function.

  This function is not exported outside of the module.

  .EXAMPLE

  Connect to Azure using parameters set on the command line

  Connect-EKS -name cluster -region eu-west-2


  #>

  [CmdletBinding()]
  param (

      [Alias("cluster")]
      [string]
      # Name of the cluster
      $name,

      [string]
      # Region the cluster is deployed into
      $region = "eu-west-2",

      [switch]
      # Whether to dry run the command
      $dryrun = $false
  )

  # Ensure that all the required parameters have been set
  foreach ($parameter in @("name", "region")) {

    # check each parameter to see if it has been set
    if ([string]::IsNullOrEmpty((Get-Variable -Name $parameter).Value)) {
        $missing += $parameter
    }
  }

  # if there are missing parameters throw an error
  if ($missing.length -gt 0) {
      Write-Error -Message ("Required parameter/s are missing: {0}" -f ($missing -join ", "))
  } else {

    $cmd = "aws eks update-kubeconfig --name {0} --region {1}" -f $name, $region
    Invoke-External $cmd
  }
}
function Find-Command {

    <#

    .SYNOPSIS
    Determine the full path to the specified command

    .DESCRIPTION
    This function accepts the name of a command to look for in the path. It then uses Get-Command to return
    the full path of that command, if it has been found.

    If the command cannot be found an error is raised and the function exits with error code 1.

    .EXAMPLE

    Find-Command -Name terraform

    #>

    [CmdletBinding()]
    param (

        [string]
        # Name of the command to find
        $Name
    )

    # Find the path to the named command
    $command = Get-Command -Name $Name -ErrorAction SilentlyContinue
    if ([string]::IsNullOrEmpty($command)) {
        Write-Error -Message ("'{0}' command cannot be found in the path, please ensure it is installed" -f $Name)
        return
    } else {
        Write-Information ("Tool found: {0}" -f $command.Source)
    }

    return $command
}
function Invoke-External {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string[]]
        # Command and arguments to be run
        $commands,

        [switch]
        # State if should be run in DryRun mode, e.g. do not execute the command
        $dryrun
    )

    foreach ($command in $commands) {

        # Trim the command
        $command = $command.Trim()

        Write-Debug -Message $command

        # Determine if the command should be executed or not
        if (!$dryrun.IsPresent) {
            $execute = $true
        }

        # Add the command to the session so all can be retrieved at a later date, if
        # the session variable exists
        if (Get-Variable -Name Session -Scope global -ErrorAction SilentlyContinue) {
            $global:Session.commands.list += $command

            if ($global:Session.dryrun) {
                $execute = $false
            }
        }

        # If a file has been set in the session, append the command to the file
        if (![String]::IsNullOrEmpty($Session.commands.file)) {
            Add-Content -Path $Session.commands.file -Value $command
        }

        if ($execute) {

            # Output the command being called
            Write-Information -MessageData $command

            # Reset the LASTEXITCODE as it can be tripped from a variety of places...
            $global:LASTEXITCODE = 0

            Invoke-Expression -Command $command | Tee-Object -variable output
            
            #Write-Output -InputObject $output

            # Add the exit code to the session, if it exists
            if (Get-Variable -Name Session -Scope global -ErrorAction SilentlyContinue) {
                $global:Session.commands.exitcodes += $LASTEXITCODE
            }


            # Stop the task if the LASTEXITCODE is greater than 0
            if ($LASTEXITCODE -gt 0) {
                Stop-Task -ExitCode $LASTEXITCODE
            }


        }
    }
}
function Stop-Task() {

    <#

    .SYNOPSIS
    Stops a task being run in a Taskctl pipeline

    .DESCRIPTION
    When commands or other process fail in the pipeline, the entire pipeline must be stopped, it is not enough
    to call `exit` with an exit code as this does not stop the pipeline. It also causes issues when the module
    is run on a local development workstation as any failure will cause the console to be terminted.

    This function is intended to be used in place of `exit` and will throw a PowerShell exception after the
    error has been written out. This is will stop the pipeline from running and does not close the current
    console

    The function will also attempt to detect the pipeline that it is being run on and output the correct message
    string for that CI/CD platform.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]
        # Error message to be displayed
        $Message,
        [Parameter(Mandatory=$false)]
        [string]
        # Exit Code of the failing command or process
        $ExitCode = -1
    )

    $exceptionMessage = "Task failed due to errors detailed above"

    if (![string]::IsNullOrEmpty($Message)) {
        # Also prepend the message to the exception for easier catching
        $exceptionMessage = $Message + "`n" + $exceptionMessage

        # Attempt to detect the CI/CD the pipeline is running in and write out messages
        # in the correct format to be picked up the pipeline
        # For example if running in Azure DevOps then write a message according to the format
        #   "##[error]<MESSAGE>"
        # https://docs.microsoft.com/en-us/azure/devops/pipelines/scripts/logging-commands?view=azure-devops&tabs=bash

        #### Azure DevOps Detection
        $azdo = Get-ChildItem -Path env:\TF_BUILD -ErrorAction SilentlyContinue
        if (![String]::IsNullOrEmpty($azdo)) {
            $Message = "##[error]{0}" -f $Message
        }

        # Write an error
        # The throw method does not allow formatted text, so use Write-Error here to display a nicely formatted error
        Write-Error $Message
    }

    # Throw an exception to stop the process
    throw [StopTaskException]::new($exitCode, $exceptionMessage)
}
function Build-DockerImage() {

  <#

    .SYNOPSIS
    Create a Docker image for the application and optionally pushes it to a container registry

    .DESCRIPTION
    Builds a docker image using the specified build arguments, name and tags. Optionally the function
    can also push the image to a remote registry, be it a generic registry, Azure or AWS.

    If the option has been specified to push to a remote registry then a name of the registry
    and the group it belongs to need to be specified.

    The parameters can be specified on the command line or as an environment variable, apart from the
    buildargs and whether the image should be pushed to a registry.

    In order to push to a registry the function will first use the Connect-Azure function and then
    get the regsitry credentials using the Get-AzContainerRegistryCredential cmdlet.

    AWS command reference: https://docs.aws.amazon.com/AmazonECR/latest/userguide/docker-push-ecr-image.html

    .EXAMPLE

    Build-DockerImage -Provider azure -Name ensonodigital/myimage:0.0.1 -Registry edregistry.azurecr.io -buildargs src/api -push

    This will build a DockerImage using the Dockefile in the current directory. The build arguments will be passed and then once
    the image has been built it will be pushed to the specified Azure registry.

    The username and password to access the registry will be extracted using the PowerShell cmdlet `Get-AzContainerRegistryCredential`
    and then this will be passed to the resultant docker command.
  #>

  [CmdletBinding()]
  param (
    [Parameter(
      ParameterSetName = "build"
    )]
    [string]
    # Arguments for docker build
    $buildargs = ".",

    [Parameter(
      ParameterSetName = "build",
      Mandatory = $true
    )]
    [string]
    # Name of the docker image
    $name = $env:DOCKER_IMAGE_NAME,

    [Parameter(
      ParameterSetName = "build"
    )]
    [string]
    # Image tag
    $tag = $env:DOCKER_IMAGE_TAG,

    [Parameter(
      ParameterSetName = "build"
    )]
    [switch]
    # Add the latest tag
    $latest,

    [Parameter(
      ParameterSetName = "build"
    )]
    [Parameter(
      ParameterSetName = "push"
    )]
    [string]
    # Docker registry FQDN to push the image to. For AWS this is in the format `<aws_account_id>.dkr.ecr.<region>.amazonaws.com`. For Azure this is in the format `<acr_name>.azurecr.io`
    $registry = $env:DOCKER_CONTAINER_REGISTRY_NAME,

    [Parameter(
      ParameterSetName = "build"
    )]
    [Parameter(
      ParameterSetName = "push"
    )]
    [switch]
    # Push the image to the specified registry
    $push,

    [string]
    [Parameter(
      ParameterSetName = "build"
    )]
    [Parameter(
      ParameterSetName = "push"
    )]
    [Parameter(
      ParameterSetName = "aws"
    )]
    [Parameter(
      ParameterSetName = "azure"
    )]
    [ValidateSet('azure', 'aws', 'generic')]
    # Determine which provider to use for the push
    $provider,

    [string]
    [Parameter(
      ParameterSetName = "build"
    )]
    [Parameter(
      ParameterSetName = "azure"
    )]
    [Parameter(
      ParameterSetName = "push"
    )]
    # Resource group  in Azure that the container registry can be found in
    $group = $env:REGISTRY_RESOURCE_GROUP,

    [string]
    [Parameter(
      ParameterSetName = "build"
    )]
    [Parameter(
      ParameterSetName = "aws"
    )]
    [Parameter(
      ParameterSetName = "push"
    )]
    # Region in AWS that the container registry can be found in
    $region = $env:ECR_REGION,

    [switch]
    # If used with -latest it will force the latest tag onto the image regardless
    # of the branch that has been detected
    $force
  )

  # Check mandatory parameters
  # This is not done at the param level because even if an environment
  # variable has been set the parameter will not see this as a value
  if ([string]::IsNullOrEmpty($name)) {
    Write-Error -Message "A name for the Docker image must be specified"
    return 1
  }

  if ([string]::IsNullOrEmpty($tag)) {
    $tag = "0.0.1-workstation"
    Write-Information -MessageData ("No tag has been specified for the image, a default one has been set: {0}" -f $tag)
  }

  # If the push switch has been specified then check that a registry
  # has been specified
  if ($push.IsPresent -and ([string]::IsNullOrEmpty($provider) -or ([string]::IsNullOrEmpty($registry) -and !(Test-Path -Path env:\NO_PUSH)))) {
    Write-Error -Message "A provider and a registry to push the image to must be specified"
    return 1
  }

  if ($provider -eq "generic" -and ([string]::IsNullOrEmpty($env:DOCKER_USERNAME) -Or [string]::IsNullOrEmpty($env:DOCKER_PASSWORD))) {
    Write-Error -Message "Pushing to a generic registry requires environment variables DOCKER_USERNAME and DOCKER_PASSWORD to be set"
    return
  }

  elseif ($provider -eq "azure" -and ([string]::IsNullOrEmpty($env:REGISTRY_RESOURCE_GROUP)) -and ([string]::IsNullOrEmpty($group))) {
    Write-Error -Message "Pushing to an azure registry requires environment variable REGISTRY_RESOURCE_GROUP or group parameter to be set (authentication must be dealt with via 'invoke-login.ps1'"
    return
  }

  elseif ($provider -eq "aws" -and ([string]::IsNullOrEmpty($env:AWS_ACCESS_KEY_ID) -Or [string]::IsNullOrEmpty($env:AWS_SECRET_ACCESS_KEY) -Or ([string]::IsNullOrEmpty($region) -And [string]::IsNullOrEmpty($env:ECR_REGION)))) {
    Write-Error -Message "Pushing to an AWS registry requires environment variable ECR_REGION or region parameter defined, and both environment variables AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY to be set"
    return
  }

  # Determine if latest tag should be applied
  $setAsLatest = $false
  if (((Confirm-TrunkBranch) -or $force.IsPresent) -and $latest.IsPresent) {
    $setAsLatest = $true
  }

  # Ensure that the name and the tagare lowercase so that Docker does not
  # throw an error with invalid strings
  $name = $name.ToLower()
  $tag = $tag.ToLower()

  # Create an array to store the arguments to pass to docker
  $arguments = @()
  $arguments += $buildArgs.Trim("`"", " ")
  $arguments += "-t {0}:{1}" -f $name, $tag

  # if the registry name has been set, add t to the tasks
  if (![String]::IsNullOrEmpty($registry)) {
    $arguments += "-t {0}/{1}:{2}" -f $registry, $name, $tag

    if ($setAsLatest) {
      $arguments += "-t {0}/{1}:latest" -f $registry, $name
    }
  }

  # Create the cmd to execute
  $cmd = "docker build {0}" -f ($arguments -Join " ")
  Invoke-External -Command $cmd

  if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
  }

  # Proceed if a registry has been specified
  if (![String]::IsNullOrEmpty($registry) -and $push.IsPresent -and !(Test-Path -Path env:\NO_PUSH)) {

    switch ($provider) {
      "azure" {
        # Ensure that the module is available and loaded
        $moduleName = "Az.ContainerRegistry"
        $module = Get-Module -ListAvailable -Name $moduleName
        if ([string]::IsNullOrEmpty($module)) {
          Write-Error -Message ("{0} module is not available" -f $moduleName)
          exit 2
        }
        else {
          Import-Module -Name $moduleName
        }

        # Login to azure
        Connect-Azure

        # Rewrite Registry value to obtain Azure Resourece Name:
        $registryName = $registry.split(".")[0]

        # Get the credentials for the registry
        $creds = Get-AzContainerRegistryCredential -Name $registryName -ResourceGroup $group

        $cmd = "docker login {0} -u {1} -p {2}" -f $registry, $creds.UserName, $creds.Password

      }
      "generic" {
        $cmd = "docker login {0} -u {1} -p {2}" -f $registry, $env:DOCKER_USERNAME, $env:DOCKER_PASSWORD
      }
      "aws" {

        $cmd = "aws ecr get-login-password --region {0} | docker login --username AWS --password-stdin {1}" -f $region, $registry

      }
    }

    # Run command to login to the docker registry to do the push
    # The Invoke-External function will need to be updated to obfruscate sensitive information
    Invoke-External -Command $cmd

    if ($LASTEXITCODE -ne 0) {
      exit $LASTEXITCODE
    }

    # Push the image with the desired tag
    $cmd = "docker push {0}/{1}:{2}" -f $registry, $name, $tag
    Invoke-External -Command $cmd

    # Push the image with the latest tag if latest flag is declared
    if ($setAsLatest) {
      $cmd = "docker push {0}/{1}:latest" -f $registry, $name
      Invoke-External -Command $cmd
    }

    $LASTEXITCODE

  }
}
function Build-Documentation() {

    <#
    
    .SYNOPSIS
    Build documentation in a project in different formats

    .DESCRIPTION
    The Build-Documentation cmdlet is used to generate documentation from the Asciidoc source in a project.

    The cmdlet allows for PDF and MD files to be generated.

    .NOTES

    In order for the documentation to be generated the asciidoctor, asciidoctor-pdf and pandoc binaries
    must be available. These can be installed locally or run in a container. 

    #>

    [CmdletBinding()]
    param (

        [string]
        # Application or base path from which the docs can be found
        $basePath = (Get-Location),

        [string]
        # Docs directory beneath the base path
        $docsDir = "docs",

        [Alias("target")]
        [string]
        # Output directory for the documentation
        $outputDir = "outputs",

        [string]
        # Set the build number to be applied to the documenation
        $buildNumber = $env:BUILDNUMBER,

        [Parameter(
            ParameterSetName="pdf"
        )]
        [switch]
        # State if PDF documentation should be generated
        $pdf,

        [Parameter(
            ParameterSetName="pdf"
        )]
        [string[]]
        # Attributes that should be passed to the generation of the PDF
        $attributes,

        [Parameter(
            ParameterSetName="pdf"
        )]
        [string]
        # Path to file containing attribuites that are required for the PDF creation
        $attributeFile,        

        [Parameter(
            ParameterSetName="pdf"
        )]
        [string]
        # Title of the PDF document
        $title,

        [Parameter(
            ParameterSetName="pdf"
        )]
        [string]
        # Name of file that should be used to generate the document
        # This is likely an indesx file that contains links to the other files to be included
        $indexFile = "index.adoc",        

        [Parameter(
            ParameterSetName="md"
        )]
        [switch]
        # State if markdown should be generated
        $md,

        [Parameter(
            ParameterSetName="md"
        )]
        [switch]
        # state if the MDX flavour of MD needs to be created
        $mdx
    )

    # Determine the directories
    # - raw documentation dir
    $docsDir = [IO.Path]::Combine($basePath, $docsDir)

    # - output directory
    $outputDir = Protect-Filesystem -Path $outputDir -BasePath (Get-Location).Path
    if (!$outputDir) {
        return $false
    }

    # Check that the documentation directory exists
    if (!(Test-Path -Path $docsDir)) {
        Write-Error -Message ("Documentation directory does not exist: {0}" -f $docsDir)
        return $false
    }

    # generate the documentation based on the switch that has been specified
    switch ($PSCmdlet.ParameterSetName) {
        "pdf" {

            # determine the pdf output dir and create if it does not exist
            $pdfOutputDir = [IO.Path]::Combine($outputDir, "docs", "pdf")
            if (!(Test-Path -Path $pdfOutputDir)) {
                Write-Output ("Creating output dir: {0}" -f $pdfOutputDir)
                New-Item -ItemType Directory -Path $pdfOutputDir | Out-Null
            }

            # Ensure that the command to generate the PDF can be found
            $pdfCommand = Find-Command -Name "asciidoctor-pdf"
            if ([string]::IsNullOrEmpty($pdfCommand)) {
                return
            }

            # Configure the attributes
            $attrs = @()

            # if an attribute file has been specified read trhe values from there
            if (![string]::IsNullOrEmpty($attributeFile)) {

                # check to see if the file exists
                if (Test-Path -Path $attributeFile) {

                    # get the file extension of the file to check that it is the correct format
                    $extn = [IO.Path]::GetExtension($attributeFile)

                    switch ($extn) {
                        ".ps1" {

                            # read the file into the attributes array
                            $attributes = Invoke-Expression -Command (Get-Content -Path $attributeFile -Raw)
                        }
                        default {
                            Write-Warning -Message "Specified file format is not supported"
                        }
                    }


                } else {

                    Write-Warning -Message ("Unable to find specified attributes file: {0}" -f $attributeFile)
                }
            }

            # configure the attributes correctly
            foreach ($attribute in $attributes) {
                
                # do not add the -a if it already starts with that
                $line = ""
                if ($attribute.StartsWith("-a")) {
                    $line = "{0}"
                } else {
                    $line = "-a {0}" 
                }

                $attrs += , $line -f $attribute
            }

            

            # Build up the array to hold the parts of the command to run
            $cmdParts = @(
                $pdfCommand
                $attrs
                '-o "{0}.pdf"' -f $title
                "-D {0}" -f $pdfOutputDir
                "{0}/{1}" -f $docsDir, $indexFile
            )

            # run the command by joining the command and then executing it
            $cmd = $cmdParts -join " "
            Invoke-External -Command $cmd

            Write-Information -Message ("Created PDF documentation: {0}.pdf" -f ([IO.Path]::Combine($pdfOutputDir, $title)))
        }

        "md" {

            # Create a temporary directory to store transitional XML files
            $mdOutputDir = [IO.Path]::Combine($outputDir, "docs", "md")
            if (!(Test-Path -Path $mdOutputDir)) {
                Write-Output ("Creating output dir: {0}" -f $mdOutputDir)
                New-Item -ItemType Directory -Path $mdOutputDir | Out-Null
            }

            $tempOutputDir = [IO.Path]::Combine($outputDir, "docs", "temp")
            if (!(Test-Path -Path $tempOutputDir)) {
                Write-Output ("Creating temporary output dir: {0}" -f $tempOutputDir)
                New-Item -ItemType Directory -Path $tempOutputDir | Out-Null
            }

            # Get a list of the document files
            $list = Get-ChildItem -Path $DocsDir/* -Attributes !Directory -Include *.adoc

            # Iterate around the list of files
            foreach ($item in $list) {

                # Get the name of the file from the pipeline
                $fileTitle = [System.IO.Path]::GetFileNameWithoutExtension($item.FullName)

                # define the filenames
                $xmlFile = [IO.Path]::Combine($tempOutputDir, ("{0}.xml" -f $fileTitle))
                $mdFile = [IO.Path]::Combine($mdOutputDir, ("{0}.md" -f $fileTitle))

                # Find the necessary commands
                $asciidoctorCmd = Find-Command -Name "asciidoctor"
                $pandocCmd = Find-Command -Name "pandoc"

                # build up the commands that need to be executed
                $commands = @()

                # -- convert to xml
                $commands += "{0} -b docbook -o {1} {2}" -f $asciidoctorCmd, $xmlFile, $item.FullName

                # -- convert XML to markdown
                $commands += "{0} -f docbook -t gfm --wrap none {1} -o {2}" -f $pandocCmd, $xmlFile, $mdFile

                Invoke-External -Command $commands

                Write-Information -MessageData ("Create Markdown file: {0}" -f $mdFile)

                # If the switch to generate MDX file has been set, execute it
                if ($MDX.IsPresent) {

                    # create the mdx file path
                    $mdxOutputDir = [IO.Path]::Combine($outputDir, "docs", "mdx")
                    $mdxFile = [IO.Path]::Combine($mdxOutputDir, ("{0}.mdx" -f $fileTitle))

                    ConvertTo-MDX -Path $mdFile -Destination $mdxFile
                }
            }

            # Remove the temporary directory
            Remove-Item -Path $tempOutputDir -Force -Recurse
        }
    }

}
function Build-PowerShellModule() {

    <#

    .SYNOPSIS
    Function to create the AmidoBuild PowerShell module

    .DESCRIPTION
    The powershell module in this repository is used with the Independent Runner
    so that all commands and operations are run in the same way regardless of the platform.

    The cmdlet can be used to build any PowerShell module as required.

    PowerShell modules can be deployed as multiple files or as a single file in the `.psm1` file.
    To ease deployment, the module will bundle all of the functions into a single file. This means
    that when it comes to deployment there are only two files that are required, the manifest file
    and the data file.

    .EXAMPLE

    Build-PowerShellModule -Path /app/src/modules -name AmidoBuild -target /app/outputs/module

    This is the command that is used to build the Independent Runner. It use the path and the name to
    determine where the files for the module. The resultant module will be saved in the specified
    target folder.

    #>

    [CmdletBinding()]
    param (

        [string]
        # Name of the module
        $name,

        [Alias("source")]
        [string]
        # Path to the module files to package up
        $path,

        [Alias("output")]
        [string]
        # Target for the "compiled" PowerShell module
        $target = "outputs",

        [Hashtable]
        # Hashtable to be put in as the global session for the module
        $sessionObject = @{},

        [string]
        # Name of the global session to create
        $sessionName,

        [string]
        # Version number to assign to the module
        $version = $env:MODULE_VERSION
    )

    # Check that all the necessary parameters have been set
    $result = Confirm-Parameters -list @("name", "path", "target")
    if (!$result) {
        return $false
    }

    # Check that the path exists
    if (!(Test-Path -Path $path)) {
        Write-Error -Message ("Specified module path does not exist: {0}" -f $path)
        return $false
    }

    # Check that the target path exists
    $target = [IO.Path]::Combine($target, $name)
    if (!(Test-Path -Path $target)) {

        $result = Protect-Filesystem -Path $target -BasePath (Get-Location).Path
        if (!$result) {
            return $false
        }
    }

    # work out the path to the module
    $moduleDir = [IO.Path]::Combine($path, $name)

    # Check that the PSD file can be found
    $modulePSD = [IO.Path]::Combine($moduleDir, ("{0}.psd1" -f $name))
    if (!(Test-Path -Path $modulePSD)) {
        Write-Error -Message ("Module data file cannot be found: {0}" -f $modulePSD)
        return $false
    }
    
    # Get all the functions in the module, except the tests
    $splat = @{
        Path = $moduleDir
        ErrorAction = "SilentlyContinue"
        Recurse = $true
        Include = "*.ps1"
    }
    $moduleFunctions = Get-ChildItem @splat | Where-Object { $_ -notmatch "Providers" -and $_ -notmatch "\.Tests\.ps1"}

    Write-Information -MessageData ("Number of functions: {0}" -f $moduleFunctions.length)
    Write-Information -MessageData "Configuring module file"

    # Create the path for the module file
    $modulePSM = [IO.Path]::Combine($target, ("{0}.psm1" -f $name))

    # if a session object and name have been specified add it to the PSM file
    # TODO: write util function to convert the hashtable to a string that can be added to the PSM file
    if (![string]::IsNullOrEmpty($sessionName) -and $sessionObject.Count -gt 0) {
        Add-Content -Path $modulePSM -Value (@"
`${0} = {1}
"@ -f $sessionName, ($sessionObject | Convert-HashToString))

        Add-Content -Path $modulePSM -Value "`n"
    }

    # Iterate around the functions that have been found
    foreach ($moduleFunction in $moduleFunctions) {

        $results = [System.Management.Automation.Language.Parser]::ParseFile($moduleFunction.FullName, [ref]$null, [ref]$null)

        # get all the functions in the file
        $functions = $results.EndBlock.Extent.Text

        # Add the functions to the PSM file
        Add-Content -Path $modulePSM -Value $functions

    }

    Write-Information -MessageData "Updating module data"

    # Copy the datafile into the output dir
    Copy-Item -Path $modulePSD -Destination $target

    # Update the manifest file with the correct list of functions to export
    # and the build number

    # get a list of the functions to export
    $functionsToExport = Get-ChildItem -Recurse $moduleDir -Include *.ps1 | Where-Object { $_.FullName -match "exported" -and $_ -notmatch "\.Tests\.ps1"} | ForEach-Object { $_.Basename }

    $splat = @{
        Path = [IO.Path]::Combine($target, ("{0}.psd1" -f $name))
        FunctionsToExport = $functionsToExport
    }

    # if a version has been specified add it to the splat
    if (![string]::IsNullOrEmpty($version)) {
        $splat["ModuleVersion"] = $version
    }

    Update-ModuleManifest @splat

}
function Confirm-Environment() {

    <#

    .SYNOPSIS
    Checks that all the environment variables have been configured

    .DESCRIPTION
    Most of the configuration for Stacks pipelines is done using environment variables
    and there can be quite a lot of them. This function uses a file in the repository to determine
    which environment variables are required for different stages and cloud platforms. If any
    environment variables are missing it will exit the task and stop the pipeline. This is
    so that things fail as early as possible.

    The structure of the file describing the envrionment is show below.

    ```
        default:
            variables: [{}]
            credentials:
                azure:  [{}]
                aws: [{}]
        
        stages:
            name: <NAME>
            variables: [{}]
    ```

    Each of the `[{}]` in variables denotes an array of the following object

        name: ""
        description: ""
        required: boolean
        cloud: <CLOUD>

    When thisd function runs it merges the default variables, the cloud cerdential variables
    and the stage variables and checks to see that they have been set. If they have not it will
    output a message stating whicch ones have not been set and then fail the task.

    .PARAMETER path
    Path to the file containing the stage environment variables

    .PARAMETER cloud
    Name of the cloud platform being deployed to. Can be set using thew
    `CLOUD_PLATFORM` environment variable. Currently only supports azure and aws.

    .PARAMETER stage
    Name of the stage to check the envirnment for. Can be set using the `STAGE` environnment
    variable.

    This variable is not checked for by this function as it is required by this function. If not
    specified a warning will be displayed stating that no stage has been specified amd will operate
    with the default variables.

    .PARAMETER passthru
    This forces the return of the missing variables as an object. It is up to the calling function
    to process this response and detremine if variables are missing.

    The primary use for this is for testing, but it can be used in other situations.

    .PARAMETER format
    Specifies the output format of the passthru. If not specified then a PSObject will be returned.

    If "json" is specifed the missing variables are returned in a JSON string


    #>

    [CmdletBinding()]
    param (

        [string]
        # Path to the file containing the list of environment variables
        # that must be set in the environment
        $path,

        [string]
        # Name of the cloud platform being deployed to. This is so that the credntial
        # environment variables are checked for correctly
        $cloud = $env:CLOUD_PLATFORM,

        [string]
        # Stage being run which determines the variables to be chcked for
        # This stage will be merged with the default check
        # If not specified then only the deafult stage will be checked
        $stage = $env:STAGE,

        [switch]
        # Pass the results throught the pipeline
        $passthru,

        [string]
        # Specify the output format if using the passthtu option, if not specfied
        # a PSObject is retruned
        $format
    )

    # Get a list of the required variables for this stage and the chosen cloud platform
    $missing = Get-EnvConfig -path $path -stage $stage -cloud $cloud

    # If there are missing values provide an error message and stop the task
    if ($missing.count -gt 0) {

        if ($passthru.IsPresent) {

            switch ($format) {
                "json" {
                    Write-Output (ConvertTo-Json $missing)
                    break
                }

                default {
                    $missing
                }
            }

        } else {

            # determine the length of the longest string
            $length = 0
            foreach ($item in $missing) {
                if ($item.name.length -gt $length) {
                    $length = $item.name.length
                }
            }

            $message = @()
            foreach ($item in $missing) {

                # determine how many whitespaces are required for this name lenght to pad it out
                $padding = $length - $item.name.length

                $sb = [System.Text.StringBuilder]::new()
                [void]$sb.Append($item.name)

                if (![string]::IsNullOrEmpty($item.description)) {
                    $whitespace = " " * $padding
                    [void]$sb.Append($whitespace)
                    [void]$sb.Append(" - {0}" -f $item.description)
                }

                $message += $sb.ToString()
            }

            # As there is an error the task in Taskctl needs to be stopped
            Stop-Task -Message ("The following environment variables are missing and must be provided:`n`t{0}" -f ($message -join "`n`t"))
        }
    }
}
function Expand-Template() {

    <#

    .SYNOPSIS
    Expand variables in a template file and output to the specified destination

    .DESCRIPTION
    This function mimics the `envsubst` command in Linux and expands any variable in a template file
    and outputs it to a file or stdout

    PowerShell deals with environment variables slightly differently in that they are prefixed, e.g. env:NAME
    So that variables such as ${NAME} can be expanded the env vars need to be converted to scoped level variables
    Ths function will get all enviornment variables and make then local variables for the expansion to use.

    If no target is specified then the template is output to stdout

    .EXAMPLE

    $env:MYNAME = "pester"
    'name: ${MYNAME}' | Expand-Template -Pipeline

    Send a template to be expanded into the cmdlet using a pipeline. The result will be a string
    'name: pester'

    .EXAMPLE

    $env:MYNAME = "pester"
    'name: ${MYNAME}' | Expand-Template -Pipeline -Target envfile

    Same as the previous example, but the output will be saved in the file specified by the 
    target parameter

    .EXAMPLE

    Set-Content -path template.txt -value 'component: ${COMPONENT}'
    Expand-Template -Template ./template.txt -additional @{"component" = "template"}

    This time the template is read from a file and the values that are to be replaced come from the
    additional hashtable. This is combnined with the values from the environment. Values that
    are duplicated between the two will be overriden by the additional values.

    #>

    [CmdletBinding()]
    param (
        [string]
        [Parameter(
            Mandatory=$true,
            ParameterSetName="content",
            ValueFromPipeline=$true
        )]
        # Content of the template to use
        $template,

        [string]
        [Parameter(
            Mandatory=$true,
            ParameterSetName="path"
        )]
        [Alias("i")]
        # Path to the file to use as the template
        $path,

        [Alias("o", "variables")]
        [string]
        # Target path for the output file
        $target,

        [Alias("a")]
        [hashtable]
        # Specify a list of additional values that should be added
        $additional = @{},

        [Alias("s")]
        [switch]
        # State if information about the transformation should be output
        $show,

        [switch]
        # State if the rendered template should be set on the pipeline
        $pipeline
    )
    
    # check that the path exists if the path parametersetname is being used
    if ($PSCmdlet.ParameterSetName -eq "path") {
        if (!(Test-Path -Path $path)) {
            Write-Error -Message ("Specified path cannot be found: {0}" -f $path)
            return
        } else {
            $template = Get-Content -Path $path -Raw
        }
    }

    # Determine if the parent path of the target exists, if one has been specified
    if (![String]::IsNullOrEmpty($target)) {
        $parentPath = Split-Path -Path $target -Parent
        if (!(Test-Path -Path $parentPath)) {
            Write-Error -Message ("Directory for target path does not exist: {0}" -f $parentPath)
        }
    }

    # Get all the enviornment variables
    $envvars = [Environment]::GetEnvironmentVariables()

    # iterate around the variables and create local ones
    foreach ($envvar in $envvars.GetEnumerator()) {
        if (@("path", "home") -notcontains $envvar.Name) {
            Set-Variable -Name $envvar.Name -Value $envvar.Value
        }
    }

    # If the additional hashtable contains data then add these as local variables
    if ($additional.Count -gt 0) {
        foreach ($extra in $additional.GetEnumerator()) {
            Set-Variable -Name $extra.Name -Value $extra.Value
        }
    }

    # Perform the expansion of the template
    $data = $ExecutionContext.InvokeCommand.ExpandString($template)

    
    # Output information if show has been specified
    if ($show) {
        Write-Information -MessageData ("base yaml: {0}" -f $path)
        Write-Information -MessageData ("out_template yaml: {0}" -f $target)
    }

    # if the target has been specfied write it out to the file
    if ($pipeline) {
        $data
    } else {

        if ([String]::IsNullOrEmpty($target)) {
            # use the path in the specified to work out the target
            $filename = Split-Path -Path $path -Leaf
            $dir = Split-Path -Path $path -Parent

            # Create the target
            $target = [IO.Path]::Combine($dir, ($filename -replace "base_", ""))

            Write-Information -MessageData ("Setting target path: {0}" -f $target)
        }

        Set-Content -Path $target -Value $data   
    }
}
function Get-AzureServiceVersions() {

    <#
    
    .SYNOPSIS
    Returns version information for specific services in Azure
    
    .DESCRIPTION
    Some Azure services provide versions that they currently support. This is valuable information
    when performing infrastructure tests. This cmdlet will return the service versions that are supported
    for supported applications.

    The cmdlet is dependant on the Azure PowerShell module to perform the authentication and call the necssary
    commands. This cmdlet is a helper function that takes care of the authentication from the provided
    Service Principal details and then calls the necessary function.

    Service princiapl details can be supplied as enviornment variables, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET and
    AZURE_TENANT_ID or as parameters `client_id`, `client_password` and `tenant_id`.

    At the moment this cmdlet only supports AKS.

    .EXAMPLE
    $env:AZURE_CLIENT_ID = "12345"
    $env:AZURE_CLIENT_PASWORD = "67890"
    $env:AZURE_TENANT_ID = "064c340f-eeae-48d2-badf-6a3b87c9830e"

    Get-AzureServiceVersions -service aks -location westeurope

    #>

    [CmdletBinding()]
    param (

        [string[]]
        # List of services that need versions for
        $services = $env:AZURE_SERVICES,

        [string]
        # Service principal Client ID
        $client_id = $env:AZURE_CLIENT_ID,

        [string]
        # Service principal password
        $client_password = $env:AZURE_CLIENT_SECRET,

        [string]
        # Tenant ID for the Service Principal
        $tenant_id = $env:AZURE_TENANT_ID,

        [string]
        # Location to check for kubernetes versions
        $location
    )

    if ($services.Count -eq 0) {
        Write-Error -Message "Please specify at least one service to check the version of. Combination of [aks]"
        return
    }

    if ($location -eq "") {
        Write-Error -Message "A valid Azure location must be specified"
        return
    }

    if ($client_id -eq "" -or $client_password -eq "" -or $tenant_id -eq "") {
        Write-Error -Message "Service principal information must be provided for authentication, (client_id, client_password, tenant_id)"
    }

    # Create the credential object
    # Convert the password to a secure string
    [SecureString] $secure_pasword = ConvertTo-SecureString -String $client_password -AsPlainText -Force

    # Create the PSCredential Object
    [PSCredential] $creds = New-Object System.Management.Automation.PSCredential ($client_id, $secure_pasword)

    # Connect to Azure
    Connect-AzAccount -ServicePrincipal -Credential $creds -Tenant $tenant_id -WarningAction Ignore | Out-Null

    # Create the hashtable to hold the values that retrieved
    $result = @{}

    switch -Regex ($services) {
        "kubernetes|k8s|aks" {
            $versions = Get-AzAksVersion -Location $location

            $available_versions = @()
            foreach ($version in $versions) {
                $available_versions += $version.OrchestratorVersion
            }

            $result["kubernetes_valid_versions"] = $available_versions
        }
    }


    return $result
}
function Get-Dependencies {

    <#

    .SYNOPSIS
    Get dependencies for the build

    .DESCRIPTION
    Retrieve the dependencies for the build. The dependencies are determines from the list
    that is provided.

    Can retrieve a list of GitHub repositories into the lcoal directory

    Each dependencies, if found, is cloned into the local repository.

    .EXAMPLE

    Get-Dependencies -type github -list @{"pester-repo-1"}

    Will attempt to clone the specified repo into the current directory

    #>

    [CmdletBinding()]
    param (

        [Parameter(Mandatory=$true)]
        [string]
        # Type of dependencies that are to be downloaded
        $type,

        [string[]]
        # List of deps to download
        $list
    )

    # Get the dependencies for the specified type
    switch ($type) {
        "github" {

            # iterate around the list of deps
            foreach ($repo in $list) {

                # get the name and the ref from the specified repo
                $name, $ref = $repo -split "@"

                Invoke-GitClone -Repo $name -Ref $ref -path support
            }
        }

        default {

            Write-Error -Message $("VCS type is not recognised: {0}" -f $type)
        }
    }
}
function Get-ExternalCommands() {

    <#

    .SYNOPSIS
    Function to return a list of the external commands that have been executed by the module

    .DESCRIPTION
    When the module is run, all of the external commands (those that are not PowerShell) cmdlets are
    stored in a session variable. This will return all of the commands that have been run. It is
    possible to access a specific command if required using the item parameter.

    This is very useful when trying to debug a build that uses the Independent Runner.

    .EXAMPLE

    Get-ExternalCommands

    List all of the commands that have been executed.

    #>

    [CmdletBinding()]
    param (

        [int]
        # Retrieve specified command item
        $item
    )

    $exists = Get-Variable -Name "Session" -Scope global -ErrorAction SilentlyContinue

    # return the commands in the session if the session var exists
    if (![String]::IsNullOrEmpty($exists)) {

        # if there are no commands in the list, display a warning
        if ($global:Session.commands.list.Count -eq 0) {
            Write-Warning -Message "No commands have been executed"
        } else {

            if ($item -gt 0) {
                
                # Raise an error if the item is greater than the number of items
                if ($item -gt $global:Session.commands.list.count) {
                    Write-Error -Message ("Specified item does not exist: {0} total" -f $global:Session.commands.list.count)
                } else {
                    $global:Session.commands.list[$item - 1]
                }
            } else {
                $global:Session.commands.list
            }
        }
        
    } else {
        Write-Warning -Message "Session has not been defined"
    }
}
function Invoke-Asciidoc() {

    <#
    
    .SYNOPSIS
    Runs AsciiDoc to convert documents to the desired format

    .DESCRIPTION
    This cmdlet provides direct access to the AsciiDoc commands. It allows more configuration
    than the Build-Documentation cmdlet.

    Like the Build-Documentation cmdlet the output format can be specified, either PDF or HTML. Markdown
    is not yet supported.

    To make it more flexible the cmdlet takes a JSON configuration file which governs how the command
    will run. For example:

    ```
   {
        "title": "MRBuild Manual",
        "output": "{{ basepath }}/outputs/docs/{{ format }}",
        "trunkBranch": "main",
        "path": "{{ basepath }}/docs/index.adoc",
        "libs": [
            "asciidoctor-diagram"
        ],
        "pdf": {
            "attributes": [
                "pdf-theme={{ basepath }}/docs/conf/pdf/theme.yml",
                "pdf-fontsdir=\"{{ basepath }}/docs/conf/fonts;GEM_FONTS_DIR\"",
                "allow-uri-read"
            ]
        }
    } 
    ```

    As can be seen the cmdlet supports inserting values into the strings. This allows for the most
    flexibilty. For example the `basepath` is determined automatcially or by specification and this
    is inserted into the output path using the {{ basepath }} token.

    The format is still specified on the command line. The configuration for the format is specified
    as another node in the configuration, in this case the attributes for PDF can be seen.

    In addition to the two tokens that are added by the cmdlet, "basepath" and "format", all environment
    variables are tokens that can be subsituted in the settings file or on the commannd line. For example
    if an environment variable of "BUILDNUMBER" exists and has a value of "1.2.3" the following "attr_a={{ BUILDNUMBER }}"
    would result in a substitution of "attr_a=1.2.3"

    The templating is resolved across the whole configuration file before it is used.

    .NOTES

    This cmdlet will eventually supercede the Build-Documentation cmdlet

    .EXAMPLE

    Invoke-AsciiDoc -pdf -folder . -config ./config.json -output outputs/

    Generate a PDF document from the current folder and put the resultant file in
    the `outputs/` directory.    
    #>

    [CmdletBinding()]
    param (

        [Parameter(
            ParameterSetName="pdf"
        )]
        [switch]
        # State that the document should be PDF
        $pdf,

        [Parameter(
            ParameterSetName="html"
        )]
        [switch]
        # State that the document should be HTML
        $html,
        
        [string]
        # Path to configuration file with all the necessary settings
        # If specified additional specific parameters are specifed, those values will 
        # override the ones in the configuration file
        $config,

        [string]
        # Base path from which all paths will be derived
        # By default this will be the current directory, but in docker this should be the dir
        # that the directory is mapped into
        $basepath = $(Get-Location),

        [alias("folder", "template")]
        [string]
        # Path to the AsciiDoc template to render
        $path,

        [string]
        # Full path for the built document
        $output,

        [string[]]
        # List of attributes to pass to the AsciiDoc command
        $attributes
    )

    # Define variables to be used in the function
    $cmdline = @()
    $extension = ""

    # Create an empty config hashtable to be used to grab the settings for the generation
    $settings = @{
        title = ""
        output = ""
        path = ""
        trunkBranch = ""
        libs = @()
        pdf = @{
            attributes = @()
        }
        html = @{
            attributes = @()
        }
    }

    # Define the tokens hashtable for any replacements
    $tokens = @{
        "format" = $PSCmdlet.ParameterSetName
        "basepath" = $basepath
    }

    # Add all environment variables to the tokens list
    # This is so that any can be used in substitutions in the generation of an AsciiDoc document
    $envs = Get-ChildItem -Path env:*
    foreach ($env in $envs) {
        $tokens[$env.Name] = $env.Value
    }

    # Perform the appropriate action based on the Parameter Set Name that
    # has been selected
    switch ($PSCmdlet.ParameterSetName) {
        "pdf" {

            # set the correct asciidoc command
            $cmdline += "asciidoctor-pdf"
            $extension = ".pdf"
        }

        "html" {
            $cmdline += "asciidoctor"
            $extension = ".html"
        }
    }

    # Read in the configuration file, if one has been specified
    if (Test-Path -Path $config) {
        # Read in the config using and merge with the empty settings hashtable
        $data = Get-Content -Path $config -Raw | ConvertFrom-Json -AsHashtable
        $settings = Merge-Hashtables -Primary $data -Secondary $settings
    }

    # If any attributes have been set, update the settings with them
    if ($attributes.count -gt 0) {
        $settings.$($PSCmdlet.ParameterSetName).attributes = $attributes
    }


    # if any attributes have been set, iterate around them and add the correct args and ensure any tokens have
    # been replaced
    foreach ($attr in $settings.$($PSCmdlet.ParameterSetName).attributes) {

        # Replace any values in the attribute
        $_attr = Replace-Tokens -tokens $tokens -data $attr

        $cmdline += '-a {0}' -f $_attr
    }

    # If any libraries have been specified add them to the command line as well
    if ($settings.libs.count -gt 0) {
        $cmdline += '-r {0}' -f ($settings.libs -join ",")
    }

    # Handle scenario where the output filename has been specified on the command line
    # this will then override the title and the output in the tokens
    if (![String]::IsNullOrEmpty($output)) {
        $settings.title = Split-Path -Path $output -Leaf
        $settings.output = Split-Path -Path $output -Parent
    }

    # Determine if the extension needs to be set on the filename
    if ($settings.title.EndsWith($extension)) {
        $extension = ""
    }

    if (![String]::IsNullOrEmpty($path)) {
        $settings.path = $path
    }

    # Ensure the tokens are replaced the settings
    $settings.output = Replace-Tokens -Tokens $tokens -Data $settings.output
    $settings.path = Replace-Tokens -Tokens $tokens -Data $settings.path
    $settings.title = Replace-Tokens -Tokens $tokens -Data $settings.title

    # Ensure that the path exists, if it does not error out
    if (!(Test-Path -Path $settings.path)) {
        Stop-Task -Message ("Specified path does not exist: {0}" -f $settings.path)
        return
    }

    # Update the cmdline with the arguments for the specifying the output filename
    $cmdline += '-o "{0}{1}"' -f $settings.title, $extension
    $cmdline += '-D "{0}"' -f $settings.output

    Write-Information -MessageData ("Output directory: {0}" -f $settings.output) -InformationAction Continue

    # Ensure that the output directory exists
    if (!(Test-Path -Path $settings.output)) {
        Write-Information -MessageData "Creating output directory" -InformationAction Continue
        New-Item -ItemType Directory -Path $settings.output | Out-Null
    }

    # Stitch the full command together
    $cmd = "{0} {1} {2}" -f $cmd, ($cmdline -join " "), (Replace-Tokens -Tokens $tokens $settings.path)

    # Execute the command
    Invoke-External -Command $cmd

    # Output the exitcode of the command
    $LASTEXITCODE
}
function Invoke-DotNet() {

    <#
    
    .SYNOPSIS
    Runs various different `dotnet` commands to perform builds and tests

    .DESCRIPTION
    This cmdlet executes the `dotnet` command to perform different aspects of building a .NET applications.
    It is designed to run all all of the necessary commands associated with a particular step.

    .EXAMPLE

    Invoke-DotNet -Build -Path src

    Perform a build using `dotnet` in the src directory

    .EXAMPLE

    Invoke-Dotnet -Tests -pattern "*UnitTests*" -arguments "--logger 'trx'"

    Perform all of the tests taht match the "UnitTests" patterns across the project. Pass the `--logger 'trx'` as a argument
    to the dotnet command.

    #>

    [CmdletBinding()]
    param (
        
        [Parameter(
            ParameterSetName="build"
        )]
        [switch]
        # Run .NET Build
        $build,

        [Alias("folder", "project", "workingDirectory")]
        [string]
        # Directory that the build should be performed in
        $path,

        [Parameter(
            ParameterSetName="coverage"
        )]
        [switch]
        # Run .NET coverage command
        $coverage,

        [Parameter(
            ParameterSetName="coverage"
        )]
        [string]
        # Type of report that should be generated
        $type = "Cobertura",

        [Parameter(
            ParameterSetName="coverage"
        )]
        [Parameter(
            ParameterSetName="tests"
        )]        
        [string]
        # Pattern used to find the files defining the coverage
        $pattern,

        [Parameter(
            ParameterSetName="coverage"
        )]
        [Alias("destination")]
        [string]
        # Target folder for outputs
        $target = "coverage",

        [Parameter(
            ParameterSetName="coverage"
        )]
        [string]
        # Target folder for outputs
        $source,

        [Parameter(
            ParameterSetName="tests"
        )]
        [switch]
        # Run .NET unit tests
        $tests,

        [Parameter(
            ParameterSetName="custom"
        )]
        [switch]
        # Run an arbitary dotnet command that is not currently defined
        $custom,

        [string]
        # Any additional arguments that should be passed to the command
        $arguments = $env:DOTNET_ARGUMENTS

    )

    # If a working directory has been specified and it exists, change to that dir
    if (![String]::IsNullOrEmpty($path) -and
        (Test-Path -Path $path)) {
        Push-Location -Path $path -StackName "dotnet"
    }

    # Perform the appropriate action based on the Parameter Set Name that
    # has been selected
    switch ($PSCmdlet.ParameterSetName) {
        "build" {
            # Find the path to the command to run
            $dotnet = Find-Command -Name "dotnet"

            # Output the directory that the build is working within
            Write-Information -MessageData ("Working directory: {0}" -f $path) -InformationAction Continue

            # Define the command that needs to be run to perform the build
            $cmd = "{0} build {1}" -f $dotnet, $arguments
        }

        "coverage" {

            # Find the path to the the reportgenerator command
            $tool = Find-Command -Name "reportgenerator"

            # Set the pattern if it has not been defined
            if ([String]::IsNullOrEmpty($pattern)) {
                $pattern = "*.opencover.xml"
            }

            # Find all the files that match the pattern for coverage
            if (![IO.Path]::IsPathRooted($pattern)) {
                $coverFiles = Find-Projects -Pattern $pattern -Path $path
            } else {
                if (Test-Path -Path $pattern) {
                    $coverFiles = @(,(Get-ChildItem -Path $pattern))
                }
            }

            # Test to see if any cover files have been found, if not output an error
            # and return
            if ($coverFiles.count -eq 0) {
                Write-Error -Message ("No tests matching the pattern '{0}' can be found" -f $pattern)
                return
            }

            # create a list of the full path to each coverfile
            $list = $coverFiles | ForEach-Object { $_.FullName }

            # Build up the command that should be executed
            $cmdParts = @(
                $tool
                "-reports:{0}" -f ($list -join ";")
                "-targetDir:{0}" -f $target
                "-reporttypes:{0}" -f $type
            )

            if (![String]::IsNullOrEmpty($source)) {
                $cmdParts += "-sourcedirs:{0}" -f $source
            }

            $cmdParts += $arguments

            $cmd = $cmdParts -join " "
        }

        "custom" {

            # error if no arguments have been set
            if ([string]::IsNullOrEmpty($arguments)) {
                Write-Error -Message "Arguments must be specified when running a custom dotnet command"
                return
            }

            # Find the path to the command to run
            $dotnet = Find-Command -Name "dotnet"

            # Build up the command
            $cmd = "{0} {1}" -f $dotnet, $arguments
        }

        "tests" {

            # Find the path to the command to run
            $dotnet = Find-Command -Name "dotnet"

            # check that a pattern has been specified
            if ([string]::IsNullOrEmpty($pattern)) {
                Write-Error -Message "A pattern must be specfied to find test files"
                return
            }

            # Find all the test files according to the pattern
            $unittests = Find-Projects -Pattern $pattern -Path $path

            if ($unittests.count -eq 0) {
                Write-Error -Message ("No tests matching the pattern '{0}' can be found" -f $pattern)
                return
            }

            # Create a list of commands that need to be run
            $cmd = @()
            foreach ($unittest in $unittests) {
                $cmd += "{0} test {1} {2}" -f $dotnet, $unittest.FullName, $arguments
            }
        }
    }

    # Execute the command
    Invoke-External -Command $cmd

    # Output the exitcode of the command
    $LASTEXITCODE

    # Move back to the original directory
    if ((Get-Location -StackName "dotnet" -ErrorAction SilentlyContinue).length -gt 0) {
        Pop-Location -StackName "dotnet"
    }
}
function Invoke-GitClone() {

    <#
    
    .SYNOPSIS
    Clones a Git repository

    .DESCRIPTION
    This cmdlet will clone a repsoitory from the specified Git provider.

    The repoUrl parameter is used to state where the repository should be retrieved from. This
    can be a short name or a full URL.

    If a short name is provided, e.g. amido/stacks-dotnet, the cmdlet will build up the archive URL
    that will be used download the archive an unpack it.

    Git is not used to get the repository, this is so that there is no dependency on the command
    and means that the URL requested has to be to a zip file for the archive. This is determined
    automatically if using GitHub as the provider.

    .NOTES
    Whilst the cmdlet has been designed so that other providers, such as GitHub, are supported
    for shortnames, it has not been extended beyond GitHub.

    If a repository needs to be retrieved from a different provider please use the full URL
    as the repoUrl parameter.

    .EXAMPLE
    Invoke-GitClone -repo amido/stacks-pipeline-templates -ref refs/tags/v2.0.6 -path support

    As the default provider is GitHub this will result in the archive https://github.com/amido/stacks-pipeline-templates/archive/refs/tags/v.2.06.zip
    being downloaded and unpacked into the `support` directory.

    #>
    
    [CmdletBinding()]
    param (

        [string]
        # Type of VCS to clone from
        $type = "github",

        [string]
        # Path that the repo should be cloned into
        $path = (Get-Location),

        [string]
        [Alias("uri")]
        # Name of the repository to clone
        $repoUrl = $env:AMIDOBUILD_REPOURL,

        [string]
        # Reference to use to download the Zip file for the repository
        $ref,

        [string]
        # The trunk branch to use if ref is empty
        $trunk = "main"
    )

    # if a repo has not been specified then error
    if ([String]::IsNullOrEmpty($repoUrl)) {
        Write-Error -Message "A repository to clone must be specified"
        return
    }

    # If the ref is empty then use $trunk
    if ([String]::IsNullOrEmpty($ref) -or $ref -eq "latest") {
        $ref = $trunk
    }

    # If path is not rooted append it to the current directory
    if (![IO.Path]::IsPathRooted($path)) {
        $path = [IO.Path]::Combine((Get-Location).Path, $path)
    }

    # Create the path if it does not exist
    if (!(Test-Path -Path $path)) {
        New-Item -ItemType Directory -Path $path | Out-Null
    }

    # If the repo is not a web address build it up
    if (!(Confirm-IsWebAddress -address $repoUrl)) {
        switch ($type) {
            # Build up the URL to download the repo from the ArchiveUrl, if the type is GitHub
            "github" {
                $repoUrl = "https://github.com/{0}/archive/{1}.zip" -f $repoUrl, $ref
            }

            default {
                Write-Error -Message ("Remote source control system is not supported: {0}" -f $type)
                return
            }
        }
    }

    Write-Verbose $repoUrl

    # Determine the path that the zip file should be dowloaded to
    # - create a safeFileName that does not have any strange characters in it
    $url = [System.Uri]$repoUrl
    $safeName = ($url.LocalPath).TrimStart("/") -replace "archive/", ""
    $safeName = $safeName -replace "/", "_"

    $zipPath = [IO.Path]::Combine($path, $safeName)

    Write-Verbose $zipPath

    try {

        # Build up the command to download the zip file
        Invoke-WebRequest -Uri $repoUrl -UseBasicParsing -ErrorAction Stop -OutFile $zipPath

    } catch {

        $_.Exception.Response.StatusCode
        return
    }

    # If the zipPath exists, unpack the zip file
    if (Test-Path -Path $zipPath) {

        # Build up the command to unzip the zip file
        Expand-Archive -Path $zipPath -Destination $path

        # if the ref has been set and is a tag, get the version number
        if ($ref -match "v(.*)") {
            $ref = $matches.1
        }

        # Move the unpacked dir to a dir named after the repo name
        $expandedPath = [IO.Path]::Combine($path, ("{0}-{1}" -f $name, $ref))
        $newPath = [IO.Path]::Combine($path, $name)

        Write-Debug $expandedPath
        Write-Debug $newPath

        Move-Item -Path $expandedPath -Destination $newPath

        Remove-Item -Path $zipPath -Confirm:$false -Force
    }
}
function Invoke-Helm() {

    <#

    .SYNOPSIS
    Is a wrapper around the `helm` command for deployment

    .DESCRIPTION
    To help with the invoking the necessary commands for `helm` this cmdlet wraps
    the login and the deploy or rollout sub command. This is its primary function, although
    custom commands can be passed to the cmdlet for situations where deploy and rollout do
    not suffice.

    `custom` - perform any `helm` command using the arguments
    `install` - performs a 'helm upgrade --install command

    The cmdlet can target Azure and AWS clusters. To specify which one is required the `provider`
    parameter needs to be set. For the identification of the cluster the name needs to be specified
    as well as an identifier. Please see the `identifier` parameter for more information.

    .EXAMPLE
    ,

    .EXAMPLE
    .
    #>

    [CmdletBinding()]
    param (

        [Parameter(
            ParameterSetName="install"
        )]
        [switch]
        # Run the install command of helm
        $install,

        [Parameter(
            ParameterSetName="custom"
        )]
        [switch]
        # Allow a custom command to be run. This allows for the scenario where the function
        # does not support the command that needs to be run
        $custom,

        [Parameter(
            ParameterSetName="repo"
        )]
        [switch]
        # Allow a repository to be added
        $repo,

        [string[]]
        [Alias("properties")]
        # Arguments to pass to the helm command
        $arguments,

        [string]
        [ValidateSet('azure', 'aws', IgnoreCase)]
        # Cloud Provider
        $provider,

        [string]
        # Target K8S cluster resource name in Cloud Provider
        $target,

        [string]
        # Unique identifier for K8S in a given Cloud Provider: region for AWS, resourceGroup for Azure, project for GKE
        $identifier,

        [bool]
        # Whether to authenticate to K8S, defaults to true
        $k8sauthrequired = $true,

        [string]
        # Path to a values file
        $valuepath,

        [string]
        # Path to a chart resource
        $chartpath,

        [string]
        # Name of the release
        $releasename,

        [string]
        # Namespace to deploy the release into
        $namespace,

        [string]
        $repositoryName,

        [string]
        $repositoryUrl

    )

    # Define parameter checking vars
    $missing = @()
    $checkParams = @()

    switch ($PSCmdlet.ParameterSetName) {
        "install" {
            # Check that some arguments have been set
            $checkParams = @("provider", "target", "identifier", "namespace", "releasename","namespace")
        }

        "repo" {
            $checkParams = @("repositoryName", "repositoryUrl")
        }

        "custom" {
            $checkParams = @("arguments")
        }

    }

    # Ensure that all the required parameters have been set:
    foreach ($parameter in $checkParams) {
        if ([string]::IsNullOrEmpty((Get-Variable -Name $parameter).Value)) {
            $missing += $parameter
        }
    }

    # if there are missing parameters throw an error
    if ($missing.length -gt 0) {
        Write-Error -Message ("Required parameters are missing: {0}" -f ($missing -join ", "))
        exit 1
    }

    $login =  {
        Param(
            [string]
            [ValidateSet('azure', 'aws', IgnoreCase)]
            $provider,

            [string]
            $target,

            [string]
            $identifier,

            [bool]
            $k8sauthrequired = $true
        )

        switch ($provider) {
            "Azure" {
                Invoke-Login -Azure -k8s:$k8sauthrequired -k8sName $target -resourceGroup $identifier
            }
            "AWS" {
                Invoke-Login  -AWS -k8s:$k8sauthrequired -k8sName $target -region $identifier
            }
            default {
                Write-Error -Message ("Cloud provider not supported for login: {0}" -f $provider)
            }
        }
    }

    # Find the helm binary
    $helm = Find-Command -Name "helm"

    $commands = @()

    # Build up and execute the commands that need to be run
    switch ($PSCmdlet.ParameterSetName) {
        "install" {
            # Invoke-Login
            $login.Invoke($provider, $target, $identifier, $k8sauthrequired)

            # Check that some arguments have been set
            $commands += "{0} upgrade {1} {2} --install --namespace {3} --create-namespace --atomic --values {4}" -f $helm, $releasename, $chartpath, $namespace, $valuepath
        }

        "repo" {
            $commands += "{0} repo add {1} {2}" -f $helm, $repositoryName, $repositoryUrl
        }

        "custom" {
            # Invoke-Login
            $login.Invoke($provider, $target, $identifier, $k8sauthrequired)

            # Build up the command that is to be run
            $commands = "{0} {1}" -f $helm, ($arguments -join " ")
        }
    }

    if ($commands.count -gt 0) {
        Invoke-External -Command $commands

        # Stop the task if the LASTEXITCODE is greater than 0
        if ($LASTEXITCODE -gt 0) {
            Stop-Task -ExitCode $LASTEXITCODE
        }
    }
}
function Invoke-Inspec() {

    <#

    .SYNOPSIS
    Performs infrastructure tests against resources using Inspec

    .DESCRIPTION
    Infrastructure testing is good practice for a number of reasons:

    1. Ensuring what has been deployed is as expected
    2. Checking that there is no configuration drift over time
    3. Ensure that supported versions of resources, such as AKS, are being used

    To help achieve this, this cmdlet will run the Inspec tests against the deployed infrastrtcure.
    The tests have to be written and part of the repository from which the build is running.

    The cmdlet has three distinct phases, `init`, `vendor` and `exec`.

    The `init` switch is used to initialise Inspec and ensure that it is configured with the correct
    provider and can execute the tests.

    The `vendor` switch is used to ensure that all dependencies and providers are downlaoded. This is
    useful if the tests are already initialised and the dependency list has been updated. This is more
    relevant to a developing and testing from a workstation rather than in a pipeline.

    The `exec` switch is used to perform the tests against the deployed infrastructure.

    When the tests are run they are generated using the JUnit format so that they can be
    uploaded to the CI/CD system as test results.

    Authentication for the Azure provider is achieved by setting the necessary values in the
    CLIENT_ID, CLIENT_SECRET, TENANT_ID, and SUBSCRIPTION_ID environment variables.

    For AWS the authentication environment variables to be set are AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
    AWS_REGION and AWS_AVAILABILTY_ZONE

    .EXAMPLE
    Invoke-Inspec -exec -path . -cloud azure

    This will run the tests from the current directory and target the Azure provider.

    #>

    [CmdletBinding()]
    param (

        [string]
        # Path to the inspec test files
        $path = $env:TESTS_PATH,

        [Parameter(
            ParameterSetName = "init"
        )]
        [switch]
        # Initialise Inspec
        $init,

        [Parameter(
            ParameterSetName = "exec"
        )]
        [switch]
        $execute,

        [Parameter(
            ParameterSetName = "exec"
        )]
        [string]
        $cloud = $env:CLOUD_PLATFORM,

        [Parameter(
            ParameterSetName = "exec"
        )]
        [string]
        # Name of the report file
        $reportFileName = $env:REPORT_FILENAME,

        [Parameter(
            ParameterSetName = "vendor"
        )]
        [switch]
        $vendor,

        [Alias("args")]
        [string[]]
        # Arguents to be passed to the command
        $arguments = $env:INSPEC_ARGS,

        [string]
        # Output path for test report
        $output = $env:INSPEC_OUTPUT_PATH

    )

    # Setflag to state if the directory has been changed
    $changedDir = $false

    # Define the inspec command that should be executed
    $command = ""

    # Set a list of parameters that are expected
    $list = @()

    if ([string]::IsNullOrEmpty($path)) {
        Stop-Task -Message "Path to the Inspec test files must be specified"
    }

    if (!(Test-Path -Path $path)) {
        Stop-Task -Message ("Specfied path for Inspec files does not exist: {0}" -f $path)
    }

    # Determine the directory of the path and change to it
    $dir = $path
    if (!((Get-Item -Path $path) -is [System.IO.DirectoryInfo])) {
        $dir = Split-Path -Path $path -Parent
    }

    Push-Location -Path $dir
    $changedDir = $true

    # Confirm the required parameters for different switches
    # Ensure that a cloud platform has been supplied if running exec
    if (@("exec").Contains($PSCmdlet.ParameterSetName)) {
        # add to the list of parameters that need to be specified
        $list += "cloud"
    }

    $result = Confirm-Parameters -List $list
    if (!$result) {
        return
    }

    # Find the Inspec command to run
    $inspec = Find-Command -Name "inspec"

    Write-Information -MessageData ("Working directory: {0}" -f (Get-Location))

    # Select the operation to run based on the switch
    switch ($PSCmdlet.ParameterSetName) {

        # Initalise Inspec
        "init" {
            $command = "{0} init" -f $inspec
        }

        # Execute inspec
        "exec" {

            # Create an array to hold each part of the overall command
            # This is because the order of the commands is important, e.g. any inputs that have been specfied
            # in the arguments need to be put at the end of the command
            # The array will be joined together to make the command

            # Add the necessary initial parts
            $cmd_parts = @($inspec, "exec", ".")

            # Add in the cloud
            $cmd_parts += "-t {0}://" -f $cloud

            # Ensure that the results are show on the console
            $cmd_parts += "--reporter cli"

            # If an output path has been passed add it to the array
            if (![String]::IsNullOrEmpty($output)) {

                # if hte output does not exist create it
                if (!(Test-Path -Path $output)) {
                    New-Item -ItemType Directory -Path $output
                }

                # Check that a reportFilename has been specified, if not generate the filename
                if ([String]::IsNullOrEmpty($reportFileName)) {
                    $reportFileName = "inspec_tests_{0}_{1}.xml" -f $cloud, (Split-Path -Path $path -Leaf)
                }

                $cmd_parts += "junit2:{0}" -f ([IO.Path]::Combine($output, $reportFileName))
            }

            # Extract any inputs that have been found in the arguments and ensure they are places
            # at the end of the command
            # This is because inpsec interprets the --input argument as taking everyting after it

            # Define the pattern to use to find the inputs in the argumnents string
            $pattern =  "(\s*?--input.*?(?= --))"

            # Get a string of the arguments to work with
            $_args = $arguments -join " "

            # Extract the inputs from the string
            $inputs = ""
            if ($_args -match $pattern) {
                $inputs = $matches[1].Trim()
            }

            # Replace the inputs in the $_args with null so that they can be place int he correct place
            $a = ($_args -replace $pattern, "").Trim()

            # Add to the results to the $cmd_parts
            if (![String]::IsNullOrEmpty($a)) {
                $cmd_parts += $a
            }

            if (![String]::IsNullOrEmpty($inputs)) {
                $cmd_parts += $inputs
            }

            $command = $cmd_parts -join " "

            # if an output path has been specified generate a report of the tests

        }

        # Vendor all of the libraries and providers that need to be installed
        "vendor" {
            $command = "{0} vendor . {1}" -f $inspec, ($arguments -join (" "))
        }
    }

    # Run the command that has been built up
    if (![string]::IsNullOrEmpty($command)) {
        Invoke-External -Command $command
    }

    # Change back to the original dirrectory if changed at the begining
    if ($changedDir) {
        Pop-Location -ErrorAction SilentlyContinue
    }
}
function Invoke-Kubectl() {

    <#
    
    .SYNOPSIS
    Is a wrapper around the `kubectl` command for deployment

    .DESCRIPTION
    To help with the invoking the necessary commands for `kubectl` this cmdlet wraps
    the login and the deploy or rollout sub command. This is its primary function, although
    custom commands can be passed to the cmdlet for situations where deploy and rollout do
    not suffice.

    `apply` - deploy one or more manifest files to the kubernetes cluster
    `custom` - perform any `kubectl` command using the arguments 
    `rollout` - performs the rollout command using the specified arguments

    The cmdlet can target Azure and AWS clusters. To specify which one is required the `provider`
    parameter needs to be set. For the identification of the cluster the name needs to be specified
    as well as an identifier. Please see the `identifier` parameter for more information.

    .EXAMPLE
    Invoke-Kubectl -apply -arguments @("manifest1.yml", "manifest2.yml") -provider azure -target myakscluster -identifier myresourcegroup

    Apply the specified manifest files, if they can be located, to the named cluster in azure

    .EXAMPLE
    Invoke-Kubectl custom -arguments @("get", "ns") -provider azure -target myakscluster -identifier myresourcegroup

    Perform a custom command and list all the namespaced in the cluster.

    #>

    [CmdletBinding()]
    param (

        [Parameter(
            ParameterSetName="apply"
        )]
        [switch]
        # Run the apply command of Kubectl
        $apply,

        [Parameter(
            ParameterSetName="rollout"
        )]
        [switch]
        # Run the rollout command of Kubectl
        $rollout,
        
        [Parameter(
            ParameterSetName="custom"
        )]
        [switch]
        # Allow a custom command to be run. This allows for the scenario where the function
        # does not support the command that needs to be run
        $custom,          

        [string[]]
        [Alias("properties")]
        # Arguments to pass to the kubectl command
        $arguments,

        [string]
        [ValidateSet('azure','aws',IgnoreCase)]
        # Cloud Provider
        $provider,

        [string]
        # Target K8S cluster resource name in Cloud Provider
        $target,

        [string]
        # Unique identifier for K8S in a given Cloud Provider: region for AWS, resourceGroup for Azure, project for GKE
        $identifier

    )
    $missing = @()
    # Ensure that all the required parameters have been set
    foreach ($parameter in @("provider", "target", "identifier")) {

        # check each parameter to see if it has been set
        if ([string]::IsNullOrEmpty((Get-Variable -Name $parameter).Value)) {
            $missing += $parameter
        }
    }

    # if there are missing parameters throw an error
    if ($missing.length -gt 0) {
        Write-Error -Message ("Required parameters are missing: {0}" -f ($missing -join ", "))
    } else {

        switch ($provider) {
            "Azure" {
                Invoke-Login -Azure -k8s -k8sName $target -resourceGroup $identifier
            }
            "AWS" {
                Invoke-Login  -AWS -k8s -k8sName $target -region $identifier
            }
            default {
                Write-Error -Message ("Cloud provider not supported for login: {0}" -f $provider)
            }
        } 

        # Find the kubectl command to use
        $kubectl = Find-Command -Name "kubectl"

        $commands = @()

        # build up and execute the commands that need to be run
        switch ($PSCmdlet.ParameterSetName) {
            "apply" {
                # Check that some arguments have been set
                if ($arguments.Count -eq 0) {
                    Write-Error -Message "No manifest files have been specified"
                    exit 1
                }

                # Iterate around the arguments that have been specified and deploy each one
                foreach ($manifest in $arguments) {

                    # check that the manifest exists
                    if (!(Test-Path -Path $manifest)) {
                        Write-Warning -Message ("Unable to find manifest file: {0}" -f $manifest)
                    } else {
                        $commands += "{0} apply -f {1}" -f $kubectl, $manifest
                        # Invoke-External -Command $command
                    }
                }
            }

            "custom" {
                # Build up the command that is to be run
                $commands = "{0} {1}" -f $kubectl, ($arguments -join " ")
            }


            "rollout" {
                # Build up the full kubectl command
                $commands = "{0} rollout {1}" -f $kubectl, ($arguments -join " ")
                
            }
        }

        if ($commands.count -gt 0) {
            Invoke-External -Command $commands
        }
    }
}
function Invoke-Login() {

    <#
    
    .SYNOPSIS
    Login into an AKS or AWS Kubernetes cluster

    .DESCRIPTION
    When using the `Invoke-Kubectl` cmdlet it needs to be able to authenticate against the cluster
    This cmdlet performs that role and ensures that it is logging in using the `az` (for Azure) or 
    the `aws` (for AWS) commands. It is a wrapper to easily perform the login.
    
    .EXAMPLE

    $env:ARM_CLIENT_ID = "xxxx-xxxx-xxxx-xxxx"
    $env:ARM_CLIENT_SECRET = "lkjdsfasdlkjasdfkasd"
    $env:ARM_TENANT_ID = "xxxx-xxxx-xxxx-xxxx"
    $env:ARM_SUBSCRIPTION_ID = "xxxx-xxxx-xxxx-xxxx"
    Invoke-Login -k8s -k8sname mycluster -resourceGroup mygroup -azuree

    Performs a login to the specified clustyer in Azure and exports the credentials innto the environments
    so that subsequent 

    #>

    [CmdletBinding()]
    param (
        [switch]
        # Specify if Kubernetes credentials should be retrieved
        $k8s,

        [string]
        # Name of the cluster to get credentials for
        $k8sName,

        [Parameter(ParameterSetName="azure")]
        [switch]
        # Switch for Azure. Not a param to avoid complications around parameterset exceptions and env var usage.
        $azure,

        [Parameter(ParameterSetName="azure")]
        [string]
        # If logging into AKS then set the resource group that the cluster is in
        $resourceGroup,

        [Parameter(ParameterSetName="azure")]
        [string]
        # Tenant ID for the account
        $tenantId = $env:ARM_TENANT_ID,

        [Parameter(ParameterSetName="azure")]
        [string]
        # ID of the subscription to use for resources
        $subscriptionId = $env:ARM_SUBSCRIPTION_ID,

        [Parameter(ParameterSetName="azure")]
        [Alias("clientId")]
        [string]
        # Username to use to access the specifiec cloud
        # For Azure this will the value for azurerm_client_id
        $username = $env:ARM_CLIENT_ID,

        [Parameter(ParameterSetName="azure")]
        [Alias("clientSecret")]
        [string]
        # Password to be used - this is not leveraged as a SecureString, so it can be sourced from an environment variable
        # For Azure this will be the value for azurerm_client_secret
        $password = $env:ARM_CLIENT_SECRET,

        [Parameter(ParameterSetName="aws")]
        [switch]
        # Switch for AWS. Not a param to avoid complications around parameterset exceptions and env var usage.
        $aws,

        [Parameter(ParameterSetName="aws")]
        [string]
        # Cloud being connected to
        $key_id = $env:AWS_ACCESS_KEY_ID,

        [Parameter(ParameterSetName="aws")]
        [string]
        # Password to be used
        # For AWS this will be the value for AWS_SECRET_ACCESS_KEY
        $key_secret = $env:AWS_SECRET_ACCESS_KEY,

        [string]
        [Parameter(ParameterSetName="aws")]
        # If logging into EKS then set the resource group that the cluster is in
        $region = $env:AWS_DEFAULT_REGION
    )

    $missing = @()

    # if running in dry run mode do not attempt to login
    if (Get-Variable -Name Session -Scope global -ErrorAction SilentlyContinue) {
        if ($global:Session.dryrun) {
          Write-Debug "Dry-Run session, not running anything"
          return
        }
    }

    # Perform the necessary login based on the specified cloud
    switch ($PSCmdlet.ParameterSetName) {
        "azure" {

            # Ensure that all the required parameters have been set
            foreach ($parameter in @("tenantId", "subscriptionId", "username", "password")) {

                # check each parameter to see if it has been set
                if ([string]::IsNullOrEmpty((Get-Variable -Name $parameter).Value)) {
                    $missing += $parameter
                }
            }

            # if there are missing parameters throw an error
            if ($missing.length -gt 0) {
                Write-Error -Message ("Required parameters are missing: {0}" -f ($missing -join ", "))
            } else {

                # Connect to Azure
                Connect-Azure -clientId $username -secret $password -subscription $subscriptionId -tenantId $tenantId

                # Import AKS credentials if specified
                if ($k8s.IsPresent) {

                    foreach ($parameter in @("k8sname", "resourceGroup")) {

                        # check each parameter to see if it has been set
                        if ([string]::IsNullOrEmpty((Get-Variable -Name $parameter).Value)) {
                            $missing += $parameter
                        }
                    }

                    # if there are missing parameters throw an error
                    if ($missing.length -gt 0) {
                        Write-Error -Message ("Required K8S parameters are missing: {0}" -f ($missing -join ", "))
                    } else {
                        Import-AzAksCredential -ResourceGroupName $resourceGroup -Name $k8sName -Force
                    }
                }
            }
        }

        "aws" {

            # Ensure that all the required parameters have been set
            foreach ($parameter in @("region", "key_id", "key_secret")) {

                # check each parameter to see if it has been set
                if ([string]::IsNullOrEmpty((Get-Variable -Name $parameter).Value)) {
                    $missing += $parameter
                }
            }

            # if there are missing parameters throw an error
            if ($missing.length -gt 0) {
                Write-Error -Message ("Required parameters are missing: {0}" -f ($missing -join ", "))
            } else {
                Write-Debug -Message ("AWS env vars for AWS_ACCESS_KEY_ID={0} , and AWS_SECRET_ACCESS_KEY (not shown) and AWS_DEFAULT_REGION={1} found OK" -f $key_id, $region)

                # Import EKS credentials if specified
                if ($k8s.IsPresent) {

                    foreach ($parameter in @("k8sname", "region")) {

                        # check each parameter to see if it has been set
                        if ([string]::IsNullOrEmpty((Get-Variable -Name $parameter).Value)) {
                            $missing += $parameter
                        }
                    }

                    # if there are missing parameters throw an error
                    if ($missing.length -gt 0) {
                        Write-Error -Message ("Required K8S parameters are missing: {0}" -f ($missing -join ", "))
                    } else {
                        Connect-EKS -name $k8sName -region $region
                    }
                }
            }
        }

        default {

            if ([string]::IsNullOrEmpty($cloud)) {
                Write-Error -Message "A cloud platform must be specified"
            } else {
                Write-Error -Message ("Specified cloud is not supported: {0}" -f $cloud)
            }

            return
        }
    }
}
function Invoke-SonarScanner() {

    <#
    
    .SYNOPSIS
    Starts or stops the SonarScanner utility when running a build and tests

    .DESCRIPTION
    When running build SonarScanner can be started so that it checks the code for
    vulnerabilities. This is invaluable when building applicatios to minimise risk
    in the final application.

    SonarScanner works by starting the process which then runs in the background.
    The build and the tests are then executed and when they are complete the SonarScanner
    process is stopped, at which point the results and analysed and report is generated.

    This command uses Sonar Cloud so it needs to have a token for credentials as well
    as the name of the project and the organisation for which the scan is being performed.

    .NOTES
    If using this tool as part of a Stacks pipeline and thus using Taskctl, all of the commands
    need to be wrapped together in the same task. This is because the start process of 
    SonarScanner sets up the environment for it to be able to check the build and tests. If this
    is run in a separate task to the build then the environment is lost.

    The way around this is to run everything in the same task, for example:

    [source,powershell]
    ---
    Invoke-SonarScanner -start &&
    Invoke-DotNet -Build -Path $env:SELF_REPO_SRC &&
    Invoke-DotNet -Tests -pattern "*UnitTests" -arguments "--logger 'trx' --results-directory /app/testresults -p:CollectCoverage=true -p:CoverletOutputFormat=opencover -p:CoverletOutput=/app/coverage/" &&
    Invoke-DotNet -Tests -pattern "*ComponentTests" -arguments "--logger 'trx' --results-directory /app/testresults -p:CollectCoverage=true -p:CoverletOutputFormat=opencover -p:CoverletOutput=/app/coverage/" &&
    Invoke-DotNet -Tests -pattern "*ContractTests" -arguments "--logger 'trx' --results-directory /app/testresults -p:CollectCoverage=true -p:CoverletOutputFormat=opencover -p:CoverletOutput=/app/coverage/" &&
    Invoke-DotNet -Coverage -target /app/coverage &&
    Remove-Item Env:\SONAR_PROPERTIES &&
    Invoke-SonarScanner -stop
    ---

    .EXAMPLE
    Invoke-SonarScanner -start -projectname myproject -org myorg -buildversion 100.98.99 -url "https://sonarscanner.example" token 122345
    --Run build and tests--
    Invoke-SonarScanner -stop -token 122345

    Starts the SonarScanner with the necessary properties set on the command line. The
    build and tests and then run and the process is stopped using the same token as before.

    .EXAMPLE
    $env:PROJECT_NAME = "myproject"
    $env:BUILD_BUILDNUMBER = "100.98.99"
    $env:SONAR_ORG = "myorg"
    $env:URL = "https://sonarscanner.example"
    $env:SONAR_TOKEN = "122345"
    Invoke-SonarScanner -start
    --Run build and tests--
    Invoke-SonarScanner -stop

    Performs the same process as the previous example, except that everything required is
    specified using environment variables. This is useful so that information about
    the access to SonardCloud is not accidentally leaked into the logs
    
    #>

    [CmdletBinding()]
    param (

        [Switch]
        # Start the sonarcloud analysis
        $start,

        [Switch]
        # Stop the analysis
        $stop,

        [string]
        # Project name
        $ProjectName = $env:PROJECT_NAME,

        [string]
        # build version
        $BuildVersion = $env:BUILD_BUILDNUMBER,

        [Alias("Host")]
        [string]
        # Sonar Host
        $URL = $env:SONAR_URL,

        [Alias("Organization")]
        [string]
        # Organisation
        $Organisation = $env:SONAR_ORG,

        [string]
        # Security Token
        $Token = $env:SONAR_TOKEN,

        [string]
        # Additional run properties
        $Properties = $env:SONAR_PROPERTIES
    )

    # The token is mandatory, but need to check the environment variables
    # to see if a token has been set
    if ([string]::IsNullOrEmpty($Token)) {
        $Token = $env:SONAR_TOKEN
    }

    # If the token is still empty then throw an error
    if ([string]::IsNullOrEmpty($Token)) {
        Write-Error -Message "A Sonar token must be specified. Use -Token or set SONAR_TOKEN env var"
        return
    }

    if ($start.IsPresent -and $stop.IsPresent) {
        Write-Error -Message "Please specify -start or -stop, not both"
        return
    }

    # Look for the sonarscanner command
    $tool = Find-Command -name "dotnet-sonarscanner"

    # Depending on the modethat has been set, define the command that needs to be run
    if ($start.IsPresent) {

        # Ensure that all the required parameters are specified
        # This is done because the Mandatory check on the parameter does not take into account
        # values from the environment
        $result = Confirm-Parameters -List @("ProjectName", "BuildVersion", "Organisation")
        if (!$result) {
            return
        }

        # Build up the command to run
        # Use an array to this with each option so that items can be easily changed and connected together
        $arguments = @()
        $arguments += "/k:{0}" -f $ProjectName
        $arguments += "/v:{0}" -f $BuildVersion
        $arguments += "/d:sonar.host.url={0}" -f $URL
        $arguments += "/o:{0}" -f $Organisation
        $arguments += "/d:sonar.login={0}" -f $Token
        if (![string]::IsNullOrEmpty($Properties)) {
            $arguments += $Properties
        }

        $cmd = "{0} begin {1}" -f $tool, ($arguments -Join " ")

    }

    if ($stop.IsPresent) {
        $arguments = @()
        $arguments += "/d:sonar.login={0}" -f $Token
        if (![string]::IsNullOrEmpty($Properties)) {
            $arguments += $Properties
        }

        $cmd = "{0} end {1}" -f $tool, ($arguments -Join " ")
    }

    Invoke-External -Command $cmd

    $LASTEEXITCODE
}
function Invoke-Templater() {

    <#
    
    .SYNOPSIS
    Reads all env vars and, optionally, an env file and replaces values in a template file

    .DESCRIPTION
    This cmdlet provides a basic templating engine for files. It uses the the `Expand-Template`
    cmdlet to perform the subsitutions.

    A file is passed to the cmdlet with tokens that need to be replaced, e.g.:

    

    #>

    [CmdletBinding()]
    param (

        [Parameter(
            Mandatory = $true,
            ParameterSetName = "path"
        )]
        [string]
        # path to the list of items
        $path,

        [Parameter(
            ValueFromPipeline=$true
        )]
        [Alias("tfdata")]
        [string]
        # JSON object representing the outputs from Terraform
        $tfoutputs = $env:TERRAFORM_OUTPUT,

        [string]
        # Base directory to use when paths are relative
        $baseDir = "/app"
    )

    # Get all the enviornment variables
    $envvars = [Environment]::GetEnvironmentVariables()

    # iterate around the variables and create local ones
    foreach ($envvar in $envvars.GetEnumerator()) {

        # Exclude the path env var so that the one that is already
        # set does not get overwritten
        if (@("path", "home") -notcontains $envvar.Name) {
            Write-Debug ("Setting variable: {0}" -f $envvar.Name)

            Set-Variable -Name $envvar.Name -Value $envvar.Value
        }
    }

    # if any tfoutputs have been specified, iterate around the object
    # and set variables for the output keys and the associated value
    if (![string]::IsNullOrEmpty($tfoutputs)) {

        # determine if the tfoutputs is a path, if it is get the data from
        # the file
        if (Test-Path -Path $tfoutputs) {
            $tfoutputs = Get-Content -Path $tfoutputs -Raw
        }

        # convert the tfoutputs to a data object
        $data = ConvertFrom-JSON -InputObject $tfoutputs -ErrorAction SilentlyContinue

        # iterate around the data and set local variables
        if ($data) {
            $data | Get-Member -MemberType NoteProperty | ForEach-Object {
                $name = $_.Name
                Set-Variable -Name $name -Value $data.$name.value
            }
        }
    }

    # Check that the specified path exists
    if ($PSCmdlet.ParameterSetName -eq "path") {
        if (!(Test-Path -Path $path)) {
            Write-Error ("Unable to find list file: {0}" -f $path)
            return
        }

        # Ensure that the path specified is a file
        if ((Get-Item $path) -is [System.IO.DirectoryInfo]) {
            Write-Error -Message ("A file must be specified, directory provided: {0}" -f $path)
            return
        }

        try {
            # Get the list of items as an object
            $items = @()
            $items += Invoke-Expression -Command (Get-Content -Path $path -Raw)

            foreach ($item in $items) {
                Write-Information ("Template: {0}" -f $item.template)

                if (![IO.Path]::IsPathRooted($item.template)) {
                    $item.template = [IO.Path]::Combine($baseDir, $item.template)
                }

                $extra = @{}
                $item.vars.GetEnumerator() | ForEach-Object {
                    Write-Debug ("{0} - {1}" -f $_.Name, $_.Value)

                    $rendered = ""

                    if (![string]::IsNullOrEmpty($_.Value)) {
                        $rendered = $ExecutionContext.InvokeCommand.ExpandString($_.Value)
                    }

                    $extra[$_.Name] = $rendered
                }

                Expand-Template -path $item.template -additional $extra
            }

        } catch {

            Write-Debug $_
            Write-Error -Message ("Unable to read specified list file as data. Please ensure that the file contains a valid PowerShell object")
        }
    }
}
function Invoke-Terraform() {


    <#

    .SYNOPSIS
    A wrapper for the Terraform command which will invoke the different commands of
    Terraform as required

    .DESCRIPTION
    The Independent Runner uses Terraform to built up the resources that are required, primairly for ED Stacks,
    but can be for any Terraform defined infrastructure.

    It is a wrapper for the Terraform command and will generate the necessary command from the inputs that the
    cmdlet is given. The benefit of this cmdlet is that it reduces complexity as people do not need to know how
    to build up the Terraform command each time.

    .EXAMPLE
    Invoke-Terraform -init -arguments "false"

    Initialise the Terraform files with a fase backend. This is useful for validation.

    .EXAMPLE
    Invoke-Terraform -plan properties "-input=false", "-out=tf.plan"

    Plan the Terraform deployment using the files in the current directory. The properties that have been passed
    are appended directly to the end of the Terraform command. In this example no missing inputs are requests and
    the plan is written out to the `tf.plan` file.

    .EXAMPLE
    Invoke-Terraform -output -path src/terraform -yaml | Out-File tfoutput.yaml

    This command will get the outputs from the Terraform state and output them as Yaml format. It will only output
    the name and value of the output. This is then piped to Out-File which means that the data will be save to the
    named file for use with other commands.

    #>

    [CmdletBinding()]
    param (

        [string]
        # Path to the terraform files
        $path,

        [Parameter(
            ParameterSetName="apply"
        )]
        [switch]
        # Initalise Terraform
        $apply,

        [Parameter(
            ParameterSetName="custom"
        )]
        [switch]
        # Initalise Terraform
        $custom,

        [Parameter(
            ParameterSetName="format"
        )]
        [switch]
        # Validate templates
        $format,

        [Parameter(
            ParameterSetName="init"
        )]
        [switch]
        # Initalise Terraform
        $init,

        [Parameter(
            ParameterSetName="plan"
        )]
        [switch]
        # Initalise Terraform
        $plan,

        [Parameter(
            ParameterSetName="output"
        )]
        [switch]
        # Initalise Terraform
        $output,

        [Parameter(
            ParameterSetName="output"
        )]
        [switch]
        # Allow the output of senstive values
        $sensitive,

        [Parameter(
            ParameterSetName="output"
        )]
        [switch]
        # Set the output to be Yaml
        $yaml,

        [Parameter(
            ParameterSetName="validate"
        )]
        [switch]
        # Perform validate check on templates
        $validate,

        [Parameter(
            ParameterSetName="workspace"
        )]
        [switch]
        # Initalise Terraform
        $workspace,

        [string[]]
        [Alias("backend", "properties")]
        # Arguments to pass to the terraform command
        $arguments = $env:TF_BACKEND,

        [string]
        # Delimiter to use to split backend config that has been passed as one string
        $delimiter = ","

    )

    # set flag to state if the dir was changed
    $changedDir = $false

    # If the arguments is one element in the array split on the delimiter
    if ($arguments.Count -eq 1) {
        $arguments = $arguments -split $delimiter
    }

    # Check parameters exist for certain cmds
    if (@("init").Contains($PSCmdlet.ParameterSetName)) {
        # Check that some backend properties have been set
        # If they have not then raise an error
        # If they have then check to see if one argument has been raised and if it has split on the comma in case
        #   all the configs have been passed in as one string
        if ($arguments.Count -eq 0 -or ($arguments.Count -eq 1 -and [String]::IsNullOrEmpty($arguments[0]))) {
            Write-Error -Message "No properties have been specified for the backend" -ErrorAction Stop
            return
        }
    }

    if (@("plan", "apply").Contains($PSCmdlet.ParameterSetName)) {
        if ([String]::IsNullOrEmpty($path)) {
            Write-Error -Message "Path to the Terraform files or plan file must be supplied" -ErrorAction Stop
            return
        }

        if (!(Test-Path -Path $path)) {
            Write-Error -Message ("Specified path does not exist: {0}" -f $path) -ErrorAction Stop
            return
        }
    }

    # Find the Terraform command to use
    $terraform = Find-Command -Name "terraform"

    # If a path has been specified and it is a directory
    # change to that path
    if (![string]::IsNullOrEmpty($path)) {

        # determine if the path is a file, and if so get the dir
        $dir = $path
        if (!((Get-Item -Path $dir) -is [System.IO.DirectoryInfo])) {
            $dir = Split-Path -Path $dir -Parent
        }

        Push-Location -Path $dir
        $changedDir = $true
    }

    Write-Information -MessageData ("Working directory: {0}" -f (Get-Location))

    # select operation to run based on the cmd
    switch ($PSCmdlet.ParameterSetName) {

        # Apply the infrastructure
        "apply" {
            $command = "{0} apply {1}" -f $terraform, $path
            Invoke-External -Command $command
        }

        # Run custom terraform command that is not supported by the function
        "custom" {
            $command = "{0} {1}" -f $terraform, ($arguments -join " ")
            Invoke-External -Command $command
        }

        # Initialise terraform
        "init" {

            # Iterate around the arguments
            $a = @()
            foreach ($arg in $arguments) {
                $a += "-backend-config='{0}'" -f $arg
            }

            # Build up the command to pass
            $command = "{0} init {1}" -f $terraform, ($a -join (" "))

            Invoke-External -Command $command
        }

        # Check format of templates
        "format" {

            $command = "{0} fmt -diff -check -recursive" -f $terraform

            Invoke-External -Command $command
        }

        # Plan the infrastrtcure
        "plan" {

            $command = "{0} plan {1}" -f $terraform, ($arguments -join " ")
            Invoke-External -Command $command

        }

        # Output information from the state
        # This will retrieve all the non-sensitive values, if these are required then
        # the -Sensitive switch must been specified
        "output" {

            # Run the command to get the state from terraform
            $command = "{0} output -json" -f $terraform
            $result = Invoke-External -Command $command

            if (![String]::IsNullOrEmpty($result)) {

                $data = $result | ConvertFrom-Json

                # iterate around the data and get the values for all the sensitive variables
                if ($sensitive) {
                    $data | Get-Member -MemberType NoteProperty | ForEach-Object {

                        $name = $_.Name

                        # if if the output is a sensitive value get the value using Terraform
                        if ($data.$name.sensitive) {
                            $value = Invoke-External -Command ("{0} output -raw {1}" -f $terraform, $name)

                            # set the value in the object
                            $data.$name.value = $value
                        }
                    }
                }

                # output the data as JSON unless Yaml has been specified
                if ($yaml) {

                    # As the aim of this is to get the name and value of the keys into a yaml
                    # file for ingestion by Inspec the name and value are the only things required
                    $yamldata = [Ordered] @{}
                    $sortedKeys = $data.PSObject.Properties | Sort-Object Name
                    foreach ($item in $sortedKeys) {
                        $yamldata[$item.Name] = $item.Value.Value
                    }

                    $yamldata | ConvertTo-Yaml
                } else {
                    $data | ConvertTo-Json -Compress
                }
            }
        }

        # Valiate the templates
        "validate" {

            # Run the commands to perform a validation
            $commands = @()
            $commands += "{0} init -backend=false" -f $terraform
            $commands += "{0} validate" -f $terraform

            Invoke-External -Command $commands

            # After validation has run, delete the terraform dir and lock file
            # This is so that it does not interfere with the deployment of the infrastructure
            # when a valid backend is initialised
            Write-Information -MessageData "Removing Terraform init files for 'false' backend"
            $removals = @(
                ".terraform",
                ".terraform.lock.hcl"
            )
            foreach ($item in $removals) {
                if (Test-Path -Path $item) {
                    Remove-Item -Path $item -Recurse -Force
                }
            }
        }


        # Create or select the terraform workspace
        "workspace" {

            if ([String]::IsNullOrEmpty($arguments)) {
                Write-Error -Message "No workspace name specified to create or switch to."
            } else {
                Write-Information -MessageData ("Attempting to select or create workspace: {0}" -f $arguments[0])
                $command = "{0} workspace select -or-create=true {1}" -f $terraform, $arguments[0]
                Invoke-External -Command $command
            }
        }

    }

    if ($changedDir) {
        Pop-Location
    }


}
function Invoke-YamlLint() {

    <#
    
    .SYNOPSIS
    Performs a Yaml Lint, using Python, against all YAML files in the path

    .DESCRIPTION
    Using Python, preferably in a container, this cmdlet will run the yamllint command
    against all of the yaml files in the specified directory.

    A configuration file for yaml lint is expected. By default this the cmdlet will look
    for the file called `yamllint.conf` in the directory from which the cmdlet was invoked.


    .NOTES
    Due to the license of yamllint, it needs to be installed by the cmdlet on each use. This
    is because the license of yamlint is GPL, which means that if we bundled it into a container
    *all* of our code would need to be distibuted under the GPL license. By installing it
    as and when we need it we do not need to do this.

    .EXAMPLE
    Invoke-YamlLint

    Perform a lint for all the yaml files in the current directory

    .EXAMPLE
    Invoke-Yamllint -basepath src/ -config config/config.yml

    Perform a yamllint on all yaml files in the `src/` directory and use a different
    configuration file

    #>

    [CmdletBinding()]
    param (
        [Alias("a")]
        [string]
        # Config File
        $ConfigFile = "yamllint.conf",

        [Alias("b")]
        [string]
        # Base path to search
        $BasePath = (Get-Location),

        [Alias("c")]
        [bool]
        # If true will enable yamllint strict mode
        $FailOnWarnings = $True
    )

    # Check that arguments have been supplied
    if ([string]::IsNullOrEmpty($ConfigFile)) {
        Write-Error -Message "-a, -configfile: Missing path to configuration file"
        return
    }

    if ([string]::IsNullOrEmpty($BasePath)) {
        Write-Error -Message "-b, -basepath: Missing base path to scan"
        return
    }

    # Check that the config file can be located
    if (!(Test-Path -Path $ConfigFile)) {
        Write-Error -Message ("ConfigFile cannot be located: {0}" -f $ConfigFile)
        return
    }

    # Check that the base path exists
    if (!(Test-Path -Path $BasePath)) {
        Write-Error -Message ("Specified base path does not exist: {0}" -f $BasePath)
        return
    }

    # strict mode is enabled with the -s (or --strict) option, the return code will be:
        # • 0 if no errors or warnings occur
        # • 1 if one or more errors occur
        # • 2 if no errors occur, but one or more warnings occur
    $StrictOption = ""
    if ($FailOnWarnings -eq $True ) {
        $StrictOption = "-s"
    }

    # Find the path to python
    # Look for python3, if that fails look for python but then check the version
    $python = Find-Command -Name "python3"
    if ([string]::IsNullOrEmpty($python)) {
        Write-Debug -Message "Cannot find 'python3'. Looking for 'python' and checking version"

        $python = Find-Command -Name "python"

        if ([string]::IsNullOrEmpty($python)) {
            Write-Error -Message "Python3 cannot be found, please ensure it is installed"  -ErrorAction Stop
        }

        # Check the version of pythong
        $cmd = "{0} -V" -f $python
        $result = Invoke-External -Command $cmd

        if (![string]::IsNullOrEmpty($result) -and !$result.StartsWith("Python 3")) {
            Write-Error -Message "Python3 cannot be found, please ensure it is installed"  -ErrorAction Stop
        }
    }

    # Ensure that yamllint is installed and if not install it
    # This is done so that we are no shipping YamlLint in the container we use to run taskctl
    # YamlLint has a GPL 3 licence which means that if we are shipping the code we have to have
    # all of our code be licenced under GPL 3. By installing when we need it we are not shipping source code
    $pip = Find-Command -Name "pip"
    $cmd = "{0} freeze" -f $pip
    $result = Invoke-External -Command $cmd
    $yamllint = $result | Where-Object { ![String]::IsNullOrEmpty($_) -and $_.StartsWith("yamllint") }
    if ([string]::IsNullOrEmpty($yamllint)) {

        Write-Information -MessageData "Installing Python package: yamllint"

        # The package is not installed so install it now
        $cmd = "{0} install yamllint" -f $pip
        Invoke-External -Command $cmd
    }

    # Create the command that needs to be run to perform the lint function
    $cmd = "{0} -m yamllint {3} -c {1} {2} {1}" -f $python, $ConfigFile, $BasePath, $StrictOption
    Invoke-External -Command $cmd

}
function New-EnvConfig() {

    <#

    .SYNOPSIS
    Creates a shell script that can be used to configure the environment variables
    for running the pipeline on a local workstation

    .DESCRIPTION
    A number of configuration items in the Indepdent Runner are set using enviornment variables.
    The `Confirm-Environment` function checks that these environment variables exist.

    This `New-EnvConfig` function is the companion function to `Confirm-Environment`. It uses
    the same configuration file and determines what the missing variables are and creates
    a relevant script file that can be edited to se5t the correct values.

    It is shell aware so if it detects PowerShell it will generate a PowerShell script, but if
    it is a Bash compatible shell it will create a bash script.

    It is cloud and stage aware so by providing these values you will get a script file
    for each of the cloud and stages as required.

    It is recommended that the resultant scripts are NOT checked into source control, so for
    this reason a `local/` directory should be created in the repo and added to the `.gitignore` file.
    All scripts can then be saved to the local folder without them being checked in.

    The shell detection works on a very simple rule, if a SHELL environment var exists then a Bash-like
    shell is assumed, if it does not exist then PowerShell is assumed.

    The filename of the script is determined by the ScriptPath, cloud, stage and detected shell.
    If the following function were run, in a PowerShell prompt:

        New-EnvConfig -Path /app/build/config/stage_envvars.yml -ScriptPath /app/local `
                      -Cloud Azure -Stage terraform_state

    The the script will be saved as:

        /app/local/envvars-azure-terraform_state.ps1

    .EXAMPLE

    The following example assumes that the command is being run in the Independent Pipeline,
    this the path is to the repo which is mapped to `/app` in the container

    PS> New-EnvConfig -Path /app/build/config/stage_envvars.yml -Cloud Azure -Stage terraform_state


    #>

    [CmdletBinding()]
    param (

        [string]
        # Path to the environment configuration file
        $path,

        [string]
        # Path to the the resulting script
        $scriptPath = $env:ENV_SCRIPT_PATH,

        [string]
        # Name of the cloud platform being deployed to. This is so that the credntial
        # environment variables are checked for correctly
        $cloud = $env:CLOUD_PLATFORM,

        [string]
        # Stage being run which determines the variables to be chcked for
        # This stage will be merged with the default check
        # If not specified then only the deafult stage will be checked
        $stage = $env:STAGE,

        [string]
        # Shell that the script should be generated for
        $shell = $env:SCRIPT_SHELL
    )

    $result = Confirm-Parameters -List @("path", "scriptpath")
    if (!$result) {
        return
    }

    # Check that the specified path exists
    if (!(Test-Path -Path $path)) {
        Stop-Task -Message ("Specified file does not exist: {0}" -f $path)
    }

    # Get a list of the missing variables for this stage and the chosen cloud platform
    $missing = Get-EnvConfig -path $path -stage $stage -cloud $cloud

    # Depending on the shell, set the preamble used in the script to configure the environment variables
    # This assumes that if the shell var does not exist then it is powershell, otherwise it assumes
    # a bash like environment
    if (Test-Path -Path env:\SHELL) {
        $preamble = "export "
        $extension = "sh"
    } else {
        $preamble = '$env:'
        $extension = "ps1"
    }

    $data = @()

    # Add the cloud platform to the script
    $data += "`# The Cloud platform for which these variables are being set"
    $data += '{0}CLOUD_PLATFORM="{1}"' -f $preamble, $cloud.ToLower()

    # Iterate around the missing variables
    foreach ($item in $missing) {

        # Add the description to the array
        $data += "`n# {0}" -f $item.description

        # Add the variable configuration
        $data += '{0}{1}=""' -f $preamble, $item.name
    }

    # Determine the name of the script file
    $filename = [IO.Path]::Combine($scriptPath, $("envvar-{0}-{1}.{2}" -f $cloud.ToLower(), $stage.ToLower(), $extension))

    # Set the contents of the file with the information in the $data var
    Set-Content -Path $filename -Value ($data -join "`n")
}
function Publish-Confluence() {

    <#
    
    .SYNOPSIS
    Publish (create or update) a page in Confluence

    .DESCRIPTION
    This cmdlet takes the specified body and uploads it to Confluence. If the page already exists
    it will be updated. All images in the file will be uploaded as attachments to the page.

    The body to be published can be passed inline to the arguments or as a file. The cmdlet will check to
    see if the `body` parameter is a path to a file in which case it will attempt to read the contents in 
    and set that as the body to upload.

    After this a call to the Confluence API will be made to see if the page already exists. If it does then
    the ID for that page is retrieved, if it does not then an initial page is created from which the ID is retrieved.
    Then the cmdlet scans the HTML for any images that need to be uploaded as attachments. Finally the final
    page is uploaded to Confluence.

    A parent page can be specified which will result in this page being a child of the named parent.

    Credentials for the API are passed to the function as a basic authentication pair with an API token in the format
    '<username>:<api_token>'. OAuth authorisation is not currently supported.

    .NOTES
    Confluence requires that the HTML extension is enabled to display content that has been uploaded as HTML.

    .EXAMPLE
    $env:CONFLUENCE_CREDENTIALS = "myuser:1234567"
    Publish-Confluence -title "MyPage" `
                       -space "ED" `
                       -server "myconfluenece.atalassian.net" `
                       -body "myfile.html" `
                       -checksum "56555655" `
                       -path "."

    Uploads the content of the `myfile.html` as the MyPage page in confluence

    #>

    [CmdletBinding()]
    param (
        [string]
        # Title of page being published
        $title,

        [string]
        # Space in which the page should belong
        $space,

        [string]
        # Name of the page that this page is a parent of
        $parent,

        [string]
        # Server to be used in the API call
        $server,

        [string]
        # Credentials to be used to access the API
        $credentials = $env:CONFLUENCE_CREDENTIALS,

        [string]
        # Body of the content that should be published
        $body,

        [string]
        # Checksum of the body to determine if a page needs to be updated
        # If passed to the function the checksum is not determined automatcially which
        # is useful if the content has been transformed from the original
        $checksum,

        [string]
        # Specify path for relative images in the body
        # This is used if there body is specified as a string, if it is a file then
        # the path is derived from the path to the file
        $path
    )

    # If the body is a file read in the contents
    $bodyPath = $path
    if (Test-Path -Path $body) {

        Write-Information -MessageData "File found for content, reading"

        if ([String]::IsNullOrEmpty($path)) {
            $bodyPath = Split-Path -Path $body -Parent
        }

        $body = Get-Content -Path $body -Raw
        
        # If the title has not been set use the filename as the title
        if ([String]::IsNullOrEmpty($title)) {
            $title = [System.IO.Path]::GetFileNameWithoutExtension($body)
        }
    }

    # Check that all the necessary parameters have been passed
    $result = Confirm-Parameters -list @("title", "space", "body", "server", "credentials")
    if (!$result) {
        return
    }    

    # See if page exists
    # Build up the path to path to use to see if the page exists
    $confluencePath = "/wiki/rest/api/content"

    # Get a checksum for the body, if it has not been specified
    if (!$checksum) {
        $checksum = Get-Checksum -Content $body
    }

    # Build the URL to use
    $url = Build-URI -Server $server -Path $confluencePath -query @{"title" = $title; "spaceKey" = $space; "expand" = "version"}

    # Call the API to get the information about the page
    $splat = @{
        url = $url
        credentials = $credentials
    }
    
    $pageDetails = Get-ConfluencePage @splat

    # If page does not exist then create it
    # this create the shell of the new page and returns the ID
    # the content will then be added as an update to the ID that is returned
    if ($pageDetails.Create) {

        # create the body object to creae the new page
        $pagebody = @{
            type = "page"
            title = $title
            space = @{
                key = $space
            }
            body = @{
                storage = @{
                    value = "Initial page created by the AmidoBuild PowerShell module. This will be updated shortly."
                    representation = "storage"
                }
            }
        }

        # if a parent has been specified get the ID of that page
        if (![String]::IsNullOrEmpty($parent)) {
            $url = Build-URI -Server $server -Path $confluencePath -query @{"title" = $parent; "spaceKey" = $space; "expand" = "version"}
            $pageDetails = Get-ConfluencePage -Url $url -Credential $credentials

            # If the parentId is not empty add it in as an ancestor for the page
            if (![string]::IsNullOrEmpty($pageDetails.ID)) {
                $pagebody.ancestors = @(@{id = $pageDetails.ID})
            }
        }

        # Create the initial page using the title and the spaceKey
        # The result of this will provide a pageId that can be used to update the content
        $splat = @{
            method = "POST"
            url = (Build-URI -Server $server -Path $confluencePath -query @{"expand" = "version"})
            body = (ConvertTo-Json -InputObject $pagebody -Depth 100)
            credentials = $credentials
        }

        $res = Invoke-API @splat

        if ($res -is [System.Exception]) {
            Stop-Task -Message $res.Message
        } else {
            $content = ConvertFrom-JSON -InputObject $res.Content
            $pageDetails.ID = $content.id
            $pageDetails.Version = $content.version.number
        }
    } else {

        # the page may need to be updated, but only do so if the checksums do not match
        if ($checksum -ieq $pageDetails.Checksum) {
            Write-Information -MessageData ("Page is up to date: '{0}' in '{1}' space" -f $title, $space)
            return
        }
    }

    # Get all the images in the HTML and determine which files need to be uploaded
    # Then modify the body so that the links are correct foreach uploaded image
    $pageImages = Get-PageImages -data $body

    foreach ($image in $pageImages) {

        # get the full path to the image
        $imgPath = [IO.Path]::Combine($bodyPath, $image.local)

        # only attempt to upload image and update body if it exists
        if (Test-Path -Path $imgPath) {
            Write-Information -MessageData ("Uploading image: {0}" -f $imgPath)

            # set the paramneters to send to the invoke-api to upload the image
            $splat = @{
                method = "POST"
                contenttype = 'multipart/form-data' #; boundary="{0}"' -f $delimiter
                formData = @{
                    file = Get-Item -Path $imgPath
                }
                headers = @{
                    "X-Atlassian-Token" = "nocheck"
                }
                url = (Build-URI -Server $server -Path ("{0}/{1}/child/attachment" -f $confluencePath, $pageDetails.ID))
                credentials = $credentials
            }

            $res = Invoke-API @splat

            # Replace the local img src to be the path for the attachment
            $image.remote = "/wiki/download/attachments/{0}/{1}" -f $pageDetails.ID, $imgItem.Name

            $body = $body -replace $image.local, $image.remote

        }
    }

    # prepare the body
    $preparedBody = @"
<ac:structured-macro ac:name="html" ac:schema-version="1">
    <ac:plain-text-body>
        <![CDATA[
            {0}
        ]]>
    </ac:plain-text-body>
</ac:structured-macro>
"@ -f $body

    # Using the ID of the page update the body
    # Update the splat of arguments to update the page with the necessary content
    $splat = @{
        method = "PUT"
        body = (ConvertTo-Json -InputObject @{
            id = $pageDetails.ID
            type = "page"
            title = $title
            space = @{
                key = $space
            }
            body = @{
                storage = @{
                    value = $preparedBody
                    representation = "storage"
                }
            }
            version = @{
                number = ($pageDetails.Version + 1)
            }
        })
        url = (Build-URI -Server $server -Path ("{0}/{1}" -f $confluencePath, $pageDetails.ID))
        credentials = $credentials
    }

    $res = Invoke-API @splat

    # Update the page properties so that the checksum of the data is set
    $splat = @{
        method = "PUT"
        url = (Build-URI -Server $server -Path ("{0}/{1}/property/checksum" -f $confluencePath, $pageDetails.ID))
        credentials = $credentials
        body = (ConvertTo-JSON -InputObject @{
            value = @(
                $checksum
            )
            version = @{
                number = $pageDetails.Version
            }
        })
    }

    $res = Invoke-API @splat

}
function Publish-GitHubRelease() {

    <#

    .SYNOPSIS
    Publishes a GitHub release using arguments and environment variables

    .DESCRIPTION
    Using the GitHub API this script will publish a release on specified repository using the
    name commit id an version number.

    All parameters are passed using arguments, apart from the GitHub token that is passed using an environment
    variable

    #>

    [CmdletBinding()]
    param (

        [string]
        # Version number of the release
        $version = $env:VERSION_NUMBER,

        [string]
        # Commit ID to be release
        $commitId = $env:COMMIT_ID,

        [string]
        [AllowEmptyString()]
        # Release notes. This can include helpful notes about installation for example
        # that will be specific to the release
        $notes = $env:NOTES,

        [string]
        # Artifacts directory, items in this folder will be added to the release
        $artifactsDir = $env:ARTIFACTS_DIR,

        [string[]]
        # List of files that will be uploaded to the release
        $artifactsList = @(),

        [string]
        # The owner username of the repository
        $owner = $env:OWNER,

        [string]
        # API Key to use to authenticate to perform the release
        $apikey = $env:API_KEY,

        [string]
        # GitHub repository that the release is for
        $repository = $env:REPOSITORY,

        [string]
        # Whether we should actually push data for this release
        $publishRelease = $env:PUBLISH_RELEASE,

        [bool]
        # Set if the release is a Draft, e.g. not visible to users
        $draft = $false,

        [bool]
        # Pre-release of an upcoming major release
        $preRelease = $true,

        [bool]
        # Auto-generate release Notes
        $generateReleaseNotes = $false

    )

    # Check whether we should actually publish
    if ($publishRelease -ne "true" -Or $publishRelease -ne $true) {
        Write-Information -MessageData ("Neither publishRelease parameter nor PUBLISH_RELEASE environment variable set to `'true`', exiting.")
        return
    }

    # As environment variables cannot be easily used for the boolean values
    # check to see if they have been set and overwite the values if they have
    if ([string]::IsNullOrEmpty($env:DRAFT)) {
        $draft = $false
    } else {
        $draft = $true
    }

    if ([string]::IsNullOrEmpty($env:PRERELEASE)) {
        $preRelease = $false
    } else {
        $preRelease = $true
    }

    # Confirm that the required parameters have been passed to the function
    $result = Confirm-Parameters -List @("version", "commitid", "owner", "apikey", "repository", "artifactsDir")
    if (!$result) {
        return $false
    }

    # if the artifactsList is empty, get all the files in the specified artifactsDir
    # otherwise find the files that have been specified
    if ($artifactsList.Count -eq 0) {
        $artifactsList = Get-ChildItem -Path $artifactsDir -Recurse -File
    } else {
        $files = $artifactsList
        $artifactsList = @()

        foreach ($file in $files) {
            $artifactsList += , (Get-ChildItem -Path $artifactsDir -Recurse -Filter $file)
        }
    }

    # Create an object to be used as the body of the request
    $requestBody = @{
        tag_name = ("v{0}" -f $version)
        target_commitsh = $commitId
        name = ("v{0}" -f $version)
        body = $notes
        draft = $draft
        prerelease = $preRelease
        generate_release_notes = $generateReleaseNotes
    }

    # Create the Base64encoded string for the APIKey to be used in the header of the API call
    $base64key = [Convert]::ToBase64String(
        [Text.Encoding]::Ascii.GetBytes($("{0}:x-oauth-basic" -f $apikey))
    )

    # Now create the header
    $header = @{
        Authorization = ("Basic {0}" -f $base64key)
    }

    # Create the splat hashtable to be used as the arguments for the Invoke-RestMethod cmdlet
    $releaseArgs = @{
        Uri = ("https://api.github.com/repos/{0}/{1}/releases" -f $owner, $repository)
        Method = "POST"
        Headers = $header
        ContentType = "application/json"
        Body = (ConvertTo-JSON -InputObject $requestBody -Compress)
        ErrorAction = "Stop"
    }

    # Create the release by making the API call, artifacts will be uploaded afterwards
    Write-Information -MessageData ("Creating release for: {0}" -f $version)
    try {
        $result = Invoke-WebRequest @releaseArgs
    } catch {
        Write-Error -Message $_.Exception.Message
        return
    }

    # Get the uploadUri that has been returned by the initial call
    $uploadUri = $result.Content | ConvertFrom-JSON | Select-Object -ExpandProperty upload_url

    # Iterate around all of the artifacts that are to be uploaded
    foreach ($uploadFile in $artifactsList) {

        # get the name of the artifact
        $artifact = Get-Item -Path $uploadFile

        Write-Output ("Adding asset to release: {0}" -f $artifact.Name)

        # Use the uploadUri to create a URI for the artifact
        $artifactUri = $uploadUri -replace "\{\?name,label\}", ("?name={0}" -f $artifact.Name)

        # Create the argument hash to perform the upload
        $uploadArgs = @{
            Uri = $artifactUri
            Method = "POST"
            Headers = $header
            ContentType = "application/octet-stream"
            InFile = $uploadFile
        }
        # Perform the upload of the artifact
        try {
            $result = Invoke-WebRequest @uploadArgs
        } catch {
            Write-Error ("An error has occured, cannot upload {0}: {1}" -f $uploadFile, $_.Exception.Message)
            continue
        }
    }

}
function Set-Config() {

    <#

    .SYNOPSIS
    Sets up the environment for the module

    .DESCRIPTION
    Cmdlet currently sets the path for the file to hold the commands that are executed
    by the module

    .EXAMPLE
    Set-Config -commandpath ./cmdlog.txt

    Set the path to the command log file `./cmdlog.txt`

    #>

    [CmdletBinding()]
    param (

        [string]
        # Set the file to be used for command log
        $commandpath
    )

    if (![String]::IsNullOrEmpty($commandpath)) {

        # ensure the parent path for the commandpath exists
        if (!(Test-Path -Path (Split-Path -Path $commandpath -Parent))) {
            Write-Error -Message "Specified path for command log does not exist"
        } else {

            if (!([string]::IsNullOrEmpty((Get-Variable -Name Session -Scope Global -ErrorAction SilentlyContinue)))) {
                $Session.commands.file = $commandpath
            }
        }
    }
}
function Update-BuildNumber() {
    [CmdletBinding()]
    param (

        [string]
        # Build number to update to
        $buildNumber = $env:DOCKER_IMAGE_TAG
    )

    # If the buildNumber is null, set it to a default value
    If ([String]::IsNullOrEmpty($buildNumber)) {
        $buildNumber = "workstation-0.0.1"
    }

    # Check that the parameters have been set
    if (Confirm-Parameters -List @("buildNumber")) {

        # If the TF_BUILD environment variable is defined, then running on an Azure Devops build agent
        if (Test-Path env:TF_BUILD) {
            Write-Output ("##vso[build.updatebuildnumber]{0}" -f $buildnumber)
        } else {
            Write-Output $buildNumber
        }
    }
}
function Update-InfluxDashboard() {

    <#

    .SYNOPSIS
    Update Deployment Dashboard Details

    .DESCRIPTION
    With pielines being defined as code, it has become more difficult to show visually what applications have
    been deployed in what environment. This cmdlet uses InfluxDB to create a dashboard of applications and 
    which version has been deployed into each environment.

    This function will send data to an InfluxDB (a time based database) so that a dahsboard can be generated. This
    can be achieved using InfluxDB or Grafana Cloud for example.

    All of the parameters can be defined as envrionment variables, as detailed in the parameters section.

    An InfluxDB account must exist and a TOKEN for the specified ORG supplied.

    #>

    [CmdletBinding()]
    param (
        [string]
        # measurement name in deployment dashboard
        $measurement = $env:DASHBOARD_MEASUREMENT,

        [string]
        # comma separated list of tags to attach to the entry in the deployment dashboard i.e.  environment=dev,source=develop
        $tags = $env:DASHBOARD_TAGS,

        [string]
        # version attached to the entry in the deployment dashboard
        $version = $env:DASHBOARD_VERSION,

        [string]
        # server endpoint
        $influx_server = $env:DASHBOARD_INFLUX_SERVER,

        [string]
        # Token for use with InfluxDB instance
        $influx_token = $env:DASHBOARD_INFLUX_TOKEN,

        [string]
        # Organisation Reference for InfluxDB
        $influx_org = $env:DASHBOARD_INFLUX_ORG,

        [string]
        # Bucket Name for InfluxDB
        $influx_bucket = $env:DASHBOARD_INFLUX_BUCKET,

        [string]
        # Whether we should actually push data for this release
        $publishRelease = $env:PUBLISH_RELEASE
    )

    # Check whether we should actually publish
    if ($publishRelease -ne "true" -Or $publishRelease -ne $true) {
        Write-Information -MessageData ("Neither publishRelease parameter nor PUBLISH_RELEASE environment variable set to `'true`', exiting.")
        return
    }
    
    # Validate all parameters are supplied
    $result = Confirm-Parameters -list @("measurement", "tags", "version", "influx_server", "influx_token", "influx_org", "influx_bucket")
    if (!$result) {
        Write-Error -Message "Missing parameters"
        return
    }



    # Confirm influx server is HTTPS web address
    $result = $false
    $result = Confirm-IsWebAddress $influx_server
    if (!$result) {
        Write-Information -MessageData ("influx server: {0}" -f $influx_server)
        Write-Error -Message "supplied server parameter is not a valid HTTPS address"
        return
    }
    Write-Information -MessageData ("Influx Server: {0} is a valid web address" -f $influx_server)

    # Test the deploymentTags are a valid comma separated list
    $result = $false
    $result = Confirm-CSL $tags
    if (!$result) {
        Write-Information -MessageData ("tags: {0}" -f $tags)
        Write-Error -Message "tags parameter is not a valid comma-separated list as a string"
        return
    }
    Write-Information -MessageData ("tags {0} is a valid comma-separated list as a string" -f $tags)

    # Test the version is a valid semantic version syntax
    $result = $false
    $result = Confirm-SemVer $version
    if (!$result) {
        Write-Information -MessageData ("version: {0}" -f $version)
        Write-Error -Message "Influx Version is not a valid semantic version string"
        return
    }
    Write-Information -MessageData ("{0} is a valid semantic version string" -f $version)

    # Generate the request URI
    $uri = "{0}/api/v2/write?org={1}&bucket={2}" -f $influx_server,$influx_org,$influx_bucket
    
    Write-Information -MessageData ("URI: {0}" -f $uri)

    # Generate the headers
    $headers = @{   "Authorization" = "Token $influx_token"
                    "Accept" = "application/json"
                    "Content-Type" = "text/plain; charset=utf-8"
                }
    # Generate the request body
    $object = $tags -split ","
    $object = ,"$measurement" + $object
    $tags = $object -join ","
    $body = "$tags" + " version=`"$version`""
    
    # Invoke-RestMethod on InfluxDB endpoint
    try     { Invoke-RestMethod -Method POST -Header $headers -uri $uri -body $body 
            Write-Information "InfluxDB Updated" }
    catch   { Write-Error $_
            return }
}
function Find-Projects() {

    [CmdletBinding()]
    param (

        [string]
        # Pattern to use to find the necessary files
        $pattern,

        [Alias("dir")]
        [string]
        # Path in which to search
        $path,

        [Switch]
        # State if looking for only directories
        $directory
    )

    # Create a hash table to be used to splat in the arguments for Get-ChildItem
    $splat = @{
        Path = $path
        Filter = $pattern
        Directory = $directory.IsPresent
        Recurse = $true
    }

    Get-ChildItem @splat
}
function Build-URI() {

    <#
    
    .SYNOPSIS
    Helper function to build up a valid URI

    #>

    [CmdletBinding()]
    param (
        [string]
        # Server / hostname of the target endpoint
        $server,

        [string]
        # Path of the URI
        $path,

        [string]
        # Port to connect to the remote host on
        $port,

        [hashtable]
        # Hashtable of the query options
        $query,

        [switch]
        # Specify that HTTP should be used instead of HTTPS
        $notls
    )

    # Create the necessary variables
    $scheme = "https://"
    $queryString = ""

    if ($notls.IsPresent) {
        Write-Warning -Message "HTTP encryption should not be turned off"
        $scheme = "http://"
    }

    # iterate around the query hashtable and turn it into an array
    # that can be joined together for the query of the URI
    if ($query.count -gt 0) {
        $queryParts = @()
        foreach ($h in $query.GetEnumerator() | Sort-Object -Property name) {
            $queryParts += "{0}={1}" -f $h.name, $h.value
        }

        $queryString = "?{0}" -f ($queryParts -join "&")
    }

    # if the the path does not start with a preceeding / add it
    if (!$path.StartsWith("/") -and ![String]::IsNullOrEmpty($path)) {
        $path = "/{0}" -f $path
    }

    # Set a port to be used if one has been specified
    if (![String]::IsNullOrEmpty($port)) {
        $port = ":{0}" -f $port
    }

    $uri = "{0}{1}{2}{3}{4}" -f $scheme, $server, $port, $path, $queryString

    $uri

}
function Confirm-CSL() {

[CmdletBinding()]
param (

    [string]
    # Input string to test
    $data = ""
)

# Import helper functions
# N/A

$data -match "^[\.0-9a-zA-Z=-]+(,[\.0-9a-zA-Z=-]+)*$"
}
function Confirm-IsWebAddress() {

    [CmdletBinding()]
    param (

        [string]
        # Address to confirm
        $address
    )

    $uri = $address -as [System.URI]

    $uri.AbsoluteURI -ne $null -and $uri.Scheme -match 'https?'
}
function Confirm-Parameters() {

    [CmdletBinding()]
    param (

        [string[]]
        # List of variables that should be checked
        $list
    )

    # Set the result to return
    $result = $false

    # Definde the array to hold missing parameters
    $missing = @()

    # Iterate around the list and check the values
    foreach ($name in $list) {
        $var = Get-Variable -Name $name -ErrorAction SilentlyContinue
        if ([string]::IsNullOrEmpty($var.Value)) {
            $missing += $name
        }
    }

    # If there are missing items, throw an error
    # and return false
    if ($missing.count -gt 0) {

        # Write-Error adds a null to the pipleine which means that the $result var ends being an array
        # which looks like @($null, $false)
        # by assigning the result of Write-Error to the £drop var this is avoided
        $drop = Write-Error -Message ("Required parameters are missing: {0}" -f ($missing -join ", "))
    } else {
        $result = $true
    }

    return $result
}
function Confirm-SemVer() {

[CmdletBinding()]
param (

    [string]
    # Value to test as Semantic Version
    $version
)

# Import helper functions
# N/A

$version -match "^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-(0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(\.(0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*)?(\+[0-9a-zA-Z-]+(\.[0-9a-zA-Z-]+)*)?$"
}
function Confirm-TrunkBranch() {

    <#
    
    .SYNOPSIS
    Determines if the current branch of the course control is the trunk branch

    .DESCRIPTION
    Sometimes operations need to be performed only when the commands are being run on the 
    trunk branch. This cmdlet returns a boolean to state if this is the case.
    
    This cmdlet currently only supports git
    #>

    [CmdletBinding()]
    param(

        [string[]]
        # List of branches that are considered trunk. This is to accomodate SCS that 
        # may have different names for a trunk
        $names = $env:TRUNK_NAMES,

        [string]
        # Name of the source control provider
        $scs = $env:SCS
    )

    # Set sane defaults
    # Set a default of Git if not set
    if ([String]::IsNullOrEmpty($scs)) {
        $scs = "git"
    }

    $discocmd = ""
    $result = $false

    # determine the command to run and branch names for the supported scs
    switch ($scs) {

        "git" {

            if ($names.length -eq 0) { $names = @("main", "master") }

            $discocmd = "git rev-parse --abbrev-ref HEAD"
        }

        default {

            Write-Warning -Message ("SCS is not currently supported: {0}" -f $scs)
            return $false
        }
    }

    Write-Information ("Checking if trunk branch: {0}" -f $names)

    # Run command to get the branch that is being run
    $branch = Invoke-Expression -Command $discocmd

    if ($names -contains $branch) {
        $result = $true
    }

    return $result
}
function Convert-ArrayToString() {

    [CmdletBinding()]
    param (

        [Parameter(
            ValueFromPipeline = $true
        )]
        [System.Array]
        # array to write out as a string
        $arr
    )

    # Check that all the required parameters have been set
    $result = Confirm-Parameters -List @("arr")
    if (!$result -and !($arr -is [System.Object[]])) {
        return
    }

    # Start the string for the array
    $arrStr = "@("

    # create an array for each of the string parts,
    # this is so that the array can be joined together with the correct delimiter
    $stringParts = @()

    foreach ($value in $arr) {

        # set the quotes to use
        $quotes = '"'

        if ($value -is [System.Object[]]) {
            $value = Convert-ArrayToString -arr $value
            $quotes = $null
        }

        if ($value -is [System.Collections.Hashtable]) {
            $value = Convert-HashToString -hash $value
            $quotes = $null
        }

        $stringParts += '{0}{1}{0}' -f $quotes, $value
    }

    $arrStr += $stringParts -join ", "
    $arrStr += ")"

    return $arrStr
}
function Convert-HashToString() {

    [CmdletBinding()]
    param (

        [Parameter(
            ValueFromPipeline = $true
        )]
        [Hashtable]
        # Hashtable to write out as a string
        $hash
    )

    # Check that all the required parameters have been set
    $result = Confirm-Parameters -List @("hash")
    if (!$result) {
        return
    }

    # Start the string for the hashtable
    $hashStr = "@{"

    # create an array for the string parts so that all the nessary
    # strings can be joined together with the correct delimiter
    $stringParts = @()

    $keys = $hash.Keys

    foreach ($key in $keys) {

        # set the quotes to use
        $quotes = '"'

        # get the the value of the key
        $value = $hash[$key]

        # Check to see if the value is a hashtable, if it is then it needs
        # be converted to a string
        if ($value -is [System.Collections.Hashtable]) {
            $value = Convert-HashToString -hash $value
            $quotes = $null
        }

        if ($value -is [System.Array]) {
            $value = Convert-ArrayToString -arr $value
            $quotes = $null
        }

        if ($key -match "\s") {
            $key = '"{0}"' -f $key
        }
        
        $stringParts += '{0} = {2}{1}{2}' -f $key, $value, $quotes
    
    }

    $hashStr += $stringParts -join "; "
    $hashStr += "}"

    return $hashStr
}
function ConvertTo-Base64() {

    [CmdletBinding()]
    param (
        [string]
        # Value that needs to be converted to base 64
        $value
    )

    # Get the byte array for the string
    $bytes = [System.Text.Encoding]::ASCII.GetBytes(($value))

    # Encode the string
    $encoded = [Convert]::ToBase64String($bytes)

    # return the encoded string
    return $encoded
}
function ConvertTo-MDX {

    <#

    .SYNOPSIS
    Convert the specified Markdown file to MDX supported format

    .DESCRIPTION
    The Stacks documentation website uses Docusarus which means that any HTML in a markdown file
    needs to be in JSX format. This is not natively supported by MD or Asciidoc so thius script will
    take the specified MD file, convert the contents and write out to the specified path

    #>

    [CmdletBinding()]
    param (

        [string]
        # Path the input MD file
        $path,

        [string]
        # Path specifying where the file should be saved to
        $destination
    )

    # Check that the necessary parameters have been supplied
    $result = Confirm-Parameters -list ("path", "destination")
    if (!$result) {
        return $false
    }

    # Check that the path exists
    if (!(Test-Path -Path $path)) {
        Write-Error -Message ("Specified MD file does not exist: {0}" -f $path)
        return $false
    }

    # Ensure that the directory for the destination exists
    $parent = Split-Path -Path $destination -Parent
    if (!(Test-Path -Path $parent)) {
        Write-Information -MessageData ("Creating output directory: {0}" -f $parent)
        New-Item -ItemType Directory -Path $parent | Out-Null
    }

    # Read in the contents of the markdown file
    $data = Get-Content -Path $path -Raw

    # JSX conversion
    # -- class to className
    $data = $data -replace "class=`"", "className=`""

    # -- set styles
    $styles = $data | Select-String -Pattern "style=`"(.*)`"" -AllMatches

    # Iterate around all of the styles and set the necessary replacement
    # This is done because the style attributes need to be separated by comma and the values surrounded by quotes
    foreach ($style in $styles.Matches) {

        $modified = $style.groups[1].value -split "," | ForEach-Object { 
            $_ -replace "(.*):\s+(.*)", '$1: "$2"'
        }

        $modified = $modified -replace '"', "'"
        
        # Perform the replacement in the main data using the value of the style as the key
        # for the replacement
        $data = $data -replace ("`"{0}`"" -f $style.groups[1].value), ("{{{{ {0} }}}}" -f ($modified -join ","))
    }

    Set-Content -Path $destination -Value $data

    Write-Information -MessageData ("Created MDX file: {0}" -f $destination)
}
function Copy-Object {

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        $Original
    )

    if($null -eq $Original)
    {
        return $null
    }
    else
    {
        $s = [System.Management.Automation.PSSerializer]::Serialize($Original, [int32]::MaxValue)
        return [System.Management.Automation.PSSerializer]::Deserialize($s)
    }
}
function Get-Checksum() {

    <#
    
    .SYNOPSIS
    Helper function to get the MD5 checksum for the contents of a file or a string

    #>

    [CmdletBinding()]
    param (
        [Alias("file")]
        [string]
        # Path to file or the content to get the hash for
        $content
    )

    $hash = ""

    # Attempt to find the file
    if (Test-Path -Path $content) {
        $content = Get-Content -Path $content -Raw
    }

    if (![String]::IsNullOrEmpty($content)) {
        $md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
        $utf8 = New-Object -TypeName System.Text.UTF8Encoding
        $hash = [System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes($content)))

        # remove the hypens from the string
        $hash = $hash -replace "-", ""
    }

    return $hash
}
function Get-EnvConfig() {

    <#

    .SYNOPSIS
    Library function to read the environment configuration file

    .DESCRIPTION
    There are a couple of functions that need to read the environment configuration file. One is to
    check the environment `Confirm-Environment` and the other one is `New-EnvConfig` which will create
    a script, compatible with the local shell, that can be used to set the up the local environment
    to use with the Independent Runner

    #>

    [CmdletBinding()]
    param (

        [string]
        # Path to the environment configuration file
        $path,

        [string]
        # stage that is being executed
        $stage,

        [string]
        # Cloud platform that is being targetted
        $cloud

    )

    $missing = @()

    # Check that the specified path exists
    if (!(Test-Path -Path $path)) {
        Stop-Task -Message ("Specified file does not exist: {0}" -f $path)
    }

    $moduleName = "Powershell-Yaml"
    $module = Get-Module -ListAvailable -Name $moduleName
    if ([string]::IsNullOrEmpty($module)) {
        Stop-Task -Message "Please ensure that the Powershell-Yaml module is installed"
    } else {
        Import-Module -Name $moduleName
    }

    # Read in the specified file
    $stage_variables = Get-Content -Path $path -Raw
    $stageVars = ConvertFrom-Yaml -Yaml $stage_variables

    # Attempt to get the default variables which are to be checked for
    $required = @()
    if ($stageVars.ContainsKey("default")) {
        # get the default variables
        if ($stageVars["default"].ContainsKey("variables")) {
            $required += $stageVars["default"]["variables"]
                | Where-Object { $_.Required -ne $false -and ([string]::IsNullOrEmpty($_.cloud) -or $_.cloud -contains $cloud) }
                | ForEach-Object { $_ }
        }

        # Get the credentials for the cloud if they have been specified
        if ($stageVars["default"].ContainsKey("credentials") -and
            $stageVars["default"]["credentials"].ContainsKey($cloud)) {
            $required += $stageVars["default"]["credentials"][$cloud]
                | Where-Object { $_.Required -ne $false }
                | ForEach-Object { $_ }
        }
    }

    # If the stage is not null check that it exists int he stages list and if
    # it does merge with the required list
    if (![String]::IsNullOrEmpty($stage)) {

        # Attempt to get the stage from the file
        $_stage = $stageVars["stages"] | Where-Object { $_.Name -eq $stage }

        if ([String]::IsNullOrEmpty($_stage)) {
            Write-Warning -Message ("Specified stage is unknown: {0}" -f $stage)
        }
        else {
            $required += $_stage["variables"] | Where-Object { $_.Required -ne $false -and ([string]::IsNullOrEmpty($_.cloud) -or $_.cloud -contains $cloud) } | ForEach-Object { $_ }
        }

    }
    else {
        Write-Warning -Message "No stage has been specified, using default environment variables"
    }

    # ensure that required does not contain "empty" items
    $required = $required | Where-Object { $_.Name -match '\S' }

    # Iterate around all the required variables and ensure that they exist in enviornment
    # If any of them do not then add to the missing array
    foreach ($envvar in $required) {
        try {
            # In some cases all of the environment variables have been capitalised, this is to do with TaskCtl.
            # Check for the existence of the variable in UPPER case as well, if it exists create the var with
            # the correct name and then remove the UPPER case value
            $path = [IO.Path]::Combine("env:", $envvar.Name)
            $pathUpper = [IO.Path]::Combine("env:", $envvar.Name.ToUpper())

            if ((Test-Path -Path $pathUpper) -and !(Test-Path -Path $path)) {
                New-Item -Path $path -Value (Get-ChildItem -Path $pathUpper).Value
                Remove-Item -Path $pathUpper -Confirm:$false
            }

            $null = Get-ChildItem -path $path -ErrorAction Stop
        } catch {
            # The variable does not exist
            $missing += $envvar
        }
    }

    # return the required env vars
    return $missing
}
function Get-StringPart() {

    [CmdletBinding()]
    param (
        [string]
        # Phrase to extract from
        $phrase,

        [string]
        # Delimieter used to split up string
        $delimiter = " ",

        [int]
        # Item number stating which part of the string is required
        $item
    )

    # if the item is less than 1, then throw an error
    if ($item -lt 1) {
        Write-Error -Message "Item must be equal to or great than 1"
        return
    }

    # Split the phrases into parts
    $parts = $phrase -split $delimiter

    # if the index is greater than the number of parts, raise an error
    if ($item -gt $parts.count) {
        Write-Error -Message ("Specified item '{0}' is greater than the number of parts: {1}" -f $item, $parts.count)
    } else {
        return $parts[$item - 1]
    }
}
function Merge-Hashtables {

    [CmdletBinding()]
    [OutputType([hashtable])]
    Param
    (
        [Parameter(Mandatory=$false)]
        [hashtable] $primary,

        [Parameter(Mandatory=$false)]
        [hashtable] $secondary,

        [Parameter(Mandatory=$false)]
        [switch] $shallow
    )

    if($primary.Count -eq 0) {
        return $secondary
    }
    if($secondary.Count -eq 0) {
        return $primary
    }

    # hshtables and dictionaries can be merged
    $mergableTypes = @(
        "Hashtable"
        "Dictionary``2"
    )

    # variable needs to exist to apply [ref]
    $primaryCopy, $secondaryCopy = $null
    $primaryCopy = Copy-Object -Original $primary
    $secondaryCopy = Copy-Object -Original $secondary

    $duplicateKeys = $primaryCopy.keys | Where-Object {$secondaryCopy.ContainsKey($_)}
    foreach ($key in $duplicateKeys)
    {
        if($null -ne $primaryCopy.$key -and $null -ne $secondaryCopy.$key)
        {
            # mergable types merge recursively
            if ($mergableTypes -contains $primaryCopy.$key.GetType().Name -and
                $mergableTypes -contains $secondaryCopy.$key.GetType().Name)
            {
                $primaryCopy.$key = Merge-Hashtables -primary $primaryCopy.$key -secondary $secondaryCopy.$key -shallow:$shallow
            }

            # merge arrays (unless it is in shallow mode)
            if (-not $shallow -and
                $primaryCopy.$key.GetType().Name -eq "Object[]" -and
                $secondaryCopy.$key.GetType().Name -eq "Object[]")
            {
                $result = @()

                # because Object[] can contain many different types, Unique of Select may not work properly
                # hence iterate over each of the two arrays
                foreach ($item in ($primaryCopy.$key + $secondaryCopy.$key))
                {
                    # Switch on the type of the item to determine how to add the information
                    switch ($item.GetType().Name)
                    {
                        # unique strings and integers
                        {$_ -in "String","Int32"} {
                            if ($result -notcontains $item) {
                                $result += $item
                            }
                        }

                        default {
                            $result += $item
                        }
                    }
                }

                # assign the result back to the primary array
                $primaryCopy.$key = $result
            }
        }

        # force primary key, so remove secondary conflict
        $secondaryCopy.Remove($key)
    }

    # join the two hash tables and return to the calling function
    $primaryCopy + $secondaryCopy
}
function Protect-Filesystem() {

    <#
    
    .SYNOPSIS
    Cmdlet to determine that the specified path is within the current directory

    .DESCRIPTION
    A lof of the functions in this module accept a path parameter, which could be relative. It is not
    good practice to allow a relative path to break out of the current location, so this cmdlet checks
    if the specified path is within the current dir.

    If it is then the dirctory will be created if it does not exist, otherwise an error will be generated
    if the path does not exist

    #>

    [CmdletBinding()]
    param (

        [string]
        # Path that is being checked
        $path,

        [Alias("BasePath")]
        [string]
        # Parent path to use to check that the path is a child
        $parentPath
    )

    # Check that the required parameters have been set
    $result = Confirm-Parameters -List @("path")
    if (!$result) {
        return $false
    }

    if ([string]::IsNullOrEmpty($parentPath)) {
        $parentPath = (Get-Location).Path
    }

    # If the path is relative, resolve it to a full path
    # This is done to get rid of any ../ that may exist
    if (![System.IO.Path]::IsPathRooted($path)) {
        Push-Location -Path $parentPath
        $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($path)
        Pop-Location
    }

    # Determiune if the path is a child of the parent path, if it is create it
    # Otherwise throw an error
    if ($path.ToLower().StartsWith($parentPath.ToLower())) {

        if (!(Test-Path -Path $path)) {
            Write-Warning -Message ("Specified output path does not exist, creating: {0}" -f $path)
            
            New-Item -ItemType Directory -Path $path | Out-Null
        }
    } else {
        Write-Error -Message "Specified output path does not exist within the current directory"
        return $false
    }

    return $path
}
function Replace-Tokens() {

    <#
    
    .SYNOPSIS
    Replaces the tokens in the specified data with the values in the hashtable

    #>

    [CmdletBinding()]
    param (

        [hashtable]
        # Hashtable of the tokens and the values to be replaced
        $tokens = @{},

        [string]
        # String that should have tokens replace
        $data,

        [string[]]
        # Delimeters to be used
        $delimiters = @("{{", "}}")
    )

    # get the start and stop delimiters
    $start = [Regex]::Escape($delimiters[0])
    $stop = [Regex]::Escape($delimiters[1])

    # Build up the pattern to find the automatic tokens
    # Currently the only one supported is "date" using the Uformat
    $pattern = '{0}\s*(date:.*?)\s*{1}' -f $start, $stop

    # Get any date based tokens from the data and ensure it is converted and added to the tokens
    $found = $data | Select-String -Pattern $pattern -AllMatches
    if ($found) {
        foreach($m in $found.Matches) {
            $date_pattern = $m.groups[1].value
            $tokens[$date_pattern] = Get-Date -Uformat ($date_pattern -split ":")[1].Trim()
        }
    }


    # Iterate around the tokens that have been passed
    foreach ($item in $tokens.GetEnumerator()) {

        # Build up the regular expression that will be used to performt he replacement
        $pattern = '{0}\s*{1}\s*{2}' -f $start, $item.Key, $stop

        $data = $data -replace $pattern, $item.Value
    }

    # Return the data to the calling function
    $data

}
function Invoke-Git() {
    Param (
        [Parameter(
            Mandatory=$true
        )]
        [string]$Reason,
        [Parameter(
            Mandatory=$true
        )]
        [string[]]$ArgumentsList
    )
    try
    {
        $gitPath = (Get-Command git).Source
        $gitErrorPath=Join-Path $env:TEMP "stderr.txt"
        $gitOutputPath=Join-Path $env:TEMP "stdout.txt"
        if($gitPath.Count -gt 1)
        {
            $gitPath=$gitPath[0]
        }

        Write-Verbose "[Git][$Reason] Begin"
        Write-Verbose "[Git][$Reason] gitPath=$gitPath"
        Write-Host "git $ArgumentsList"
        $process=Start-Process $gitPath -ArgumentList $ArgumentsList -NoNewWindow -PassThru -Wait -RedirectStandardError $gitErrorPath -RedirectStandardOutput $gitOutputPath
        $outputText=(Get-Content $gitOutputPath)
        $outputText | ForEach-Object {Write-Host $_}

        Write-Verbose "[Git][$Reason] process.ExitCode=$($process.ExitCode)"
        if($process.ExitCode -ne 0)
        {
            Write-Warning "[Git][$Reason] process.ExitCode=$($process.ExitCode)"
            $errorText=$(Get-Content $gitErrorPath)
            $errorText | ForEach-Object {Write-Host $_}

            if($errorText -ne $null)
            {
               # exit $process.ExitCode
            }
        }
        return $outputText
    }
    catch
    {
        Write-Error "[Git][$Reason] Exception $_"
    }
    finally
    {
        Write-Verbose "[Git][$Reason] Done"
    }
}
function Get-ConfluencePage() {

    <#
    
    .SYNOPSIS
    Get the ID for the specified confluence page

    .DESCRIPTION
    Get information about the specified page, this includes the pageId, version and checksum

    The function will return an object that containing the necessary information. This is safer
    than returning multiple values as sometimes the other values are not required and can
    cause issues if not caught

    #>

    [CmdletBinding()]
    param (
        [string]
        # URL of confluence to call
        $url,

        [string]
        # Credentials to be used to access confluence
        $credentials
    )

    # Create the object that will be returned to the calling function
    $details = [PSCustomObject]@{
        ID = ""
        Version = ""
        Checksum = ""
        Create = $false
    }

    $res = Invoke-API -url $url -credentials $credentials

    # If there has been an HTTP exception then catch it here and return the details
    # A 404 will only be thrown if the URL is incorrect, not the name of the page as
    # that is a query string
    if ($res -is [System.Exception]) {
        # check to see if the response is that the page could not
        # be found, in which case the page needs to be created
        if ($res.Response.StatusCode -eq [System.Net.HttpStatusCode]::NotFound) {
            Write-Information -MessageData "URL cannot be found, creating new page"
            Stop-Task -Message $res.Message
        }

        return $details
    }

    # As the res will have zero results, this cna be used to see if the page has been found or not
    $data = ConvertFrom-JSON -InputObject $res

    if ($data.results.length -eq 0) {#

        # The page within Confluence cannot be found, so set the details accordingly
        Write-Information -MessageData "Confluence page cannot be found, creating new page"
        $details.Version = 1
        $details.Create = $true

    } else {

        # The page has been found so get the page ID
        $details.ID = $data.results[0].id
        $details.Version = $data.results[0].version.number

        # As the page exists, get the checksum of the page
        $uri = [System.Uri]$url
        $propUrl = "{0}://{1}:{2}{3}/{4}/property" -f $uri.Scheme, $uri.DnsSafeHost, $uri.Port, $uri.AbsolutePath, $details.ID

        $res = Invoke-API -url $propUrl -credentials $credentials
        $properties = (ConvertFrom-Json -InputObject $res.Content).results

        foreach ($prop in $properties) {
            if ($prop.key -eq "checksum") {
                $details.Checksum = $prop.value[0]
            }
        }
    }

    return $details
}
function Get-PageImages() {

    <#
    
    .SYNOPSIS
    Retrieves all the src locations of images in the HTML

    .DESCRIPTION
    Reads the src for all img tags in the specified HTML and returns a unique list of the 
    local files.

    Any full web addresses are ignored.

    The value returned is an array of hashtables with the following format:

        @{
            local = ""
            remote = ""
        }

    Thsi is so that the calling function can fiund the page to the image to upload and then set 
    the remote location for any replacements that need to be performed

    #>

    [CmdletBinding()]
    param (
        [string]
        # Data to be analysed
        $data,

        [string]
        # Pattern to be used to find the images
        $pattern = "<img src=`"(.*?)`""
    )

    # Create local arrays to be used
    $register = @()
    $images = @()

    # parse the content
    $res = [Regex]::Matches($data, $pattern)

    # loop around the matchaes and add to the array
    # do not add items that are a full url
    foreach ($img in $res) {

        $src = $img.groups[1].value

        if (!$src.StartsWith("http") -and ($register -notcontains $src) -and !$src.StartsWith("data:image")) {
            $images += @{
                local = $src
                remote = ""
            }
            $register += $src
        }
    }

    # Return the images array
    # The comma is required to force PowerShell to return an array when there is only
    # one entry, otherwise just a single hashtable is returned
    , $images

}
