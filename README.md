# stacks-infrastructure-eks



# How to configure DNS for the Stacks Infra

### Get a domain name for your project :
   
   You need to registar a domain name for your project, use few of the links below if you require help to do that.

   - [How to registar a domain](https://mailchimp.com/resources/how-to-buy-a-domain-name/)
   - [How to registar a domain using Route53](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/domain-register.html)


### Create a hosted zone with the subdomains for the stacks application.
 
   #### Option 1:

   Now if you have registered a domain name with a 3rd party domain registrar (e.g like GoDaddy) and also managing the DNS records via them,
   you need to create a hosted zone on AWS Route53 with same domain or subdomain(if there multiple stacks app like app1.nonprod.org-name-stacks.com & app2.org-name-stacks.com) as shown below.

   The hosted zone can be created via the infrastructure code itself by toggling the "enable_zone" in "main.tf" file and passing the hosted zone records via the public_zone parameter.

   <img src=assets/route53-zone-in-terraform.png width="600" height="200" >
  
   ### This is how it looks via AWS Console:

   <img src=assets/hosted-zone-creation.png  width="300" height="300">
   

   Once this is created, you will be presented with up to 4 nameservers(NS) records. Go to your domain registrar dashboard and add these records to the NS records.

   <img src=assets/nameserver-records.png width="1000">

   <img src=assets/add-ns-records-to-3rd-party-domain-providers.png width="1000" height="400">

   #### Option 2:

   You can buy the domains in Route53 service itself, it will automatically create a hosted zone with the same domain name that you bought, follow this link to [setup domain name and dns with aws](https://aws.amazon.com/getting-started/hands-on/get-a-domain/).
   
   <img src=assets/register-domain-in-route53.png width="600" height="200">

   ***If you do the setup via this way remember to toggle off the hosted-zone creation via infrastructure code in main.tf file.***

   
   # How to generate SSL Certificate for the Stacks Infra:


   Once you are ready with the domain and subdomain, you can proceed to request or import a TLS/SSL certificate from the AWS Certificate Manager.

   <img src=assets/register-a-certificate-console.png width="600" height="200">

   Here request a public certifcate, for a private certificate, there are separate charges levied and click request a certificate button.
   
   <img src=assets/register-a-certficiate-request.png width="600" height="200">

   It's better use a wild card entry with the main domains, so that we can use other subdomains

   <img src=assets/register-a-certificate-examples.png width="600" height="200">
    
    Here you can choose any method for validating your domain, Email Validation is a straight forward method,other options are covering the DNS Validation and next add tags.

<img src=assets/register-a-certficate-validation-method.png width="600" height="200">
    