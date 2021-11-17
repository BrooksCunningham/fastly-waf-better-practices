# Unofficial better practices for the Fastly Next Gen WAF
The Fastly Next Gen WAF (Signal Sciences) is amazing right out of the box. We can use the framework that it provides to provide more suggestions about how to get the most out of the product. This repository provides the following functionaliy.

* Block attack traffic from known suspicious sources
* Consolidate the various malicious attack traffic into a single signal
* Discover login endpoints
* Discover card endpoints
* Block bots based on disallow in robots.txt

# How to use this repo
* Run the script get-robots-txt.sh to populate the list of paths that bots should not crawl in the file "main.auto.tfvars".
* (optional) create a site.auto.tfvars with your site variable so you do not have to be prompted each time you run `terraform plan` or `terraform apply`
* Set up the following variables however you like. (I prefer environment variables)  
    * SIGSCI_CORP
    * SIGSCI_EMAIL
    * SIGSCI_TOKEN
* Run the command `terraform apply`


# TODOs

| Request  | Status | Notes |
| :------------- | :----------: | -----------: |
|  Block attack traffic from known suspicious sources | DONE |     |
| Consolidate all attack traffic into a single custom signal | DONE | |
| Discover Login paths | DONE | |
| Discover places where card details are used | DONE | |
| Block bots based on robots.txt | DONE | |
| Lower the default site alerts | DONE | |
| Rate limit by ASN after excessive 404s | NOT STARTED | Need to define either A) list of high volume ASNs that should not be subject rate limiting or B) a list of suspicious ASNs |




