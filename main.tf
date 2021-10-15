# Terraform 0.13.x
terraform {
  required_providers {
    sigsci = {
      source = "signalsciences/sigsci"
    }
  }
}

variable "SIGSCI_CORP" {
    type        = string
    description = "This is the corp where configuration changes will be made as an env variable."
}
variable "SIGSCI_EMAIL" {
    type        = string
    description = "This is the email address associated with the token for the Sig Sci API as an env variable."
}
variable "SIGSCI_TOKEN" {
    type        = string
    description = "This is a secret token for the Sig Sci API as an env variable."
}

# Supply login information
provider "sigsci" {
  corp = "${var.SIGSCI_CORP}"
  email = "${var.SIGSCI_EMAIL}"
  auth_token = "${var.SIGSCI_TOKEN}"
}

# Add a tag for attacks from known bad sources
resource "sigsci_corp_signal_tag" "attack-bad-src" {
  short_name  = "attack-bad-src"
  description = "Block attacks from bad sources"
}

# sigsci_corp_rule.bad-attack-src:
resource "sigsci_corp_rule" "attack-bad-src" {
    corp_scope       = "global"
    enabled          = true
    group_operator   = "all"
    reason           = "Attacks from bad sources"
    site_short_names = []
    type             = "request"
    expiration       = ""

    actions {
        type = "block"
    }
    actions {
        signal = "corp.attack-bad-src"
        type   = "addSignal"
    }

    conditions {
        field          = "signal"
        group_operator = "any"
        operator       = "exists"
        type           = "multival"

        conditions {
            field    = "signalType"
            operator = "equals"
            type     = "single"
            value    = "BACKDOOR"
        }
        conditions {
            field    = "signalType"
            operator = "equals"
            type     = "single"
            value    = "CMDEXE"
        }
        conditions {
            field    = "signalType"
            operator = "equals"
            type     = "single"
            value    = "SQLI"
        }
        conditions {
            field    = "signalType"
            operator = "equals"
            type     = "single"
            value    = "TRAVERSAL"
        }
        conditions {
            field    = "signalType"
            operator = "equals"
            type     = "single"
            value    = "USERAGENT"
        }
        conditions {
            field    = "signalType"
            operator = "equals"
            type     = "single"
            value    = "XSS"
        }
    }
    conditions {
        field          = "signal"
        group_operator = "any"
        operator       = "exists"
        type           = "multival"

        conditions {
            field    = "signalType"
            operator = "equals"
            type     = "single"
            value    = "SANS"
        }
        conditions {
            field    = "signalType"
            operator = "equals"
            type     = "single"
            value    = "SIGSCI-IP"
        }
        conditions {
            field    = "signalType"
            operator = "equals"
            type     = "single"
            value    = "TORNODE"
        }
    }
}
