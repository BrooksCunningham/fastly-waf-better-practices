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
variable "SIGSCI_SITE" {
    type        = string
    description = "This is the site for the Sig Sci API as an env variable."
}
variable "ROBOTS_DISALLOW_LIST" {
    type        = list
    description = "List of paths that are disallowed in robots.txt. https://developers.google.com/search/docs/advanced/robots/intro"
}

# Supply API authentication
provider "sigsci" {
  corp = "${var.SIGSCI_CORP}"
  email = "${var.SIGSCI_EMAIL}"
  auth_token = "${var.SIGSCI_TOKEN}"
}

#### start attack from suspicious sources
# Add a tag for attacks from known suspicious sources
resource "sigsci_corp_signal_tag" "attack-sus-src" {
  short_name  = "attack-sus-src"
  description = "Attacks from suspicious sources"
}

resource "sigsci_corp_rule" "attack-sus-src-rule" {
    corp_scope       = "global"
    enabled          = true
    group_operator   = "all"
    reason           = "Attacks from suspicious sources"
    site_short_names = []
    type             = "request"
    expiration       = ""

    actions {
        type = "block"
    }
    actions {
        signal = "corp.attack-sus-src"
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
#### end attack from suspicious sources

#### start login discovery
# Signal for suspected login attempts
resource "sigsci_corp_signal_tag" "sus-login" {
  short_name      = "sus-login"
  description     = "Make sure these requests are visibible in your ATO dashboard or customize the rule to avoid adding this Signal to rules"
}

# Add a signal when there is a suspected login
resource "sigsci_corp_rule" "sus-login-rule" {
    corp_scope       = "global"
    enabled          = true
    group_operator   = "all"
    reason           = "Add signal for suspected logins"
    site_short_names = []
    type             = "request"
    expiration = ""
    actions {
        signal = "corp.sus-login"
        type   = "addSignal"
    }
    conditions {
        group_operator = "any"
        type           = "group"

        conditions {
            field          = "postParameter"
            group_operator = "any"
            operator       = "exists"
            type           = "multival"

            conditions {
                field    = "name"
                operator = "contains"
                type     = "single"
                value    = "email"
            }
            conditions {
                field    = "name"
                operator = "equals"
                type     = "single"
                value    = "/pass"
            }
            conditions {
                field    = "name"
                operator = "contains"
                type     = "single"
                value    = "passwd"
            }
            conditions {
                field    = "name"
                operator = "contains"
                type     = "single"
                value    = "password"
            }
            conditions {
                field    = "name"
                operator = "contains"
                type     = "single"
                value    = "phone"
            }
            conditions {
                field    = "name"
                operator = "equals"
                type     = "single"
                value    = "/user"
            }
            conditions {
                field    = "name"
                operator = "contains"
                type     = "single"
                value    = "username"
            }
        }
        conditions {
            field    = "path"
            operator = "contains"
            type     = "single"
            value    = "/auth"
        }
        conditions {
            field    = "path"
            operator = "contains"
            type     = "single"
            value    = "/login"
        }
    }
    conditions {
        field    = "method"
        operator = "equals"
        type     = "single"
        value    = "POST"
    }
}
#### end login discovery

#### start card-input discovery
# Signal for discovering when credit cards or gift cards are used.
resource "sigsci_corp_signal_tag" "sus-card-input" {
  short_name      = "sus-card-input"
  description     = "Make sure these requests are visibible in your carding dashboard or customize the rule to avoid adding this Signal to rules"
}

# Add a signal when there is a suspected login
resource "sigsci_corp_rule" "sus-card-input-rule" {
    corp_scope       = "global"
    enabled          = true
    group_operator   = "all"
    reason           = "Add signal for suspected carding attempt"
    site_short_names = []
    type             = "request"
    expiration = ""
    actions {
        signal = "corp.sus-card-input"
        type   = "addSignal"
    }
    conditions {
        group_operator = "any"
        type           = "group"

        conditions {
            field          = "postParameter"
            group_operator = "any"
            operator       = "exists"
            type           = "multival"

            conditions {
                field    = "name"
                operator = "contains"
                type     = "single"
                value    = "creditcard"
            }
            conditions {
                field    = "name"
                operator = "contains"
                type     = "single"
                value    = "credit-card"
            }
            conditions {
                field    = "name"
                operator = "contains"
                type     = "single"
                value    = "cvv"
            }
        }
        conditions {
            field    = "path"
            operator = "contains"
            type     = "single"
            value    = "/creditcard"
        }
        conditions {
            field    = "path"
            operator = "contains"
            type     = "single"
            value    = "/credit-card"
        }
    }
    conditions {
        field    = "method"
        operator = "equals"
        type     = "single"
        value    = "POST"
    }
}
#### end card-input discovery

#### start any-attack
resource "sigsci_corp_rule" "any-attack-signal-rule" {
    corp_scope       = "global"
    enabled          = true
    group_operator   = "all"
    reason           = "Any attack signal"
    site_short_names = []
    type             = "request"
    expiration       = ""

    actions {
        signal = "corp.any-attack-signal"
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
}
### end any-attack

#### start robots.txt

# create list to disallow based on robots.txt
# run the script get-robots-txt.sh first to generate the terraform variable file in main.auto.tfvars
resource "sigsci_corp_list" "robots-txt-disallow-list" {
  name        = "robots-txt disallow list"
  type        = "wildcard"
  description = "list of wildcard paths disallowed from robots.txt"
  entries = "${var.ROBOTS_DISALLOW_LIST}"
}

# Signal for discovering when bots are submitting requests to disallowed robots.txt resources
resource "sigsci_corp_signal_tag" "robots-txt-disallow" {
  short_name      = "robots-txt-disallow"
  description     = "Requests made by bots to disallowed pages defined in robots.txt"
}

# create rule to disallow based on robots.txt
resource "sigsci_corp_rule" "robots-txt-disallow-rule" {
corp_scope       = "global"
    enabled          = true
    group_operator   = "all"
    reason           = "Requests made by bots to disallowed paths in robots.txt"
    site_short_names = []
    type             = "request"
    expiration       = ""

    actions {
        signal = "corp.robots-txt-disallow"
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
            value    = "SUSPECTED-BAD-BOT"
        }
        conditions {
            field    = "signalType"
            operator = "equals"
            type     = "single"
            value    = "SUSPECTED-BOT"
        }
    }
    conditions {
        field    = "path"
        operator = "inList"
        type     = "single"
        value    = "corp.robots-txt-disallow-list"
    }
}
#### end robots.txt

#### start site alerts
resource "sigsci_site_alert" "any-attack-1-min" {
    action             = "flagged"
    enabled            = true
    interval           = 1
    long_name          = "any attack - 1 min"
    site_short_name    = "${var.SIGSCI_SITE}"
    skip_notifications = false
    tag_name           = "corp.any-attack-signal"
    threshold          = 10
}
resource "sigsci_site_alert" "any-attack-10-min" {
    action             = "flagged"
    enabled            = true
    interval           = 10
    long_name          = "any attack - 10 min"
    site_short_name    = "${var.SIGSCI_SITE}"
    skip_notifications = false
    tag_name           = "corp.any-attack-signal"
    threshold          = 50
}
resource "sigsci_site_alert" "any-attack-60-min" {
    action             = "flagged"
    enabled            = true
    interval           = 60
    long_name          = "any attack - 60 min"
    site_short_name    = "${var.SIGSCI_SITE}"
    skip_notifications = false
    tag_name           = "corp.any-attack-signal"
    threshold          = 200
}
#### end site alerts