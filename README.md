# Introduction 
This repo holds all the scripts and automation we need to automatically import a large amount of IoCs (500) at a time to MDE for blocking. 

# Contents
[[_TOC_]]


# Getting Started
## IoC preparation script

This script contains all you need to upload a list of IoCs (with a limit of 500 per batch). Essentially if you have a list with IoCs of "FileSha1", "FileSha256", "IpAddress", "DomainName" and "Url" the script will construct a .csv that can be imported by the MDE. This script follows the conventions depicted in the image below (** For more info: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/indicator-manage?view=o365-worldwide**):

![Alt text](image.png)

**Be aware that in order for the script to work you need a list of weaponized IoCs (not defanged) and you need to have one indicator per line e.g.:**

![Alt text](image-1.png)

To manually import indicators in MDE:

1. In the navigation pane, select **Settings > Endpoints > Indicators (under Rules)**.

2. Select the tab of the entity type you'd like to manage.

3. Select Import and upload the final file


- **IoC preparation script** -> The script takes 2 arguments:

## Resources
- https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/indicator-manage?view=o365-worldwide
