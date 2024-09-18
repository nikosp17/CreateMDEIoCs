# Introduction 
This repository contains all the scripts and automation necessary to automatically import up to 500 IoCs at a time into Microsoft Defender for Endpoint (MDE) for blocking.

# Getting Started
## IoC preparation script

This script provides everything needed to upload a list of Indicators of Compromise (IoCs), with a limit of 500 entries per batch. If you have a list (.txt file) containing IoCs such as "FileSha1", "FileSha256", "IpAddress", "DomainName", and "Url", the script will generate a comma-delimited .txt file that can be imported into Microsoft Defender for Endpoint (MDE). Currently, this script does not support certificates. The script adheres to the conventions shown in the image below.
**For more info visit: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/indicator-manage?view=o365-worldwide**):

![image](https://github.com/nikosp17/CreateMDEIoCs/assets/58854267/0989000d-020f-468a-a1b8-1a223b0ff8ac)

**It is important to save the file as a '.txt'.**

**Please note that for the script to work properly, you must provide a list of weaponized (non-defanged) IoCs, with each indicator listed on a separate line (e.g., one IoC per line):**

![image](https://github.com/nikosp17/CreateMDEIoCs/assets/58854267/eedcfea2-215f-4175-a262-980746513518)


To manually import indicators in MDE:

1. In the navigation pane, select **Settings > Endpoints > Indicators (under Rules)**.

2. Select the tab of the entity type you'd like to manage.

3. Select Import and upload the final file.


- **IoC preparation script** -> The script takes 2 arguments:
  - The file path of the .txt with the fanged IoCs &
  - The file path where the MDE-formatted IoCs will be saved.

## Resources
- https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/indicator-manage?view=o365-worldwide
