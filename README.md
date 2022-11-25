# README #

### What is this repository for? ###

* Quick summary
    * FOMO : A tool to help alleviate your "Fear Of Major Outages". 
    * This utility aims to allow users to programmatically manage resources in monitoring services such as AWS CloudWatch, Zabbix, PagerDuty*, Grafana*, via Python.
    * - See "Version" for more information

* Version
    * 1.0.1
    * Currently, there is only support for AWS Cloudwatch and Zabbix. PagerDuty, Grafana, and other potential Observability Tools will be supported in future releases

### How do I get set up? ###

* Summary of set up
    * Installation/updates can be performed via pip installation
    * sudo pip install fomo

* Configuration
    * User specific configurations are to be applied to the "fomo.toml". An example "fomo.toml.example" will be installed with package.

* Dependencies
    * Python modules: boto3,botocore,pyzabbix,tabulate modules. These should be installed via wheel installation.

* How to run tests

* Deployment instructions
    * Perform module build from root directory (containing pyproject.toml) via the following: sudo python3 -m build

### Contribution guidelines ###

* Writing tests

* Code review

* Other guidelines

### Who do I talk to? ###

* Repo owner or admin
    * Matt Alvis (thetechietidbits@gmail.com)
