# Using Py-Crawler

This tool is a replacement for the legacy FPKI Crawler. It has the following advantages over its predecessor:
1. It produced much more usable and readable outputs, designed to clearly identify errors in processing or other issues that prevent the full PKI Graph from being built. This will significantly reduce the time spent identifying changes in the graph.
1. It makes better use of github features in its execution, to reduce disk space and improve performanct.
1. It is a much simpler design and implementation, and thus much easier to customize for new requirements.
1. It automates previously manual processes such as opening pull requests and issues
1. It is designed specifically to operate in a cloud/container environment, offering flexibility of operation.
1. It supports multiple output formats, not just GEXF, and additional output formats can be easily added.

## Installing Py-Crawler
Py-crawler may run independently, but it is designed to operate in the context of containerized workflow. Docker (including docker-compose) are required for the successful execution of py-crawler.

The Py-crawler code is available from github. The repository is self contained, and has all of the elements required for execution except for the github authentication token which must be provided by the user.

To obtain a github authentication token, follow the instructions at https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token

Once the token has been issued, copy the contents of the token to a file called "accesstoken" under the dierctory "py-crawler/py_crawler/secrets"

## Running Py-Crawler
Once the prerequisites have been met, py-crawler can be executed by running "docker-compose up" from the main repo directory. If necessary, docker-compose will build the docker container and install all necessary tools before executing the tool.

The tool itself will grab the latest copy of the playbooks repo, create the new files necessary for the graph updates in a new branch, push the new branch to github and open the required issues and pull requests. All that should be required is to verify the output, and identify any followup actions.

## Interpreting the output
Py-crawler produces two output files during ordinary operation:
1. A json file containing the important results of the crawler run, and
2. a debug log file with detailed information about the execution of the process.

To determine the cause of any change in the graph between runs, the json file should be the first stop. This file contains the following elements:
1. anchor: This is always the common policy root. 
2. Issuers: This is a list of the issuers discovered for which a path exists to Common (Issuer DN is listed)
3. Valid Certs: This is the list of certificates that are valid and for which a path to common was discovered
4. Bad Certs: This is a list of the certificates that were discovered, but are not valid, or do not have a path to common. This section provides information about the cause of the failure. This section provides the most important information for troubleshooting - see the next section.
5. Found Paths: This section lists all of the paths that were discovered during the crawler run. It can be ignored for troubleshooting.

## Troubleshooting
The "Bad Certs" list in the json file is the most important source of information about potential issues causing a change in the graph.
1. "End Entity Cert expired or not valid": This error appears when the current date and time is outside a certificate's validity date. This is almost always due to expiration of a certificate.
2. "Pathbuilder timed out." - This error occurs when a CDP or AIA/SIA URL is unavailable, usually due to a temporary system outage.
3. "Certificate is a trust anchor, but not the root of the graph." - This error is returned when a trust anchor other than common appears in a certificates' AIA field.
4. "Certificate is present in the SIA of a CA that is not its issuer." - Sometimes a certificate may be bundled in the SIA of a cert that is not it's issuer. This is usually the case when an issuer publishes the same SIA bundle for all of its certificates. In some cases we are not even able to discover a path to common, and this is the error that is returned.
5. "Certificate Valid, but no path to common.": This error appears when a certificate is itself valid, but does not have a valid path to common. This is usually an issue with return certificates issued within other bridges cross-certified to the Federal Bridge.

The most common issues creating a change in the graph are number 1 (certificate expiration), and number 2 (system outage preventing CRL or Cert discovery). 

If the graph has changed, and the cause is not obvious from the json file, the debug log can be looked at. It contains detailed technical information about the execution of the process. Interpreting the output is beyond the scope of this guidance.