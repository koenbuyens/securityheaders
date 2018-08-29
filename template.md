# Analysis of security headers on the Internet
This section describes the results of applying our security headers script on $nbhosts hosts. 
Out of those $nbhosts, $securityheaderhosts replied with at least one security header, while $nberrors did not reply.

The table below shows the headers being used per host. The '$headers_per_host_maxheader' header is the most popular as it has been used by $headers_per_host_maxheader_percent % hosts, while the '$headers_per_host_minheader' header is only used by $headers_per_host_minheader_nb hosts.

$headersperhosttable

## Content Security Policy
### Usage
The Content Security Policy is used by $csppercentagenbhosts% of the hosts ($nbhostscsp out of $securityheaderhosts hosts). Out of those hosts using the header, $contentsecuritypolicydirectivedistribution_text.

$contentsecuritypolicydirectivedistribution_table

![Percentage of hosts with directive]($contentsecuritypolicydirectivedistribution_percentgraph)

### Insecure Usage
Out of $nbhostscsp hosts, $nbhostscsp_findings configure the CSP insecurely ($nbhostscsp_percentage %). Out of those hosts using each directive, $contentsecuritypolicydirectivedistribution_insecure_text

$contentsecuritypolicydirectivedistribution_insecure_table

![Percentage of hosts that use directive insecurely]($contentsecuritypolicydirectivedistribution_insecure_percentgraph)

$csp_findings_per_host_table

#![Findings for Content Security Policy](./pics/content-security-policyfindings_per_host.png)

$csp_findings_per_directive_table

#![Findings for Content Security Policy](./pics/content-security-policyfindings)



