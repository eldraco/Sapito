# Sapito is a mDNS (multicast DNS) sniffer and interpreter






## Why some packets have a question and answers in the same packet?
Because of Known-Answer suppression (https://tools.ietf.org/html/rfc6762#section-7.1)

    Known-Answer Suppression

       When a Multicast DNS querier sends a query to which it already knows
       some answers, it populates the Answer Section of the DNS query
       message with those answers.

       Generally, this applies only to Shared records, not Unique records,
       since if a Multicast DNS querier already has at least one Unique
       record in its cache then it should not be expecting further different
       answers to this question, since the Unique record(s) it already has
       comprise the complete answer, so it has no reason to be sending the
       query at all.  In contrast, having some Shared records in its cache
       does not necessarily imply that a Multicast DNS querier will not 
       receive further answers to this query, and it is in this case that it
       is beneficial to use the Known-Answer list to suppress repeated
       sending of redundant answers that the querier already knows.





# To take into account
The Answer Section of Multicast DNS queries is not authoritative.

- A SRV record gives the target host and port where the service instance can be reached.

