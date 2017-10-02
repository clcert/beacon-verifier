# CLCERT Random Beacon Output Verifier

Web application that helps to verify the random output value produced by the Generator, providing tools to check all the steps that the beacon must perform from extracting randomness from the external events value until producing the final random output value.

## Check Raw External Events

The database only stores raw external events from records generated in the last 60 minutes (for the rest, only a digest of the raw values is stored). You can check this raw external events from an specific record (providing his record id) using the following calls:

#### Earthquake Twitter

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;/verifier/1.0/check\_earthquake\_twitter/id/\<record\_id\>

#### Earthquake Web

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;/verifier/1.0/check\_earthquake\_web/id/\<record\_id\>

#### Trending Twitter

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;/verifier/1.0/check\_trending/id/\<record\_id\>

#### Radio Stream

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;/verifier/1.0/check\_radio/id/\<record\_id\>
