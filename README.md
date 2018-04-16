![](https://www.clcert.cl/img/logo-clcert.png)

# CLCERT Random Beacon Verifier Scripts

Python scripts that verify the correctness of the values delivered by the CLCERT Random Beacon service.

#### Install requirements

`$ pip install -r requirements.txt`


### Chain Consistency

Each new record that is created by the service it must be linked to the previous records that were created before. In order to achieve that, each record must reference to records and values committed in the past. Specifically, there are some properties that each record in the chain must fulfill in order to preserve the consistency and correctness of the chain:
* Correct reference to previous records.
* Use of local random value committed in the record created immediately before.
* Correct use of hash function to create output value.
* Valid Signature.
* Correct hashing of external events.

The script checks all this properties for each record and reports if there are record that doesn't fulfill any of this properties.

#### How to Use

```
$ python beacon-verifier-script.py [options] [values]

Options:
 -a          Run all tests (check all properties).
 -c          Check reference of previous records already created in the chain.
 -p          Check local random value pre-committed.
 -o          Check correct generation of output value using hash function.
 -s          Check valid signature.
 -e          Check correct hash of external events.
 -i [value]  Set initial record id [value].
 -f [value]  Set final record id [value].
 -w [value]  Set address [value] of beacon web server.
```

### Real-Time External Events Verifier

Checks in real-time that the data extracted by the service from each entropy source is the same data that the user can collect from her point of view. It reports if the data is not the same or if there are some errors in the collection (timeout or server errors).

#### How to Use

```
$ python real-time-verifier.py [options] [values]

Options:
-w [value]  Set address [value] of beacon web server.
```



