# How to Verify NIST/CLCERT Signature

```
bytes signedMessage(JSON pulse) {
    int uriLength = stringLength(pulse["uri"])
    int versionLength = stringLength(pulse["version"])
    bytes cipherSuiteAsBytes = bytes(pulse["cipherSuite"]), 4, 'big-endian')
    bytes periodAsBytes = bytes(pulse["period"], 4, 'big-endian')
    int certificateIdLength = byteLength(bytesFromHexadecimal(pulse["certificateId"]))
    bytes chainIndexAsBytes = bytes(pulse["chainIndex"], 8, 'big-endian')
    bytes pulseIndexAsBytes = bytes(pulse["pulseIndex"], 8, 'big-endian')
    int timestampLength = stringLength(pulse["timeStamp"])
    int localRandomValueLength = byteLength(bytesFromHexadecimal(pulse["localRandomValue"]))
    bytes externalValuesAsBytes = handleExternalValues(pulse["externalValues"])
    bytes previousValuesAsBytes = handlePreviousValues(pulse["listValues"])
    int preCommitmentLength = byteLength(bytesFromHexadecimal(pulse["precommitmentValue"]))
    bytes statusCodeAsBytes = bytes(pulse["statusCode"], 4, 'big-endian')

    bytes out;

    out += bytes(uriLength, 4, 'big-endian')
    out += encodeAsBytes(pulse["uri"], 'utf-8')

    out += bytes(versionLength, 4, 'big-endian')
    out += encodeAsBytes(pulse["version"], 'utf-8')

    out += cipherSuiteAsBytes

    out += periodAsBytes

    out += bytes(certificateIdLength, 4, 'big-endian')
    out += bytesFromHexadecimal(pulse["certificateId"])

    out += chainIndexAsBytes

    out += pulseIndexAsBytes

    out += bytes(timestampLength, 4, 'big-endian')
    out += encodeAsBytes(pulse["timeStamp"], 'utf-8')

    out += bytes(localRandomValueLength, 4, 'big-endian')
    out += bytesFromHexadecimal(pulse["localRandomValue"])

    out += externalValuesAsBytes
    out += previousValuesAsBytes

    out += bytes(preCommitmentLength, 4, 'big-endian')
    out += bytesFromHexadecimal(pulse["precommitmentValue"])

    out += statusCodeAsBytes

    return out
}

int stringLength(String a) {
    // returns the number of characters in 'a'
}

int byteLength(bytes a) {
    // returns the numbers of bytes in 'a'
}

bytes bytes(int a, int b, String mode) {
    // returns 'b' bytes (in endianness 'mode') that represents the number 'a'
}

bytes bytesFromHexadecimal(String hex) {
    // returns the bytes object that represents 'hex'
}

bytes encodeAsBytes(String a, String encoding) {
    // returns 'a' encoding as bytes using 'encoding' encoding
}

bytes handleExternalValues(List externalValues) {
    // NIST doesn't use a List, but only a single JSON object
    bytes out;
    for externalValue in externalValues:
        out += bytes(byteLength(bytesFromHexadecimal(externalValue["sourceId"])), 4, 'big-endian')
        out += bytesFromHexadecimal(externalValue["sourceId"])
        out += bytes(pulse["statusCode"], 4, 'big-endian')
        out += bytes(byteLength(bytesFromHexadecimal(externalValue["value"])), 4, 'big-endian')
        out += bytesFromHexadecimal(externalValue["value"])
    return out;
}

bytes handlePreviousValues(List previousValues) {
    bytes out;

    bytes previousAsBytes = bytesFromHexadecimal(previousValues[type='previous'])
    bytes previousHourAsBytes = bytesFromHexadecimal(previousValues[type='hour'])
    bytes previousDayAsBytes = bytesFromHexadecimal(previousValues[type='day'])
    bytes previousMonthAsBytes = bytesFromHexadecimal(previousValues[type='month'])
    bytes previousYearAsBytes = bytesFromHexadecimal(previousValues[type='year'])

    out += bytes(byteLength(previousAsBytes), 4, 'big-endian')
    out += previousAsBytes
    out += bytes(byteLength(previousHourAsBytes), 4, 'big-endian')
    out += previousHourAsBytes
    out += bytes(byteLength(previousDayAsBytes), 4, 'big-endian')
    out += previousDayAsBytes
    out += bytes(byteLength(previousMonthAsBytes), 4, 'big-endian')
    out += previousMonthAsBytes
    out += bytes(byteLength(previousYearAsBytes), 4, 'big-endian')
    out += previousYearAsBytes

    return out;
}
```